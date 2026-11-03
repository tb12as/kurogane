package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/tb12as/serverman/internal/notify"
	"github.com/tb12as/serverman/internal/secret"
)

// queued is one pending delivery, persisted in bbolt so alerts survive restarts and outages (§11.4).
type queued struct {
	Channel string       `json:"channel"`
	Alert   notify.Alert `json:"alert"`
	Tries   int          `json:"tries"`
	Next    time.Time    `json:"next"`
	Created time.Time    `json:"created"`
}

// dispatch routes an alert to channels (rule channels, else severity routing, else all) and queues it.
func (e *Engine) dispatch(ctx context.Context, r *rule, labels map[string]string, a notify.Alert) {
	if a.State != "resolved" && e.silenced(ctx, r) {
		slog.Info("alert silenced", "rule", r.ID)
		return
	}
	chans := r.Channels
	if len(chans) == 0 {
		chans = e.d.Cfg.Alerts.Routing[a.Severity]
	}
	if len(chans) == 0 {
		e.mu.Lock()
		for n := range e.chans {
			chans = append(chans, n)
		}
		e.mu.Unlock()
	}
	now := e.now()
	for _, ch := range chans {
		q := queued{Channel: ch, Alert: a, Next: now, Created: now}
		if e.d.Store == nil {
			e.deliver(ctx, "", q)
			continue
		}
		if _, err := e.d.Store.Enqueue(queueBucket, q); err != nil {
			slog.Error("alert enqueue failed", "channel", ch, "err", err)
		}
	}
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// Run is the delivery worker plus periodic baseline persistence.
func (e *Engine) Run(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	save := time.NewTicker(5 * time.Minute)
	defer save.Stop()
	for {
		select {
		case <-ctx.Done():
			e.saveBaselines()
			return
		case <-save.C:
			e.saveBaselines()
		case <-t.C:
		case <-e.wake:
		}
		e.Flush(ctx)
	}
}

// Flush delivers due queue items once.
func (e *Engine) Flush(ctx context.Context) {
	if e.d.Store == nil {
		return
	}
	type item struct {
		k string
		q queued
	}
	var items []item
	_ = e.d.Store.List(queueBucket, func(k string, raw []byte) error {
		var q queued
		if json.Unmarshal(raw, &q) == nil {
			items = append(items, item{k, q})
		} else {
			_ = e.d.Store.Delete(queueBucket, k)
		}
		return nil
	})
	for _, it := range items {
		e.deliver(ctx, it.k, it.q)
	}
	e.summaries(ctx)
}

func (e *Engine) deliver(ctx context.Context, key string, q queued) {
	now := e.now()
	drop := func() {
		if key != "" {
			_ = e.d.Store.Delete(queueBucket, key)
		}
	}
	if now.Sub(q.Created) > maxQueueAge {
		slog.Warn("alert dropped after 24h undelivered", "channel", q.Channel, "rule", q.Alert.Rule)
		drop()
		return
	}
	if now.Before(q.Next) {
		return
	}
	e.mu.Lock()
	n := e.notif[q.Channel]
	if n == nil {
		e.mu.Unlock()
		slog.Warn("alert channel not available, dropping", "channel", q.Channel)
		drop()
		return
	}
	if !e.allow(q.Channel, now) {
		e.overflow[q.Channel]++
		e.mu.Unlock()
		drop()
		return
	}
	e.mu.Unlock()
	err := n.Send(ctx, q.Alert)
	if err == nil {
		drop()
		e.mu.Lock()
		e.sent[q.Channel] = append(e.sent[q.Channel], now)
		e.mu.Unlock()
		return
	}
	if notify.Permanent(err) {
		slog.Error("alert delivery failed permanently", "channel", q.Channel, "err", secret.Redact(err.Error()))
		drop()
		return
	}
	q.Tries++
	back := time.Duration(1<<min(q.Tries, 9)) * time.Second // 2s .. ~8.5m
	q.Next = now.Add(back)
	slog.Warn("alert delivery failed, retrying", "channel", q.Channel, "in", back, "err", secret.Redact(err.Error()))
	if key == "" {
		return
	}
	b, _ := json.Marshal(q)
	_ = e.d.Store.Put(queueBucket, key, json.RawMessage(b))
}

// allow enforces the per-channel rate limit (default 20/min); caller holds e.mu.
func (e *Engine) allow(ch string, now time.Time) bool {
	lim := e.limit()
	ts := e.sent[ch][:0]
	for _, t := range e.sent[ch] {
		if now.Sub(t) < time.Minute {
			ts = append(ts, t)
		}
	}
	e.sent[ch] = ts
	return len(ts) < lim
}

// summaries collapses rate-limited overflow into one message per channel once the window frees up.
func (e *Engine) summaries(ctx context.Context) {
	now := e.now()
	e.mu.Lock()
	type pend struct {
		ch string
		n  int
		nf notify.Notifier
	}
	var ps []pend
	for ch, n := range e.overflow {
		if n == 0 || !e.allow(ch, now) || e.notif[ch] == nil {
			continue
		}
		ps = append(ps, pend{ch, n, e.notif[ch]})
		e.overflow[ch] = 0
		e.sent[ch] = append(e.sent[ch], now)
	}
	e.mu.Unlock()
	for _, p := range ps {
		a := notify.Alert{ID: "summary", Rule: "rate_limit", Server: e.d.Cfg.ServerName, Severity: "warning",
			State: "summary", Title: fmt.Sprintf("%d alerts collapsed", p.n), StartedAt: now,
			Text: fmt.Sprintf("%d more alert messages exceeded the channel limit of %d/min. Open the dashboard "+
				"alert history for details.", p.n, e.limit())}
		if err := p.nf.Send(ctx, a); err != nil {
			slog.Warn("alert summary failed", "channel", p.ch, "err", secret.Redact(err.Error()))
		}
	}
}

func (e *Engine) limit() int {
	if l := e.d.Cfg.Alerts.RateLimit; l > 0 {
		return l
	}
	return 20
}
