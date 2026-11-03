package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/tb12as/serverman/internal/config"
	"github.com/tb12as/serverman/internal/db"
	"github.com/tb12as/serverman/internal/notify"
	"github.com/tb12as/serverman/internal/pb"
)

// agentAlert stores an agent's alert event under the server id and routes state changes.
// Dedup: one notification per (server, fingerprint) transition; re-sent events with an unchanged state are silent.
func (c *Central) agentAlert(ctx context.Context, id string, a *pb.AlertEvent) {
	ev := db.AlertEvent{ID: id + ":" + a.Id, RuleID: a.Rule, ServerID: id, Fingerprint: id + ":" + a.Fingerprint,
		State: a.State, Severity: a.Severity, Summary: a.Summary, StartedAt: unixOr0(a.StartedAt),
		ResolvedAt: unixOr0(a.ResolvedAt)}
	if json.Valid([]byte(a.Payload)) {
		ev.Payload = json.RawMessage(a.Payload)
	}
	notifyIt := true
	if prev, err := c.DB.GetEvent(ctx, ev.ID); err == nil {
		notifyIt = prev.State != ev.State
		ev.LastSentAt, ev.AckedAt, ev.AckedBy, ev.Noise = prev.LastSentAt, prev.AckedAt, prev.AckedBy, prev.Noise
	} else if open, err := c.DB.OpenEvent(ctx, ev.Fingerprint); err == nil && open.ID != ev.ID && ev.State == "firing" {
		notifyIt = false // same condition already firing under another event id (agent restart)
	}
	if notifyIt && ev.State != "firing" && ev.State != "resolved" {
		notifyIt = false
	}
	if notifyIt {
		ev.LastSentAt = time.Now()
	}
	if err := c.DB.SaveEvent(ctx, ev); err != nil {
		slog.Error("save agent alert", "err", err)
		return
	}
	if notifyIt {
		c.route(ctx, id, ev)
	}
}

func unixOr0(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(n, 0)
}

// CheckOffline marks servers without a heartbeat for server.offline_after as offline and fires agent_offline.
func (c *Central) CheckOffline(ctx context.Context) {
	after := c.Cfg.Server.OfflineAfter
	if after <= 0 {
		after = 2 * time.Minute
	}
	srvs, err := c.DB.ListServers(ctx)
	if err != nil {
		return
	}
	now := time.Now()
	for _, s := range srvs {
		if s.Status != "online" || now.Sub(s.LastSeen) < after {
			continue
		}
		_ = c.DB.TouchServer(ctx, s.ID, s.LastSeen, "offline")
		fp := "agent_offline:" + s.ID
		if _, err := c.DB.OpenEvent(ctx, fp); err == nil {
			continue
		}
		ev := db.AlertEvent{ID: db.NewID(), RuleID: "agent_offline", ServerID: s.ID, Fingerprint: fp, State: "firing",
			Severity: "critical", StartedAt: now, LastSentAt: now,
			Summary: fmt.Sprintf("Agent offline: no heartbeat from %s for %s", s.Name, now.Sub(s.LastSeen).Round(time.Second))}
		if err := c.DB.SaveEvent(ctx, ev); err != nil {
			slog.Error("save offline alert", "err", err)
			continue
		}
		c.audit(ctx, s.ID, "fleet.agent_offline", s.Name, nil)
		c.route(ctx, s.ID, ev)
	}
}

func (c *Central) resolveOffline(ctx context.Context, s db.Server) {
	ev, err := c.DB.OpenEvent(ctx, "agent_offline:"+s.ID)
	if err != nil {
		return
	}
	ev.State, ev.ResolvedAt, ev.LastSentAt = "resolved", time.Now(), time.Now()
	ev.Summary = "Agent back online: " + s.Name
	if err := c.DB.SaveEvent(ctx, ev); err != nil {
		return
	}
	c.route(ctx, s.ID, ev)
}

// Channels resolves alert routing for a server. alerts.routing keys: a severity ("critical"), "rule:<id>",
// "server:<name>", "tag:<tag>" and "default"; the union of matches is used, then "default", then every channel.
func (c *Central) Channels(srv db.Server, rule, severity string) []string {
	r := c.Cfg.Alerts.Routing
	seen := map[string]bool{}
	var out []string
	add := func(k string) {
		for _, ch := range r[k] {
			if !seen[ch] {
				seen[ch] = true
				out = append(out, ch)
			}
		}
	}
	add(severity)
	add("rule:" + rule)
	add("server:" + srv.Name)
	for _, t := range srv.Tags {
		add("tag:" + t)
	}
	if len(out) == 0 {
		add("default")
	}
	if len(out) == 0 && len(r) == 0 {
		for _, ch := range c.channels(context.Background()) {
			out = append(out, ch.Name)
		}
	}
	return out
}

// channels merges config channels with UI-managed ones from the database (config wins on name clash).
func (c *Central) channels(ctx context.Context) []config.Channel {
	out := append([]config.Channel{}, c.Cfg.Alerts.Channels...)
	seen := map[string]bool{}
	for _, ch := range out {
		seen[ch.Name] = true
	}
	dbc, _ := c.DB.ListChannels(ctx)
	for _, d := range dbc {
		if seen[d.Name] {
			continue
		}
		m := d.Config
		ch := config.Channel{Name: d.Name, Type: d.Type, WebhookURL: m["webhook_url"], WebhookURLEnv: m["webhook_url_env"],
			ChatID: m["chat_id"], SMTPAddr: m["smtp_addr"], SMTPUser: m["smtp_user"], From: m["from"]}
		if m["to"] != "" {
			ch.To = strings.Split(m["to"], ",")
		}
		out = append(out, ch)
	}
	return out
}

// route delivers ev to the server's channels in the background.
func (c *Central) route(ctx context.Context, id string, ev db.AlertEvent) {
	srv, err := c.DB.GetServer(ctx, id)
	if err != nil {
		srv = db.Server{ID: id, Name: id}
	}
	names := c.Channels(srv, ev.RuleID, ev.Severity)
	if len(names) == 0 {
		return
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	a := notify.Alert{ID: ev.ID, Rule: ev.RuleID, Server: srv.Name, Severity: ev.Severity, State: ev.State,
		Title: ev.Summary, Text: ev.Summary, StartedAt: ev.StartedAt, DashboardURL: c.Cfg.DashboardURL}
	for _, ch := range c.channels(ctx) {
		if !want[ch.Name] {
			continue
		}
		n, err := c.NewNotifier(ch, c.Box)
		if err != nil || n == nil {
			slog.Warn("alert channel unusable", "channel", ch.Name, "err", err)
			continue
		}
		go func(name string) {
			sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			if err := n.Send(sctx, a); err != nil {
				slog.Warn("alert delivery failed", "channel", name, "err", err)
			}
		}(ch.Name)
	}
}
