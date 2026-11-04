// Package alert is the rule engine, lifecycle, baselines and delivery pipeline (PRD §8).
package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tb12as/kurogane/internal/audit"
	"github.com/tb12as/kurogane/internal/collector"
	"github.com/tb12as/kurogane/internal/config"
	"github.com/tb12as/kurogane/internal/db"
	"github.com/tb12as/kurogane/internal/firewall"
	"github.com/tb12as/kurogane/internal/notify"
	"github.com/tb12as/kurogane/internal/secret"
	"github.com/tb12as/kurogane/internal/store"
)

// Event is an externally detected condition or one-shot event (SSH login, rollback, drift, ...).
type Event struct {
	Rule     string            `json:"rule"`
	Severity string            `json:"severity"` // info | warning | critical
	Title    string            `json:"title"`
	Text     string            `json:"text"`
	Labels   map[string]string `json:"labels,omitempty"`
	Fields   map[string]string `json:"fields,omitempty"`
	Resolve  bool              `json:"resolve,omitempty"` // condition cleared
	Once     bool              `json:"once,omitempty"`    // one-shot: no resolve message
}

type Deps struct {
	Cfg      *config.Config
	DB       db.Store
	Store    *store.Store
	Box      *secret.Box
	Audit    *audit.Logger
	Firewall *firewall.Manager
	ServerID string
	Publish  func(event string, v any)
}

const (
	baseBucket  = "alert_baselines"
	queueBucket = "alert_queue"
	maxQueueAge = 24 * time.Hour
)

var sevRank = map[string]int{"info": 0, "warning": 1, "critical": 2}

type rule struct {
	db.AlertRule
	n    node // nil for externally fired rules
	crit node // optional escalation to critical
}

// Engine evaluates samples against rules and delivers alerts.
type Engine struct {
	d   Deps
	now func() time.Time

	mu       sync.Mutex
	rules    map[string]*rule
	pending  map[string]time.Time // fingerprint -> condition first true
	open     map[string]db.AlertEvent
	base     map[string]*baseline
	last     *collector.Snapshot
	proj     map[string]float64 // mount -> hours until full
	projAt   time.Time
	notif    map[string]notify.Notifier
	chans    map[string]config.Channel
	sent     map[string][]time.Time // channel -> sends in the last minute
	overflow map[string]int
	banned   int

	wake chan struct{}
}

// NewEngine seeds built-in and configured rules and loads open events and baselines.
func NewEngine(d Deps) (*Engine, error) {
	e := &Engine{d: d, now: time.Now, rules: map[string]*rule{}, pending: map[string]time.Time{},
		open: map[string]db.AlertEvent{}, base: map[string]*baseline{}, proj: map[string]float64{},
		sent: map[string][]time.Time{}, overflow: map[string]int{}, wake: make(chan struct{}, 1)}
	if d.Cfg == nil {
		d.Cfg = &config.Config{}
		e.d.Cfg = d.Cfg
	}
	if e.d.ServerID == "" {
		e.d.ServerID = d.Cfg.ServerName
	}
	ctx := context.Background()
	if err := e.seed(ctx); err != nil {
		return nil, err
	}
	if err := e.Reload(ctx); err != nil {
		return nil, err
	}
	evs, err := d.DB.ListEvents(ctx, db.EventFilter{State: "open", Limit: 10000})
	if err != nil {
		return nil, err
	}
	for _, ev := range evs {
		e.open[ev.Fingerprint] = ev
	}
	e.loadBaselines()
	return e, nil
}

// seed upserts built-in rules (keeping user edits) and config rules (config wins).
func (e *Engine) seed(ctx context.Context) error {
	cfg := e.d.Cfg.Alerts
	disabled := map[string]bool{}
	for _, id := range cfg.DisableBuiltin {
		disabled[id] = true
	}
	for _, b := range builtins {
		r := b.rule(cfg.Thresholds)
		old, err := e.d.DB.GetRule(ctx, r.ID)
		if err == nil {
			// keep operator edits; config thresholds and disables still apply
			r.Channels, r.For, r.Enabled, r.Tags = old.Channels, old.For, old.Enabled, old.Tags
			if _, ok := cfg.Thresholds[r.ID]; !ok {
				r.Expr = old.Expr
			}
		}
		if disabled[r.ID] {
			r.Enabled = false
		}
		if err := e.d.DB.UpsertRule(ctx, r); err != nil {
			return err
		}
	}
	for _, c := range cfg.Rules {
		r := db.AlertRule{ID: c.ID, Name: c.Name, Expr: c.Expr, For: c.For, Severity: c.Severity, Channels: c.Channels,
			Enabled: c.Enabled == nil || *c.Enabled, Tags: c.Tags}
		if err := ValidateRule(r); err != nil {
			return fmt.Errorf("alerts.rules %s: %w", c.ID, err)
		}
		if err := e.d.DB.UpsertRule(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

// ValidateRule checks severity and expression syntax.
func ValidateRule(r db.AlertRule) error {
	if r.ID == "" {
		return fmt.Errorf("rule id is required")
	}
	if _, ok := sevRank[r.Severity]; !ok {
		return fmt.Errorf("severity %q must be info, warning or critical", r.Severity)
	}
	if r.Expr == "" {
		return nil
	}
	_, err := parse(r.Expr)
	return err
}

// Reload recompiles rules and rebuilds notifiers from config + db channels.
func (e *Engine) Reload(ctx context.Context) error {
	rs, err := e.d.DB.ListRules(ctx)
	if err != nil {
		return err
	}
	rules := map[string]*rule{}
	for _, r := range rs {
		x := &rule{AlertRule: r}
		if r.Expr != "" {
			if x.n, err = parse(r.Expr); err != nil {
				slog.Error("alert rule invalid, skipped", "rule", r.ID, "err", err)
				continue
			}
		}
		if c := critExpr[r.ID]; c != "" {
			x.crit, _ = parse(c)
		}
		rules[r.ID] = x
	}
	chans, notif := map[string]config.Channel{}, map[string]notify.Notifier{}
	all := append([]config.Channel{}, e.d.Cfg.Alerts.Channels...)
	dbc, err := e.d.DB.ListChannels(ctx)
	if err != nil {
		return err
	}
	for _, c := range dbc {
		all = append(all, channelFromDB(c))
	}
	for _, c := range all {
		chans[c.Name] = c
		n, err := notify.New(c, e.d.Box)
		if err != nil {
			slog.Warn("alert channel unavailable", "channel", c.Name, "err", secret.Redact(err.Error()))
			continue
		}
		notif[c.Name] = n
	}
	e.mu.Lock()
	e.rules, e.chans, e.notif = rules, chans, notif
	e.mu.Unlock()
	return nil
}

func channelFromDB(c db.Channel) config.Channel {
	ch := config.Channel{Name: c.Name, Type: c.Type, WebhookURL: c.Config["webhook_url"],
		WebhookURLEnv: c.Config["webhook_url_env"], ChatID: c.Config["chat_id"], SMTPAddr: c.Config["smtp_addr"],
		SMTPUser: c.Config["smtp_user"], From: c.Config["from"]}
	if to := c.Config["to"]; to != "" {
		ch.To = strings.Split(to, ",")
	}
	return ch
}

func fingerprint(server, rule string, labels map[string]string) string {
	return server + "|" + rule + "|" + collector.SeriesKey("", labels)
}

// Eval runs every enabled rule against a snapshot (AL-1).
func (e *Engine) Eval(ctx context.Context, s *collector.Snapshot) {
	if s == nil {
		return
	}
	now := e.now()
	e.mu.Lock()
	e.observe(s, now)
	e.last = s
	samples := append(append([]collector.Sample{}, s.Samples...), e.synthetic(s, now)...)
	rules := make([]*rule, 0, len(e.rules))
	for _, r := range e.rules {
		if r.Enabled && r.n != nil {
			rules = append(rules, r)
		}
	}
	e.mu.Unlock()

	for _, r := range rules {
		res := r.n.eval(samples)
		var crit map[string]inst
		if r.crit != nil {
			crit = r.crit.eval(samples)
		}
		seen := map[string]bool{}
		for k, in := range res {
			fp := fingerprint(e.d.ServerID, r.ID, in.labels)
			seen[fp] = true
			if !in.ok {
				e.clear(ctx, fp)
				continue
			}
			sev := r.Severity
			if c, ok := crit[k]; ok && c.ok {
				sev = "critical"
			}
			e.mu.Lock()
			first, ok := e.pending[fp]
			if !ok {
				first = now
				e.pending[fp] = now
			}
			e.mu.Unlock()
			if now.Sub(first) < r.For {
				continue
			}
			title, text, fields := describe(r, in, s, now.Sub(first))
			e.raise(ctx, r, fp, in.labels, sev, title, text, fields, first, in.v, onceRules[r.ID])
		}
		// series that disappeared clear their alerts
		e.mu.Lock()
		var gone []string
		for fp, ev := range e.open {
			if ev.RuleID == r.ID && !seen[fp] && strings.HasPrefix(fp, e.d.ServerID+"|") {
				gone = append(gone, fp)
			}
		}
		e.mu.Unlock()
		for _, fp := range gone {
			e.clear(ctx, fp)
		}
	}
}

// Fire handles externally detected events (CONTRACTS.md rule ids).
func (e *Engine) Fire(ctx context.Context, ev Event) {
	if e == nil {
		return
	}
	fp := fingerprint(e.d.ServerID, ev.Rule, ev.Labels)
	if ev.Once {
		// one-shot events are distinct incidents, not a deduplicated condition
		fp += "|" + db.NewID()
	}
	if ev.Resolve {
		e.clear(ctx, fp)
		return
	}
	e.mu.Lock()
	r := e.rules[ev.Rule]
	e.mu.Unlock()
	if r == nil {
		r = &rule{AlertRule: db.AlertRule{ID: ev.Rule, Severity: ev.Severity, Enabled: true}}
	}
	if !r.Enabled {
		return
	}
	sev := ev.Severity
	if sev == "" {
		sev = r.Severity
	}
	var fields []notify.Field
	keys := make([]string, 0, len(ev.Fields))
	for k := range ev.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fields = append(fields, notify.Field{Name: k, Value: ev.Fields[k]})
	}
	title := ev.Title
	if title == "" {
		title = titles[ev.Rule]
	}
	e.raise(ctx, r, fp, ev.Labels, sev, title, ev.Text, fields, e.now(), 0, ev.Once)
}

// raise opens a new alert or refreshes an open one (dedup, escalation, repeat reminder - AL-3).
func (e *Engine) raise(ctx context.Context, r *rule, fp string, labels map[string]string, sev, title, text string,
	fields []notify.Field, started time.Time, v float64, once bool) {
	now := e.now()
	e.mu.Lock()
	ev, isOpen := e.open[fp]
	e.mu.Unlock()
	state := "firing"
	if isOpen {
		repeat := e.repeat(r.ID)
		escalated := sevRank[sev] > sevRank[ev.Severity]
		if !escalated && (ev.State == "acknowledged" || now.Sub(ev.LastSentAt) < repeat) {
			return
		}
		if !escalated {
			state = "reminder"
		}
		ev.Severity, ev.Summary = sev, title
	} else {
		payload, _ := json.Marshal(map[string]any{"labels": labels, "value": v, "text": text, "fields": fields})
		ev = db.AlertEvent{ID: db.NewID(), RuleID: r.ID, ServerID: e.d.ServerID, Fingerprint: fp, State: "firing",
			Severity: sev, Summary: title, StartedAt: started, Payload: payload}
	}
	ev.LastSentAt = now
	if once {
		ev.State, ev.ResolvedAt = "resolved", now
	}
	if err := e.d.DB.SaveEvent(ctx, ev); err != nil {
		slog.Error("alert event save failed", "rule", r.ID, "err", err)
	}
	e.mu.Lock()
	if once {
		delete(e.open, fp)
	} else {
		e.open[fp] = ev
	}
	e.mu.Unlock()
	if e.d.Publish != nil {
		e.d.Publish("alert", ev)
	}
	a := e.message(ev, state, text, fields)
	if r.ID == "ddos" && state == "firing" {
		e.autoBan(ctx)
	}
	e.dispatch(ctx, r, labels, a)
}

// clear resolves an open alert and sends the resolve message.
func (e *Engine) clear(ctx context.Context, fp string) {
	now := e.now()
	e.mu.Lock()
	delete(e.pending, fp)
	ev, ok := e.open[fp]
	if ok {
		delete(e.open, fp)
	}
	r := e.rules[ev.RuleID]
	e.mu.Unlock()
	if !ok {
		return
	}
	ev.State, ev.ResolvedAt = "resolved", now
	if err := e.d.DB.SaveEvent(ctx, ev); err != nil {
		slog.Error("alert event save failed", "rule", ev.RuleID, "err", err)
	}
	if e.d.Publish != nil {
		e.d.Publish("alert", ev)
	}
	if r == nil {
		r = &rule{AlertRule: db.AlertRule{ID: ev.RuleID}}
	}
	var p struct {
		Labels map[string]string `json:"labels"`
	}
	_ = json.Unmarshal(ev.Payload, &p)
	e.dispatch(ctx, r, p.Labels, e.message(ev, "resolved", "", nil))
}

func (e *Engine) repeat(ruleID string) time.Duration {
	if d, ok := repeatOverride[ruleID]; ok {
		return d
	}
	if d := e.d.Cfg.Alerts.RepeatInterval; d > 0 {
		return d
	}
	return 30 * time.Minute
}

func (e *Engine) message(ev db.AlertEvent, state, text string, fields []notify.Field) notify.Alert {
	a := notify.Alert{ID: ev.ID, Rule: ev.RuleID, Server: e.d.Cfg.ServerName, Severity: ev.Severity, State: state,
		Title: ev.Summary, Text: text, Fields: fields, StartedAt: ev.StartedAt, ResolvedAt: ev.ResolvedAt}
	if a.Server == "" {
		a.Server = e.d.ServerID
	}
	if u := strings.TrimRight(e.d.Cfg.DashboardURL, "/"); u != "" {
		a.DashboardURL = u + "/alerts?event=" + ev.ID
		a.SilenceURL = u + "/alerts/silence?rule=" + ev.RuleID + "&for=1h"
	}
	return a
}

// Ack acknowledges an alert: it keeps firing but stops reminders.
func (e *Engine) Ack(ctx context.Context, id, by string) (db.AlertEvent, error) {
	ev, err := e.d.DB.GetEvent(ctx, id)
	if err != nil {
		return ev, err
	}
	if ev.State != "firing" {
		return ev, fmt.Errorf("alert %s is %s, only firing alerts can be acknowledged", id, ev.State)
	}
	ev.State, ev.AckedAt, ev.AckedBy = "acknowledged", e.now(), by
	if err := e.d.DB.SaveEvent(ctx, ev); err != nil {
		return ev, err
	}
	e.mu.Lock()
	if _, ok := e.open[ev.Fingerprint]; ok {
		e.open[ev.Fingerprint] = ev
	}
	e.mu.Unlock()
	if e.d.Publish != nil {
		e.d.Publish("alert", ev)
	}
	return ev, nil
}

// MarkNoise flags an alert as a false positive (success metric: < 5% noise).
func (e *Engine) MarkNoise(ctx context.Context, id string, noise bool) (db.AlertEvent, error) {
	ev, err := e.d.DB.GetEvent(ctx, id)
	if err != nil {
		return ev, err
	}
	ev.Noise = noise
	return ev, e.d.DB.SaveEvent(ctx, ev)
}

// Test sends a test message to a channel directly (bypasses queue, silences and rate limit).
func (e *Engine) Test(ctx context.Context, channel string) error {
	e.mu.Lock()
	n, ok := e.notif[channel]
	_, known := e.chans[channel]
	e.mu.Unlock()
	if !known {
		return fmt.Errorf("unknown channel %q: list channels with `kurogane alert channels list`", channel)
	}
	if !ok {
		return fmt.Errorf("channel %q is misconfigured (check its webhook URL or env var)", channel)
	}
	a := notify.Alert{ID: "test", Rule: "test", Server: e.d.Cfg.ServerName, Severity: "info", State: "test",
		Title: "Test message", Text: "Kurogane can reach this channel.", StartedAt: e.now()}
	if err := n.Send(ctx, a); err != nil {
		return fmt.Errorf("%s", secret.Redact(err.Error()))
	}
	return nil
}

// Channels lists configured channels (never with secrets).
func (e *Engine) Channels() []ChannelInfo {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]ChannelInfo, 0, len(e.chans))
	cfgNames := map[string]bool{}
	for _, c := range e.d.Cfg.Alerts.Channels {
		cfgNames[c.Name] = true
	}
	for _, c := range e.chans {
		_, ok := e.notif[c.Name]
		out = append(out, ChannelInfo{Name: c.Name, Type: c.Type, HasSecret: c.WebhookURL != "" || c.WebhookURLEnv != "",
			Env: c.WebhookURLEnv, Source: map[bool]string{true: "config", false: "api"}[cfgNames[c.Name]], Ready: ok})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ChannelInfo is a channel without secret values.
type ChannelInfo struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	HasSecret bool   `json:"has_secret"`
	Env       string `json:"webhook_url_env,omitempty"`
	Source    string `json:"source"`
	Ready     bool   `json:"ready"`
}

// AddChannel stores a channel; the webhook URL/token is sealed before it touches the database (AL-8).
func (e *Engine) AddChannel(ctx context.Context, c config.Channel) error {
	if c.Name == "" {
		return fmt.Errorf("channel name is required")
	}
	for _, x := range e.d.Cfg.Alerts.Channels {
		if x.Name == c.Name {
			return fmt.Errorf("channel %q is defined in config.yaml: edit it there", c.Name)
		}
	}
	cfg := map[string]string{"webhook_url_env": c.WebhookURLEnv, "chat_id": c.ChatID, "smtp_addr": c.SMTPAddr,
		"smtp_user": c.SMTPUser, "from": c.From, "to": strings.Join(c.To, ",")}
	if c.WebhookURL != "" {
		if e.d.Box == nil {
			return fmt.Errorf("secret key not loaded: cannot store webhook URL encrypted")
		}
		sealed, err := e.d.Box.Seal(c.WebhookURL)
		if err != nil {
			return err
		}
		cfg["webhook_url"] = sealed
		c.WebhookURL = sealed
	}
	if _, err := notify.New(c, e.d.Box); err != nil {
		return err
	}
	if err := e.d.DB.UpsertChannel(ctx, db.Channel{Name: c.Name, Type: c.Type, Config: cfg}); err != nil {
		return err
	}
	return e.Reload(ctx)
}

// DeleteChannel removes an API-managed channel.
func (e *Engine) DeleteChannel(ctx context.Context, name string) error {
	if err := e.d.DB.DeleteChannel(ctx, name); err != nil {
		return err
	}
	return e.Reload(ctx)
}

// Silence creates a silence (AL-4).
func (e *Engine) Silence(ctx context.Context, s db.Silence) (db.Silence, error) {
	if s.Matcher == (db.Matcher{}) {
		return s, fmt.Errorf("silence needs at least one of server, rule or tag")
	}
	if s.StartsAt.IsZero() {
		s.StartsAt = e.now()
	}
	if !s.EndsAt.After(s.StartsAt) {
		return s, fmt.Errorf("silence end must be after its start")
	}
	if s.ID == "" {
		s.ID = db.NewID()
	}
	return s, e.d.DB.SaveSilence(ctx, s)
}

// silenced reports whether an alert is muted by an active silence or maintenance window.
func (e *Engine) silenced(ctx context.Context, r *rule) bool {
	ss, err := e.d.DB.ListSilences(ctx, e.now())
	if err != nil || len(ss) == 0 {
		return false
	}
	tags := append(append([]string{}, e.d.Cfg.Tags...), r.Tags...)
	for _, s := range ss {
		m := s.Matcher
		if m.Server != "" && m.Server != e.d.Cfg.ServerName && m.Server != e.d.ServerID {
			continue
		}
		if m.Rule != "" && m.Rule != r.ID {
			continue
		}
		if m.Tag != "" && !contains(tags, m.Tag) {
			continue
		}
		return true
	}
	return false
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// autoBan bans the top offending sources during a DDoS (AL-6, off by default).
func (e *Engine) autoBan(ctx context.Context) {
	ab := e.d.Cfg.Alerts.AutoBan
	if !ab.Enabled || e.d.Firewall == nil {
		return
	}
	e.mu.Lock()
	s := e.last
	e.mu.Unlock()
	if s == nil {
		return
	}
	for _, x := range s.Conns.TopIPs {
		if ab.MaxBans > 0 && e.banned >= ab.MaxBans {
			slog.Warn("auto-ban cap reached", "max_bans", ab.MaxBans)
			return
		}
		// only clear offenders: far above a normal client's concurrency
		if x.Count < 50 || e.d.Firewall.Exempt(x.IP) || allowed(ab.Allowlist, x.IP) {
			continue
		}
		if err := e.d.Firewall.Ban(ctx, x.IP, ab.Duration, fmt.Sprintf("auto-ban: %d concurrent connections", x.Count)); err != nil {
			slog.Warn("auto-ban failed", "ip", x.IP, "err", err)
			continue
		}
		e.banned++
		e.d.Audit.Record(audit.WithActor(ctx, "system:auto-ban", ""), "firewall.ban", x.IP, nil,
			map[string]any{"connections": x.Count, "for": ab.Duration.String()})
	}
}

func allowed(cidrs []string, ip string) bool {
	m := firewall.New(nil)
	if m.SetAllowlist(cidrs) != nil {
		return true
	}
	return m.Exempt(ip)
}

func pct(v float64) string { return fmt.Sprintf("%.1f%%", v) }

func bytesH(b float64) string {
	const u = 1024
	if b < u {
		return fmt.Sprintf("%.0f B", b)
	}
	exp, n := 0, b/u
	for n >= u && exp < 4 {
		n /= u
		exp++
	}
	return fmt.Sprintf("%.1f %cB", n, "KMGTP"[exp])
}

func durH(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d s", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d min", int(math.Round(d.Minutes())))
	}
	return fmt.Sprintf("%.1f h", d.Hours())
}
