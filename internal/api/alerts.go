package api

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/tb12as/kurogane/internal/alert"
	"github.com/tb12as/kurogane/internal/auth"
	"github.com/tb12as/kurogane/internal/collector"
	"github.com/tb12as/kurogane/internal/config"
	"github.com/tb12as/kurogane/internal/db"
)

func init() { Register((*Server).alertRoutes) }

// ruleReq is AlertRule with a human duration ("5m").
type ruleReq struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Expr     string   `json:"expr"`
	For      string   `json:"for"`
	Severity string   `json:"severity"`
	Channels []string `json:"channels"`
	Enabled  *bool    `json:"enabled"`
	Tags     []string `json:"tags"`
}

func (q ruleReq) apply(r *db.AlertRule) error {
	if q.Name != "" {
		r.Name = q.Name
	}
	if q.Expr != "" {
		// rules edited here must use known metrics; config.yaml rules are only parsed (see alert.CheckMetrics)
		if err := alert.CheckMetrics(q.Expr); err != nil {
			return Errf(http.StatusBadRequest, "%s", err.Error())
		}
		r.Expr = q.Expr
	}
	if q.For != "" {
		d, err := config.ParseDuration(q.For)
		if err != nil {
			return Errf(http.StatusBadRequest, "invalid for %q: use a duration like 5m", q.For)
		}
		r.For = d
	}
	if q.Severity != "" {
		r.Severity = q.Severity
	}
	if q.Channels != nil {
		r.Channels = q.Channels
	}
	if q.Enabled != nil {
		r.Enabled = *q.Enabled
	}
	if q.Tags != nil {
		r.Tags = q.Tags
	}
	if err := alert.ValidateRule(*r); err != nil {
		return Errf(http.StatusBadRequest, "%s", err.Error())
	}
	return nil
}

func (s *Server) alertRoutes() {
	if s.Alerts == nil {
		return
	}
	s.Route("GET /alerts/rules", auth.ScopeRead, func(r *http.Request) (any, error) {
		rs, err := s.DB.ListRules(r.Context())
		if err != nil {
			return nil, err
		}
		out := make([]RuleView, len(rs))
		for i, x := range rs {
			out[i] = ruleView(x)
		}
		return out, nil
	})
	s.Route("GET /alerts/metrics", auth.ScopeRead, s.alertMetrics)
	s.Route("POST /alerts/rules", auth.ScopeAdmin, func(r *http.Request) (any, error) {
		var q ruleReq
		if err := Decode(r, &q); err != nil {
			return nil, err
		}
		if _, err := s.DB.GetRule(r.Context(), q.ID); err == nil {
			return nil, Errf(http.StatusConflict, "rule %s exists: use PUT /alerts/rules/%s to edit it", q.ID, q.ID)
		}
		rule := db.AlertRule{ID: q.ID, Enabled: true, Severity: "warning"}
		if err := q.apply(&rule); err != nil {
			return nil, err
		}
		if rule.Expr == "" {
			return nil, Errf(http.StatusBadRequest, "expr is required, e.g. cpu.total_pct > 90")
		}
		return s.saveRule(r, nil, rule)
	})
	s.Route("PUT /alerts/rules/{id}", auth.ScopeAdmin, func(r *http.Request) (any, error) {
		old, err := s.DB.GetRule(r.Context(), r.PathValue("id"))
		if err != nil {
			return nil, err
		}
		var q ruleReq
		if err := Decode(r, &q); err != nil {
			return nil, err
		}
		rule := old
		if err := q.apply(&rule); err != nil {
			return nil, err
		}
		return s.saveRule(r, &old, rule)
	})
	s.Route("DELETE /alerts/rules/{id}", auth.ScopeAdmin, func(r *http.Request) (any, error) {
		old, err := s.DB.GetRule(r.Context(), r.PathValue("id"))
		if err != nil {
			return nil, err
		}
		if old.Builtin {
			return nil, Errf(http.StatusBadRequest, "built-in rule %s cannot be deleted: disable it with enabled=false", old.ID)
		}
		if err := s.DB.DeleteRule(r.Context(), old.ID); err != nil {
			return nil, err
		}
		s.Audit.Record(r.Context(), "alert.rule.delete", old.ID, old, nil)
		return nil, s.Alerts.Reload(r.Context())
	})

	s.Route("GET /alerts/events", auth.ScopeRead, func(r *http.Request) (any, error) {
		f, err := eventFilter(r.URL.Query())
		if err != nil {
			return nil, err
		}
		return s.DB.ListEvents(r.Context(), f)
	})
	s.Raw("GET /api/v1/alerts/events/export", auth.ScopeRead, s.exportEvents)
	s.Raw("GET /api/v1/alerts/events/summary", auth.ScopeRead, s.eventSummary)
	s.Route("POST /alerts/events/summary/send", auth.ScopeAdmin, s.sendEventSummary)
	s.Route("POST /alerts/events/{id}/ack", auth.ScopeAdmin, func(r *http.Request) (any, error) {
		ev, err := s.Alerts.Ack(r.Context(), r.PathValue("id"), PrincipalFrom(r).Actor)
		if err != nil && !errors.Is(err, db.ErrNotFound) {
			return nil, Errf(http.StatusBadRequest, "%s", err.Error())
		}
		s.Audit.Record(r.Context(), "alert.ack", r.PathValue("id"), nil, nil)
		return ev, err
	})
	s.Route("POST /alerts/events/{id}/noise", auth.ScopeAdmin, func(r *http.Request) (any, error) {
		var q struct {
			Noise *bool `json:"noise"`
		}
		if err := Decode(r, &q); err != nil {
			return nil, err
		}
		noise := q.Noise == nil || *q.Noise
		s.Audit.Record(r.Context(), "alert.noise", r.PathValue("id"), nil, map[string]bool{"noise": noise})
		return s.Alerts.MarkNoise(r.Context(), r.PathValue("id"), noise)
	})

	s.Route("GET /alerts/silences", auth.ScopeRead, func(r *http.Request) (any, error) {
		var at time.Time
		if r.URL.Query().Get("active") == "true" {
			at = time.Now()
		}
		return s.DB.ListSilences(r.Context(), at)
	})
	s.Route("POST /alerts/silences", auth.ScopeAdmin, func(r *http.Request) (any, error) {
		var q struct {
			db.Matcher
			For      string    `json:"for"`
			StartsAt time.Time `json:"starts_at"`
			EndsAt   time.Time `json:"ends_at"`
			Reason   string    `json:"reason"`
		}
		if err := Decode(r, &q); err != nil {
			return nil, err
		}
		sl := db.Silence{Matcher: q.Matcher, StartsAt: q.StartsAt, EndsAt: q.EndsAt, Reason: q.Reason,
			CreatedBy: PrincipalFrom(r).Actor}
		if sl.StartsAt.IsZero() {
			sl.StartsAt = time.Now()
		}
		if q.For != "" {
			d, err := config.ParseDuration(q.For)
			if err != nil {
				return nil, Errf(http.StatusBadRequest, "invalid for %q: use a duration like 2h", q.For)
			}
			sl.EndsAt = sl.StartsAt.Add(d)
		}
		sl, err := s.Alerts.Silence(r.Context(), sl)
		if err != nil {
			return nil, Errf(http.StatusBadRequest, "%s", err.Error())
		}
		s.Audit.Record(r.Context(), "alert.silence.create", sl.ID, nil, sl)
		return sl, nil
	})
	s.Route("DELETE /alerts/silences/{id}", auth.ScopeAdmin, func(r *http.Request) (any, error) {
		s.Audit.Record(r.Context(), "alert.silence.delete", r.PathValue("id"), nil, nil)
		return nil, s.DB.DeleteSilence(r.Context(), r.PathValue("id"))
	})

	s.Route("GET /alerts/channels", auth.ScopeRead, func(r *http.Request) (any, error) { return s.Alerts.Channels(), nil })
	s.Route("POST /alerts/channels", auth.ScopeAdmin, func(r *http.Request) (any, error) {
		var q struct {
			config.Channel
			WebhookURL string `json:"webhook_url"`
		}
		if err := Decode(r, &q); err != nil {
			return nil, err
		}
		q.Channel.WebhookURL = q.WebhookURL
		if err := s.Alerts.AddChannel(r.Context(), q.Channel); err != nil {
			return nil, Errf(http.StatusBadRequest, "%s", err.Error())
		}
		s.Audit.Record(r.Context(), "alert.channel.add", q.Name, nil, map[string]string{"type": q.Type})
		return map[string]string{"name": q.Name}, nil
	})
	s.Route("DELETE /alerts/channels/{name}", auth.ScopeAdmin, func(r *http.Request) (any, error) {
		s.Audit.Record(r.Context(), "alert.channel.delete", r.PathValue("name"), nil, nil)
		return nil, s.Alerts.DeleteChannel(r.Context(), r.PathValue("name"))
	})
	s.Route("POST /alerts/channels/{name}/test", auth.ScopeAdmin, func(r *http.Request) (any, error) {
		if err := s.Alerts.Test(r.Context(), r.PathValue("name")); err != nil {
			return nil, Errf(http.StatusBadGateway, "%s", err.Error())
		}
		return map[string]bool{"ok": true}, nil
	})
}

// RuleView is a rule as GET /alerts/rules returns it: the stored rule plus its expression as structured conditions
// (nil when it mixes and/or) and as a sentence.
type RuleView struct {
	db.AlertRule
	Conditions *alert.Conditions `json:"conditions"`
	Summary    string            `json:"summary"`
}

func ruleView(r db.AlertRule) RuleView {
	v := RuleView{AlertRule: r}
	if r.Expr != "" {
		v.Conditions, _ = alert.FlatConditions(r.Expr)
		v.Summary = alert.Summary(r.Expr)
	}
	return v
}

// LiveSeries is one current value of a metric with its labels.
type LiveSeries struct {
	Labels map[string]string `json:"labels,omitempty"`
	Value  float64           `json:"value"`
}

// MetricInfo is a catalog entry with the values the agent sees right now (none on the central server).
type MetricInfo struct {
	alert.MetricDef
	Live []LiveSeries `json:"live"`
}

// alertMetrics serves the metric catalog for the rule builder, with live values from the latest snapshot.
func (s *Server) alertMetrics(*http.Request) (any, error) {
	live := map[string][]LiveSeries{}
	if s.Metrics != nil {
		if snap := s.Metrics.Latest(); snap != nil {
			for _, x := range snap.Samples {
				live[x.Metric] = append(live[x.Metric], LiveSeries{Labels: x.Labels, Value: x.Value})
			}
		}
	}
	cat := alert.Catalog()
	out := make([]MetricInfo, len(cat))
	for i, d := range cat {
		ls := live[d.Name]
		sort.SliceStable(ls, func(a, b int) bool {
			return collector.SeriesKey("", ls[a].Labels) < collector.SeriesKey("", ls[b].Labels)
		})
		if ls == nil {
			ls = []LiveSeries{}
		}
		out[i] = MetricInfo{MetricDef: d, Live: ls}
	}
	return out, nil
}

func (s *Server) saveRule(r *http.Request, old *db.AlertRule, rule db.AlertRule) (any, error) {
	if err := s.DB.UpsertRule(r.Context(), rule); err != nil {
		return nil, err
	}
	action := "alert.rule.create"
	if old != nil {
		action = "alert.rule.update"
	}
	s.Audit.Record(r.Context(), action, rule.ID, old, rule)
	return ruleView(rule), s.Alerts.Reload(r.Context())
}

func eventFilter(q url.Values) (db.EventFilter, error) {
	lim, _ := strconv.Atoi(q.Get("limit"))
	f := db.EventFilter{State: q.Get("state"), RuleID: q.Get("rule"), ServerID: q.Get("server"), Limit: lim}
	if q.Get("since") != "" {
		d, err := config.ParseDuration(q.Get("since"))
		if err != nil || d <= 0 {
			return f, Errf(http.StatusBadRequest, "invalid since %q: use a positive duration like 24h or 7d", q.Get("since"))
		}
		f.Since = time.Now().Add(-d)
	}
	for _, key := range []string{"from", "to"} {
		v := q.Get(key)
		if v == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			t, err = time.ParseInLocation(time.DateOnly, v, time.Local)
			if err == nil && key == "to" {
				t = t.AddDate(0, 0, 1)
			}
		}
		if err != nil {
			return f, Errf(http.StatusBadRequest, "invalid %s %q: use RFC3339 or YYYY-MM-DD", key, v)
		}
		if key == "from" {
			f.Since = t
		} else {
			f.Until = t
		}
	}
	if !f.Since.IsZero() && !f.Until.IsZero() && !f.Since.Before(f.Until) {
		return f, Errf(http.StatusBadRequest,
			"from must be before to: use RFC3339 or YYYY-MM-DD with an increasing period")
	}
	return f, nil
}

// exportEvents is the AL-7 alert history export as CSV or JSON.
func (s *Server) exportEvents(w http.ResponseWriter, r *http.Request) {
	f, err := eventFilter(r.URL.Query())
	if err != nil {
		writeErr(w, err)
		return
	}
	if f.Limit == 0 {
		f.Limit = 100000
	}
	evs, err := s.DB.ListEvents(r.Context(), f)
	if err != nil {
		writeErr(w, err)
		return
	}
	if r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Disposition", `attachment; filename="alerts.json"`)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(evs)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="alerts.csv"`)
	w.Header().Set("Content-Type", "text/csv")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "rule_id", "server_id", "severity", "state", "summary", "started_at", "acked_at",
		"acked_by", "resolved_at", "noise"})
	tf := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format(time.RFC3339)
	}
	for _, e := range evs {
		_ = cw.Write([]string{e.ID, e.RuleID, e.ServerID, e.Severity, e.State, e.Summary, tf(e.StartedAt),
			tf(e.AckedAt), e.AckedBy, tf(e.ResolvedAt), strconv.FormatBool(e.Noise)})
	}
	cw.Flush()
}
