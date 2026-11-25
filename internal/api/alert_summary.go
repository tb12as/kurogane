package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/tb12as/kurogane/internal/alert"
	"github.com/tb12as/kurogane/internal/secret"
)

func (s *Server) loadEventSummary(ctx context.Context, q url.Values) (alert.EventSummary, error) {
	f, err := eventFilter(q)
	if err != nil {
		return alert.EventSummary{}, err
	}
	now := time.Now()
	if f.Since.IsZero() {
		f.Since = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	}
	if f.Until.IsZero() {
		f.Until = now
	}
	if !f.Since.Before(f.Until) {
		return alert.EventSummary{}, Errf(http.StatusBadRequest,
			"from must be before to: use RFC3339 or YYYY-MM-DD with an increasing period")
	}
	// shortcut: summaries include at most 100000 events, use database aggregation if larger periods are needed
	f.Limit = 100000
	evs, err := s.DB.ListEvents(ctx, f)
	if err != nil {
		return alert.EventSummary{}, err
	}
	return alert.Summarize(evs, f.Since, f.Until), nil
}

func (s *Server) eventSummary(w http.ResponseWriter, r *http.Request) {
	summary, err := s.loadEventSummary(r.Context(), r.URL.Query())
	if err != nil {
		writeErr(w, err)
		return
	}
	if r.URL.Query().Get("format") != "csv" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(summary)
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="alerts-summary-%s_%s.csv"`,
		summary.From.Format(time.DateOnly), summary.To.Format(time.DateOnly)))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"dimension", "key", "count"})
	row := func(dimension, key string, count int) {
		_ = cw.Write([]string{dimension, key, strconv.Itoa(count)})
	}
	row("total", "", summary.Total)
	row("open", "", summary.Open)
	row("noise", "", summary.Noise)
	for _, group := range []struct {
		name   string
		counts map[string]int
	}{{"severity", summary.BySeverity}, {"state", summary.ByState}} {
		keys := make([]string, 0, len(group.counts))
		for key := range group.counts {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			row(group.name, key, group.counts[key])
		}
	}
	for _, rule := range summary.ByRule {
		row("rule", rule.Key, rule.Count)
	}
	for _, server := range summary.ByServer {
		row("server", server.Key, server.Count)
	}
	cw.Flush()
}

func (s *Server) sendEventSummary(r *http.Request) (any, error) {
	var q struct {
		Channel string `json:"channel"`
		From    string `json:"from"`
		To      string `json:"to"`
		Since   string `json:"since"`
	}
	if err := Decode(r, &q); err != nil {
		return nil, err
	}
	period := url.Values{"from": {q.From}, "to": {q.To}, "since": {q.Since}}
	summary, err := s.loadEventSummary(r.Context(), period)
	if err != nil {
		return nil, err
	}
	if err := s.Alerts.SendSummary(r.Context(), q.Channel, alert.SummaryAlert(summary, s.Cfg.DashboardURL)); err != nil {
		var channelErr *alert.ChannelError
		if errors.As(err, &channelErr) {
			return nil, Errf(http.StatusBadRequest, "%s", err.Error())
		}
		return nil, Errf(http.StatusBadGateway, "%s", secret.Redact(err.Error()))
	}
	s.Audit.Record(r.Context(), "alert.summary.send", q.Channel, nil, summary)
	return map[string]any{"ok": true, "total": summary.Total}, nil
}
