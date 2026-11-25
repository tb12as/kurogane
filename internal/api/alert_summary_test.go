package api

import (
	"context"
	"encoding/csv"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tb12as/kurogane/internal/alert"
	"github.com/tb12as/kurogane/internal/config"
	"github.com/tb12as/kurogane/internal/db"
)

func TestEventFilterPeriod(t *testing.T) {
	for _, tc := range []struct {
		query, from, to string
		bad             bool
	}{
		{"from=2026-11-24&to=2026-11-25", "2026-11-24", "2026-11-26", false},
		{"from=2026-03-08&to=2026-03-08", "2026-03-08", "2026-03-09", false},
		{"from=2026-11-25T01:00:00%2B07:00&to=2026-11-25T12:00:00%2B07:00", "", "", false},
		{"from=2026-11-25&since=1h", "2026-11-25", "", false},
		{"since=24h", "", "", false},
		{"from=bad", "", "", true},
		{"to=2026-02-30", "", "", true},
		{"from=2026-11-26&to=2026-11-24", "", "", true},
		{"from=2026-11-25T01:00:00Z&to=2026-11-25T01:00:00Z", "", "", true},
		{"since=bad", "", "", true},
		{"since=-1h", "", "", true},
	} {
		t.Run(tc.query, func(t *testing.T) {
			q, err := url.ParseQuery(tc.query)
			if err != nil {
				t.Fatal(err)
			}
			f, err := eventFilter(q)
			if (err != nil) != tc.bad {
				t.Fatalf("%+v, %v", f, err)
			}
			if err != nil {
				if !strings.Contains(err.Error(), "use ") {
					t.Fatal("error needs expected format", err)
				}
				return
			}
			if tc.from != "" {
				want, _ := time.ParseInLocation(time.DateOnly, tc.from, time.Local)
				if !f.Since.Equal(want) {
					t.Fatal(f.Since, want)
				}
			}
			if tc.to != "" {
				want, _ := time.ParseInLocation(time.DateOnly, tc.to, time.Local)
				if !f.Until.Equal(want) {
					t.Fatal(f.Until, want)
				}
			}
			if strings.Contains(tc.query, "%2B07") && f.Until.Sub(f.Since) != 11*time.Hour {
				t.Fatal(f)
			}
		})
	}
}

func TestEventSummaryRoutes(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	now := time.Now()
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
	for _, ev := range []db.AlertEvent{
		{ID: "today", Fingerprint: "today", RuleID: "cpu", ServerID: "host", Severity: "critical",
			State: "firing", Noise: true, StartedAt: midnight},
		{ID: "yesterday", Fingerprint: "yesterday", RuleID: "disk", Severity: "warning",
			State: "resolved", StartedAt: midnight.Add(-time.Hour)},
	} {
		if err := s.srv.DB.SaveEvent(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	path := "/api/v1/alerts/events/summary"
	out := decode[alert.EventSummary](t, s.do("GET", path, s.read, nil, 200))
	if out.Total != 1 || out.Open != 1 || out.Noise != 1 || !out.From.Equal(midnight) || out.To.Before(now) {
		t.Fatalf("today: %+v", out)
	}
	q := url.Values{"from": {midnight.AddDate(0, 0, -1).Format(time.DateOnly)},
		"to": {midnight.Format(time.DateOnly)}}.Encode()
	out = decode[alert.EventSummary](t, s.do("GET", path+"?"+q, s.read, nil, 200))
	if out.Total != 2 || out.Open != 1 {
		t.Fatal(out)
	}
	req := httptest.NewRequest("GET", path+"?"+q+"&format=csv", nil)
	w := httptest.NewRecorder()
	s.srv.eventSummary(w, req)
	if !strings.Contains(w.Header().Get("Content-Disposition"), "alerts-summary-") {
		t.Fatal(w.Header())
	}
	rows, err := csv.NewReader(w.Body).ReadAll()
	if err != nil || len(rows) != 12 || strings.Join(rows[0], ",") != "dimension,key,count" || rows[1][2] != "2" {
		t.Fatal(rows, err)
	}
	s.do("GET", path+"?format=csv", s.read, nil, 200)
	for _, route := range []string{"", "/export", "/summary"} {
		s.do("GET", "/api/v1/alerts/events"+route+"?from=bad", s.read, nil, 400)
	}
	s.do("GET", path+"?from=2999-01-01", s.read, nil, 400)
	send := path + "/send"
	body := map[string]string{"channel": "ops"}
	s.do("POST", send, s.read, body, 403)
	result := decode[map[string]any](t, s.do("POST", send, s.admin, body, 200))
	if result["ok"] != true || result["total"] != float64(1) {
		t.Fatal(result)
	}
	if len(*s.sink) != 1 || (*s.sink)[0]["state"] != "summary" {
		t.Fatal(*s.sink)
	}
	entries, err := s.srv.DB.ListAudit(ctx, db.AuditFilter{Action: "alert.summary.send"})
	if err != nil || len(entries) != 1 || entries[0].Target != "ops" {
		t.Fatal(entries, err)
	}
	s.do("POST", send, s.admin, map[string]string{"channel": "missing"}, 400)
	s.srv.Cfg.Alerts.Channels = append(s.srv.Cfg.Alerts.Channels,
		config.Channel{Name: "pager", Type: "pagerduty", WebhookURL: "key"},
		config.Channel{Name: "broken", Type: "webhook"},
		config.Channel{Name: "fails", Type: "webhook", WebhookURL: ":invalid"})
	if err := s.srv.Alerts.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	b := s.do("POST", send, s.admin, map[string]string{"channel": "pager"}, 400)
	if !strings.Contains(string(b), "pagerduty pages on-call; pick a chat or email channel") {
		t.Fatal(string(b))
	}
	s.do("POST", send, s.admin, map[string]string{"channel": "broken"}, 400)
	s.do("POST", send, s.admin, map[string]string{"channel": "fails"}, 502)
	s.do("POST", send, s.admin, map[string]string{"channel": "ops", "since": "bad"}, 400)
	s.do("POST", send, s.admin, map[string]string{"channel": "ops", "from": "bad"}, 400)
	s.do("POST", send, s.admin, map[string]string{"channel": "ops", "from": "2999-01-01"}, 400)
	s.do("POST", send, s.admin, "invalid", 400)
	s.do("GET", path+"?since=1h", s.read, nil, 200)
}

func TestEventSummaryRead(t *testing.T) {
	d, err := db.Open(t.TempDir() + "/summary.db")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	s := &Server{DB: d}
	from := time.Date(2026, 11, 25, 0, 0, 0, 0, time.Local)
	if err := d.SaveEvent(context.Background(), db.AlertEvent{
		ID: "event", Fingerprint: "event", RuleID: "cpu", ServerID: "host", State: "firing",
		Severity: "warning", StartedAt: from,
	}); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"json", "csv"} {
		r := httptest.NewRequest("GET", "/alerts/events/summary?from=2026-11-25&to=2026-11-25&format="+format, nil)
		w := httptest.NewRecorder()
		s.eventSummary(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		if format == "csv" {
			rows, err := csv.NewReader(w.Body).ReadAll()
			if err != nil || len(rows) != 8 || rows[1][2] != "1" {
				t.Fatal(rows, err)
			}
			want := `attachment; filename="alerts-summary-2026-11-25_2026-11-26.csv"`
			if w.Header().Get("Content-Disposition") != want {
				t.Fatal(w.Header())
			}
			continue
		}
		out := decode[alert.EventSummary](t, w.Body.Bytes())
		if out.Total != 1 || out.Open != 1 || !out.From.Equal(from) || !out.To.Equal(from.AddDate(0, 0, 1)) {
			t.Fatal(out)
		}
	}
	for _, query := range []string{"from=bad", "to=bad", "from=2026-11-26&to=2026-11-24", "since=bad"} {
		w := httptest.NewRecorder()
		s.eventSummary(w, httptest.NewRequest("GET", "/?"+query, nil))
		if w.Code != 400 {
			t.Fatal(query, w.Code, w.Body.String())
		}
	}
	summary, err := s.loadEventSummary(context.Background(), nil)
	if err != nil || summary.From.Hour() != 0 || summary.From.Day() != time.Now().Day() {
		t.Fatal(summary, err)
	}
}

func TestEventSummaryToOnly(t *testing.T) {
	d, err := db.Open(t.TempDir() + "/summary.db")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	s := &Server{DB: d}
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
	q := url.Values{"to": {today.Format(time.DateOnly)}}
	summary, err := s.loadEventSummary(context.Background(), q)
	if err != nil || !summary.From.Equal(today) || !summary.To.Equal(today.AddDate(0, 0, 1)) {
		t.Fatal(summary, err)
	}
	for _, to := range []string{today.AddDate(0, 0, -1).Format(time.DateOnly), today.Format(time.RFC3339)} {
		w := httptest.NewRecorder()
		q.Set("to", to)
		s.eventSummary(w, httptest.NewRequest("GET", "/?"+q.Encode(), nil))
		if w.Code != 400 || !strings.Contains(w.Body.String(), "from must be before to") {
			t.Fatal(to, w.Code, w.Body.String())
		}
	}
}
