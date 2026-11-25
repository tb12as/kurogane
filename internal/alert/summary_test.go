package alert

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tb12as/kurogane/internal/config"
	"github.com/tb12as/kurogane/internal/db"
	"github.com/tb12as/kurogane/internal/notify"
	"github.com/tb12as/kurogane/internal/secret"
)

func TestSummarize(t *testing.T) {
	from := time.Date(2026, 11, 25, 0, 0, 0, 0, time.Local)
	to := from.Add(12 * time.Hour)
	evs := []db.AlertEvent{
		{RuleID: "b", ServerID: "b", Severity: "warning", State: "firing", Noise: true},
		{RuleID: "a", ServerID: "a", Severity: "critical", State: "acknowledged"},
		{RuleID: "b", ServerID: "a", Severity: "info", State: "resolved"},
		{RuleID: "c", ServerID: "c", Severity: "warning", State: "resolved"},
	}
	s := Summarize(evs, from, to)
	if s.Total != 4 || s.Open != 2 || s.Noise != 1 || s.From != from || s.To != to {
		t.Fatalf("summary: %+v", s)
	}
	if !reflect.DeepEqual(s.BySeverity, map[string]int{"critical": 1, "warning": 2, "info": 1}) ||
		!reflect.DeepEqual(s.ByState, map[string]int{"firing": 1, "acknowledged": 1, "resolved": 2}) ||
		!reflect.DeepEqual(s.ByRule, []SummaryCount{{"b", 2}, {"a", 1}, {"c", 1}}) ||
		!reflect.DeepEqual(s.ByServer, []SummaryCount{{"a", 2}, {"b", 1}, {"c", 1}}) {
		t.Fatalf("counts or ordering: %+v", s)
	}
	a := SummaryAlert(s, "https://dashboard.example/")
	if a.ID != "summary" || a.Rule != "summary" || a.State != "summary" || a.Severity != "critical" ||
		a.DashboardURL != "https://dashboard.example/alerts?tab=events" || a.SilenceURL != "" ||
		len(a.Fields) != 3 || !strings.Contains(a.Text, "Total: 4") {
		t.Fatalf("alert: %+v", a)
	}
	for _, sev := range []string{"warning", "info"} {
		if a := SummaryAlert(Summarize([]db.AlertEvent{{Severity: sev}}, from, to), ""); a.Severity != sev {
			t.Fatal(a)
		}
	}
	empty := Summarize(nil, from, to)
	if empty.Total != 0 || empty.Open != 0 || empty.Noise != 0 || len(empty.BySeverity) != 0 ||
		empty.ByRule == nil || empty.ByServer == nil || SummaryAlert(empty, "").Severity != "info" {
		t.Fatalf("empty: %+v", empty)
	}
	for i := 0; i < 12; i++ {
		s.ByRule = append(s.ByRule, SummaryCount{Key: "extra", Count: 1})
	}
	if strings.Count(SummaryAlert(s, "").Text, "extra: 1") != 7 {
		t.Fatal("top rules must be limited to ten")
	}
}

type summarySink struct {
	messages []notify.Alert
	err      error
}

func (s *summarySink) Send(_ context.Context, a notify.Alert) error {
	s.messages = append(s.messages, a)
	return s.err
}

func TestSendSummary(t *testing.T) {
	sink := &summarySink{}
	e := &Engine{
		d: Deps{Cfg: &config.Config{ServerName: "web-01"}, ServerID: "agent-01"},
		chans: map[string]config.Channel{
			"ops": {Type: "webhook"}, "broken": {Type: "webhook"}, "pager": {Type: "pagerduty"},
		},
		notif: map[string]notify.Notifier{"ops": sink},
	}
	now := time.Now()
	a := SummaryAlert(Summarize(nil, now, now.Add(time.Hour)), "")
	ctx := context.Background()
	if err := e.SendSummary(ctx, "ops", a); err != nil || len(sink.messages) != 1 {
		t.Fatal(err, sink.messages)
	}
	if sink.messages[0].Server != "web-01" {
		t.Fatal(sink.messages[0])
	}
	e.d.Cfg.ServerName = ""
	if err := e.SendSummary(ctx, "ops", a); err != nil || sink.messages[1].Server != "agent-01" {
		t.Fatal(err, sink.messages)
	}
	for _, channel := range []string{"missing", "broken", "pager"} {
		if _, ok := e.SendSummary(ctx, channel, a).(*ChannelError); !ok {
			t.Fatalf("expected channel error for %s", channel)
		}
	}
	sink.err = fmt.Errorf("delivery failed https://example.com/secret?token=private")
	if err := e.SendSummary(ctx, "ops", a); err == nil || !strings.Contains(err.Error(), "retry") ||
		!strings.Contains(err.Error(), secret.Redact(sink.err.Error())) {
		t.Fatal(err)
	}
}

func TestSummaryAlertLocalTitle(t *testing.T) {
	from := time.Date(2026, 11, 25, 0, 0, 0, 0, time.FixedZone("remote", 14*60*60))
	to := from.Add(23*time.Hour + 10*time.Minute + 44*time.Second + 123*time.Millisecond)
	a := SummaryAlert(Summarize(nil, from, to), "")
	want := "Alert summary " + from.Local().Format("2006-01-02 15:04 MST") +
		" to " + to.Local().Format("2006-01-02 15:04 MST")
	if a.Title != want {
		t.Fatalf("title = %q, want %q", a.Title, want)
	}
}
