package alert

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tb12as/kurogane/internal/db"
	"github.com/tb12as/kurogane/internal/notify"
	"github.com/tb12as/kurogane/internal/secret"
)

// SummaryCount holds the event count for one grouping key.
type SummaryCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// EventSummary contains event totals and grouped counts for a period.
type EventSummary struct {
	From       time.Time      `json:"from"`
	To         time.Time      `json:"to"`
	Total      int            `json:"total"`
	Open       int            `json:"open"`
	Noise      int            `json:"noise"`
	BySeverity map[string]int `json:"by_severity"`
	ByState    map[string]int `json:"by_state"`
	ByRule     []SummaryCount `json:"by_rule"`
	ByServer   []SummaryCount `json:"by_server"`
}

// Summarize aggregates the supplied events for the given period.
func Summarize(evs []db.AlertEvent, from, to time.Time) EventSummary {
	s := EventSummary{From: from, To: to, Total: len(evs), BySeverity: map[string]int{}, ByState: map[string]int{}}
	rules, servers := map[string]int{}, map[string]int{}
	for _, ev := range evs {
		if ev.State != "resolved" {
			s.Open++
		}
		if ev.Noise {
			s.Noise++
		}
		s.BySeverity[ev.Severity]++
		s.ByState[ev.State]++
		rules[ev.RuleID]++
		servers[ev.ServerID]++
	}
	s.ByRule, s.ByServer = summaryCounts(rules), summaryCounts(servers)
	return s
}

func summaryCounts(counts map[string]int) []SummaryCount {
	out := make([]SummaryCount, 0, len(counts))
	for key, count := range counts {
		out = append(out, SummaryCount{Key: key, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// SummaryAlert renders an event summary as a notification.
func SummaryAlert(s EventSummary, dashboardURL string) notify.Alert {
	a := notify.Alert{ID: "summary", Rule: "summary", State: "summary", Severity: "info", StartedAt: s.From,
		Title: "Alert summary " + s.From.Local().Format("2006-01-02 15:04 MST") +
			" to " + s.To.Local().Format("2006-01-02 15:04 MST")}
	var text strings.Builder
	fmt.Fprintf(&text, "Total: %d\nOpen: %d\nNoise: %d\n", s.Total, s.Open, s.Noise)
	for _, sev := range []string{"critical", "warning", "info"} {
		count := s.BySeverity[sev]
		if count > 0 && sevRank[sev] > sevRank[a.Severity] {
			a.Severity = sev
		}
		fmt.Fprintf(&text, "%s: %d\n", sev, count)
		a.Fields = append(a.Fields, notify.Field{Name: sev, Value: strconv.Itoa(count)})
	}
	text.WriteString("Top rules:")
	for _, rule := range s.ByRule[:min(10, len(s.ByRule))] {
		fmt.Fprintf(&text, "\n%s: %d", rule.Key, rule.Count)
	}
	a.Text = text.String()
	if u := strings.TrimRight(dashboardURL, "/"); u != "" {
		a.DashboardURL = u + "/alerts?tab=events"
	}
	return a
}

// ChannelError indicates a channel selection the caller must correct before sending.
type ChannelError struct{ Err error }

func (e *ChannelError) Error() string { return e.Err.Error() }

// SendSummary sends a summary directly to a configured non-paging channel.
func (e *Engine) SendSummary(ctx context.Context, channel string, a notify.Alert) error {
	n, err := e.channel(channel, true)
	if err != nil {
		return &ChannelError{Err: err}
	}
	a.Server = e.d.Cfg.ServerName
	if a.Server == "" {
		a.Server = e.d.ServerID
	}
	if err := n.Send(ctx, a); err != nil {
		return fmt.Errorf("summary delivery failed: %s; check the channel and retry", secret.Redact(err.Error()))
	}
	return nil
}
