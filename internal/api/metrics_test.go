package api

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tb12as/serverman/internal/collector"
	"github.com/tb12as/serverman/internal/config"
	"github.com/tb12as/serverman/internal/executor"
	"github.com/tb12as/serverman/internal/store"
)

func TestParseTime(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Time{
		"":                     {},
		"2026-11-03T10:00:00Z": time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC),
		"1700000000":           time.Unix(1700000000, 0),
		"6h":                   now.Add(-6 * time.Hour),
		"-30m":                 now.Add(-30 * time.Minute),
		"7d":                   now.Add(-7 * 24 * time.Hour),
	} {
		got, err := parseTime(in, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("parseTime(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := parseTime("yesterday", now); err == nil {
		t.Error("want error")
	}
}

func TestWriteProm(t *testing.T) {
	w := httptest.NewRecorder()
	writeProm(w, []collector.Sample{
		{Metric: "cpu.total_pct", Value: 12.5},
		{Metric: "cpu.core_pct", Labels: map[string]string{"core": "1"}, Value: 3},
		{Metric: "disk.used_pct", Labels: map[string]string{"mount": `/a "b"`}, Value: 50},
		{Metric: "cpu.core_pct", Labels: map[string]string{"core": "0"}, Value: 2},
	})
	want := "# TYPE serverkeeper_cpu_core_pct gauge\n" +
		"serverkeeper_cpu_core_pct{core=\"1\"} 3\n" +
		"serverkeeper_cpu_core_pct{core=\"0\"} 2\n" +
		"# TYPE serverkeeper_cpu_total_pct gauge\n" +
		"serverkeeper_cpu_total_pct 12.5\n" +
		"# TYPE serverkeeper_disk_used_pct gauge\n" +
		"serverkeeper_disk_used_pct{mount=\"/a \\\"b\\\"\"} 50\n"
	if got := w.Body.String(); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestMetricsHandlers(t *testing.T) {
	s := &Server{}
	if _, err := s.metricsCurrent(nil); err == nil || err.(*HTTPError).Code != 503 {
		t.Errorf("current without collector: %v", err)
	}
	s.Metrics = collector.NewManager(config.Collector{Interval: time.Second}, executor.NewFake())
	if _, err := s.metricsCurrent(nil); err == nil || !strings.Contains(err.Error(), "retry") {
		t.Errorf("current before first tick: %v", err)
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s.Store = st
	now := time.Now()
	for i := 0; i < 3; i++ {
		ts := now.Add(time.Duration(i-3) * 10 * time.Second)
		st.Append(ts, []collector.Sample{{Metric: "cpu.total_pct", Value: float64(i)}, {Metric: "mem.used_pct", Value: 5},
			{Metric: "load.1", Value: 1}})
	}
	r := httptest.NewRequest("GET", "/api/v1/metrics/history?names=cpu,mem&from=5m&step=10s", nil)
	v, err := s.metricsHistory(r)
	if err != nil {
		t.Fatal(err)
	}
	h := v.(HistoryResponse)
	if len(h.Series) != 2 || h.Series[0].Metric != "cpu.total_pct" || len(h.Series[0].Points) != 3 || h.Step != "10s" {
		t.Errorf("history = %+v", h)
	}
	for _, q := range []string{"from=bad", "step=-1s", "from=1h&to=2h"} {
		r := httptest.NewRequest("GET", "/api/v1/metrics/history?"+q, nil)
		if _, err := s.metricsHistory(r); err == nil || err.(*HTTPError).Code != 400 {
			t.Errorf("%s: want 400, got %v", q, err)
		}
	}
}
