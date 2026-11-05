package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tb12as/kurogane/internal/collector"
	"github.com/tb12as/kurogane/internal/config"
	"github.com/tb12as/kurogane/internal/executor"
)

func TestAlertMetricsAndRuleViews(t *testing.T) {
	st := newStack(t)
	var ms []MetricInfo
	json.Unmarshal(st.do("GET", "/api/v1/alerts/metrics", st.read, nil, 200), &ms)
	var disk *MetricInfo
	for i := range ms {
		if ms[i].Name == "disk.used_pct" {
			disk = &ms[i]
		}
	}
	if len(ms) < 90 || disk == nil || disk.Title == "" || disk.Unit != "pct" || disk.Labels[0] != "mount" || disk.Live == nil {
		t.Fatalf("catalog = %d entries, disk = %+v", len(ms), disk)
	}

	// built-in rules come with conditions and a sentence
	var rules []RuleView
	json.Unmarshal(st.do("GET", "/api/v1/alerts/rules", st.read, nil, 200), &rules)
	var cpu *RuleView
	for i := range rules {
		if rules[i].ID == "high_cpu" {
			cpu = &rules[i]
		}
	}
	if cpu == nil || cpu.Conditions == nil || cpu.Conditions.Items[0].Metric != "cpu.total_pct" ||
		cpu.Summary != "CPU usage, all cores above 90 %" {
		t.Fatalf("high_cpu = %+v", cpu)
	}

	// the API refuses unknown metrics and label keys, with a hint
	body := string(st.do("POST", "/api/v1/alerts/rules", st.admin, map[string]any{"id": "typo", "expr": "cpu.total > 9"}, 400))
	if !strings.Contains(body, "did you mean cpu.total_pct?") {
		t.Fatalf("typo body = %s", body)
	}
	st.do("POST", "/api/v1/alerts/rules", st.admin, map[string]any{"id": "lbl", "expr": `disk.used_pct{dev="sda"} > 9`}, 400)
	var created RuleView
	json.Unmarshal(st.do("POST", "/api/v1/alerts/rules", st.admin,
		map[string]any{"id": "root_disk", "name": "Root disk", "expr": `disk.used_pct{mount="/"} > 85`, "for": "5m"}, 200), &created)
	if created.Summary != "Disk space used (mount /) above 85 %" || created.Conditions.Items[0].Labels["mount"] != "/" {
		t.Fatalf("created = %+v", created)
	}
}

func TestAlertMetricsLive(t *testing.T) {
	s := &Server{Metrics: collector.NewManager(config.Collector{Interval: 1e9, Redis: config.Redis{Enabled: "false"}},
		executor.NewFake())}
	v, err := s.alertMetrics(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range v.([]MetricInfo) {
		if m.Live == nil {
			t.Fatalf("%s: live must be an empty list, not null", m.Name)
		}
	}
}
