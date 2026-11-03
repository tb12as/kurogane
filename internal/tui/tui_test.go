package tui

import (
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tb12as/serverman/internal/collector"
)

func snap() *collector.Snapshot {
	l := func(k, v string) map[string]string { return map[string]string{k: v} }
	return &collector.Snapshot{
		TS: time.Now(),
		Samples: []collector.Sample{
			{Metric: "cpu.total_pct", Value: 42}, {Metric: "cpu.core_pct", Labels: l("core", "0"), Value: 95},
			{Metric: "cpu.core_pct", Labels: l("core", "10"), Value: 5}, {Metric: "mem.used_pct", Value: 60},
			{Metric: "mem.total_bytes", Value: 2 << 30}, {Metric: "net.rx_bps", Labels: l("iface", "eth0"), Value: 2048},
			{Metric: "diskio.read_bps", Labels: l("dev", "sda"), Value: 1 << 20}, {Metric: "net.tcp.established", Value: 7},
		},
		System: collector.SystemInfo{Hostname: "web-01", Uptime: 90000, CPUs: 2},
		TopCPU: []collector.Proc{{PID: 1, Name: "nginx", Cmd: "nginx: master", CPU: 12}},
		TopMem: []collector.Proc{{PID: 2, Name: "mysqld", Cmd: "/usr/sbin/mysqld", RSS: 500 << 20}},
		Mounts: []collector.Mount{{Path: "/", UsedPct: 81, Used: 8 << 30, Total: 10 << 30}},
		Conns:  collector.ConnInfo{TopIPs: []collector.IPCount{{IP: "203.0.113.5", Count: 4}}},
	}
}

func TestView(t *testing.T) {
	calls := 0
	m := newModel(func() (*collector.Snapshot, error) { calls++; return snap(), nil })
	if !strings.Contains(m.View(), "connecting") {
		t.Error("empty view")
	}
	msg := m.Init()()
	x, cmd := m.Update(msg)
	m = x.(model)
	if cmd == nil || calls != 1 {
		t.Fatal("no poll scheduled")
	}
	v := m.View()
	for _, want := range []string{"web-01", "1d1h", "42.0%", "eth0", "2.0K", "sda", "1.0M", "203.0.113.5", "nginx: master",
		"8.0G / 10.0G"} {
		if !strings.Contains(v, want) {
			t.Errorf("view missing %q:\n%s", want, v)
		}
	}
	if strings.Index(v, "  0 [") > strings.Index(v, " 10 [") {
		t.Error("cores not in numeric order")
	}
	x, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
	if v := x.(model).View(); !strings.Contains(v, "mysqld") || strings.Contains(v, "nginx: master") {
		t.Error("sort toggle")
	}
	x, _ = m.Update(snapMsg{err: errors.New("down")})
	if v := x.(model).View(); !strings.Contains(v, "stale: down") || !strings.Contains(v, "web-01") {
		t.Error("stale view")
	}
	if _, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")}); cmd == nil {
		t.Error("q must quit")
	}
	if _, cmd := m.Update(tickMsg{}); cmd == nil {
		t.Error("tick must fetch")
	}
	e := newModel(nil)
	e.err = errors.New("no token")
	if !strings.Contains(e.View(), "no token") {
		t.Error("error view")
	}
}

func TestHelpers(t *testing.T) {
	if bytes(512) != "512B" || bytes(1536) != "1.5K" || trunc("abcdef", 4) != "abc~" || dur(3700) != "1h1m0s" {
		t.Error(bytes(512), bytes(1536), trunc("abcdef", 4), dur(3700))
	}
}
