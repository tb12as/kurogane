package tui

import (
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tb12as/kurogane/internal/certs"
	"github.com/tb12as/kurogane/internal/collector"
	"github.com/tb12as/kurogane/internal/db"
	"github.com/tb12as/kurogane/internal/sshmgr"
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
		System:   collector.SystemInfo{Hostname: "web-01", Uptime: 90000, CPUs: 2},
		TopCPU:   []collector.Proc{{PID: 1, Name: "nginx", Cmd: "nginx: master", CPU: 12}},
		TopMem:   []collector.Proc{{PID: 2, Name: "mysqld", Cmd: "/usr/sbin/mysqld", RSS: 500 << 20}},
		Mounts:   []collector.Mount{{Path: "/", UsedPct: 81, Used: 8 << 30, Total: 10 << 30}},
		Conns:    collector.ConnInfo{TopIPs: []collector.IPCount{{IP: "203.0.113.5", Count: 4}}},
		Services: []collector.ServiceState{{Unit: "nginx.service", Active: "failed", Sub: "failed"}},
		Certs: []certs.Cert{{Name: "shop.example.org", DaysLeft: 2, Stale: true, ServedPort: 443},
			{Name: "broken.pem", Error: "unreadable"}},
		Redis: []collector.RedisInstance{{Name: "redis", Status: collector.RedisUp, Version: "7.2.4", Role: "master",
			MemoryUsed: 1 << 20, OpsPS: 120}, {Name: "cache", Addr: "127.0.0.1:6380", Status: collector.RedisNeedsCreds,
			Hint: "set collector.redis.instances"}},
	}
}

func data() *Data {
	st := &Status{ServerName: "prod-web", Version: "v1.2.3", Alerts: []db.AlertEvent{
		{RuleID: "high_cpu", Severity: "critical", Summary: "CPU above 90%", State: "firing", StartedAt: time.Now()},
		{RuleID: "disk_full", Severity: "warning", State: "acknowledged"}}}
	st.Hardening = &struct {
		Score     float64   `json:"score"`
		Grade     string    `json:"grade"`
		ScannedAt time.Time `json:"scanned_at"`
	}{Score: 78, Grade: "B"}
	return &Data{Snap: snap(), Status: st,
		Sessions: []sshmgr.Session{{User: "deploy", TTY: "pts/0", From: "198.51.100.7", PID: 4242}}}
}

func TestView(t *testing.T) {
	calls := 0
	m := newModel(func() (*Data, error) { calls++; return data(), nil })
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
		"8.0G / 10.0G",
		"prod-web", "kurogane v1.2.3", "2 active", "CPU above 90%", "disk_full", "(acknowledged)", "B 78 / 100",
		"nginx.service", "shop.example.org", "reload the web server", "unreadable", "7.2.4", "needs credentials",
		"set collector.redis.instances", "deploy", "198.51.100.7"} {
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
	x, _ = m.Update(dataMsg{err: errors.New("down")})
	if v := x.(model).View(); !strings.Contains(v, "stale: down") || !strings.Contains(v, "web-01") {
		t.Error("stale view")
	}
	if _, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")}); cmd == nil {
		t.Error("q must quit")
	}
	if _, cmd := m.Update(tickMsg{}); cmd == nil {
		t.Error("tick must fetch")
	}
	// a short terminal clips the body and scrolls
	x, _ = m.Update(tea.WindowSizeMsg{Width: 100, Height: 10})
	sm := x.(model)
	if v := sm.View(); strings.Count(v, "\n") != 9 || !strings.Contains(v, "lines 1-9 of") {
		t.Errorf("clipped view:\n%s", v)
	}
	x, _ = sm.Update(tea.KeyMsg{Type: tea.KeyEnd})
	if v := x.(model).View(); !strings.Contains(v, "198.51.100.7") || strings.Contains(v, "prod-web") {
		t.Errorf("end must show the last section:\n%s", v)
	}
	x, _ = x.(model).Update(tea.KeyMsg{Type: tea.KeyHome})
	if x.(model).off != 0 {
		t.Error("home")
	}
	x, _ = sm.Update(tea.KeyMsg{Type: tea.KeyUp})
	if x.(model).off != 0 {
		t.Error("scroll above top")
	}

	e := newModel(nil)
	e.err = errors.New("no token")
	if !strings.Contains(e.View(), "no token") {
		t.Error("error view")
	}
}

func TestHelpers(t *testing.T) {
	if bytes(512) != "512B" || bytes(1536) != "1.5K" || trunc("abcdef", 4) != "abc~" || dur(3700) != "1h1m" || dur(45) != "45s" || dur(120) != "2m" {
		t.Error(bytes(512), bytes(1536), trunc("abcdef", 4), dur(3700))
	}
}
