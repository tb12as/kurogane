package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tb12as/kurogane/internal/audit"
	"github.com/tb12as/kurogane/internal/certs"
	"github.com/tb12as/kurogane/internal/collector"
	"github.com/tb12as/kurogane/internal/config"
	"github.com/tb12as/kurogane/internal/db"
	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/firewall"
	"github.com/tb12as/kurogane/internal/store"
)

type hookSink struct {
	mu   sync.Mutex
	msgs []map[string]any
	code int
}

func (h *hookSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var m map[string]any
	json.NewDecoder(r.Body).Decode(&m)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.code != 0 {
		w.WriteHeader(h.code)
		return
	}
	h.msgs = append(h.msgs, m)
}

func (h *hookSink) n() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.msgs)
}

func setup(t *testing.T, mut func(*config.Config)) (*Engine, *hookSink, *time.Time) {
	t.Helper()
	dir := t.TempDir()
	d, err := db.Open(filepath.Join(dir, "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close(); d.Close() })
	sink := &hookSink{}
	srv := httptest.NewServer(sink)
	t.Cleanup(srv.Close)
	cfg := &config.Config{ServerName: "web-01"}
	cfg.Alerts.Channels = []config.Channel{{Name: "ops", Type: "webhook", WebhookURL: srv.URL}}
	cfg.Alerts.RepeatInterval = 30 * time.Minute
	if mut != nil {
		mut(cfg)
	}
	e, err := NewEngine(Deps{Cfg: cfg, DB: d, Store: st})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 3, 23, 0, 0, 0, time.Local)
	e.now = func() time.Time { return now }
	return e, sink, &now
}

func snap(kv ...any) *collector.Snapshot {
	s := &collector.Snapshot{}
	for i := 0; i < len(kv); i += 2 {
		s.Samples = append(s.Samples, collector.Sample{Metric: kv[i].(string), Value: kv[i+1].(float64)})
	}
	return s
}

func TestExpr(t *testing.T) {
	ss := []collector.Sample{
		{Metric: "disk.used_pct", Labels: map[string]string{"mount": "/"}, Value: 90},
		{Metric: "disk.used_pct", Labels: map[string]string{"mount": "/data"}, Value: 50},
		{Metric: "cpu.total_pct", Value: 60},
	}
	for expr, want := range map[string]int{
		`disk.used_pct > 85`:                          1,
		`disk.used_pct{mount="/data"} > 40`:           1,
		`disk.used_pct > 85 and cpu.total_pct > 50`:   1,
		`disk.used_pct > 95 or cpu.total_pct > 50`:    2,
		`(cpu.total_pct < 10 || cpu.total_pct >= 60)`: 1,
	} {
		n, err := parse(expr)
		if err != nil {
			t.Fatal(expr, err)
		}
		got := 0
		for _, in := range n.eval(ss) {
			if in.ok {
				got++
			}
		}
		if got != want {
			t.Errorf("%s: %d firing, want %d", expr, got, want)
		}
	}
	for _, bad := range []string{"cpu >", "cpu.total_pct ~ 3", `disk{mount=/} > 1`, "(cpu > 1"} {
		if _, err := parse(bad); err == nil {
			t.Errorf("%q must fail", bad)
		}
	}
}

func TestLifecycleDedupRepeatResolve(t *testing.T) {
	e, sink, now := setup(t, nil)
	ctx := context.Background()
	high := snap("cpu.total_pct", 95.0)

	e.Eval(ctx, high)
	*now = now.Add(4 * time.Minute)
	e.Eval(ctx, high)
	e.Flush(ctx)
	if sink.n() != 0 {
		t.Fatal("fired before for: 5m")
	}
	*now = now.Add(time.Minute + time.Second)
	e.Eval(ctx, high)
	e.Eval(ctx, high) // dedup
	e.Flush(ctx)
	if sink.n() != 1 {
		t.Fatalf("want 1 firing message, got %d", sink.n())
	}
	*now = now.Add(31 * time.Minute)
	e.Eval(ctx, high)
	e.Flush(ctx)
	if sink.n() != 2 || sink.msgs[1]["state"] != "reminder" {
		t.Fatalf("want reminder, got %v", sink.msgs)
	}
	evs, _ := e.d.DB.ListEvents(ctx, db.EventFilter{State: "open"})
	if len(evs) != 1 {
		t.Fatal("one open event expected")
	}
	if _, err := e.Ack(ctx, evs[0].ID, "admin"); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(31 * time.Minute)
	e.Eval(ctx, high)
	e.Flush(ctx)
	if sink.n() != 2 {
		t.Fatal("acked alert must not repeat")
	}
	e.Eval(ctx, snap("cpu.total_pct", 20.0))
	e.Flush(ctx)
	if sink.n() != 3 || sink.msgs[2]["state"] != "resolved" {
		t.Fatalf("want resolved message, got %v", sink.msgs)
	}
}

func TestEscalationAndText(t *testing.T) {
	e, sink, now := setup(t, nil)
	ctx := context.Background()
	s := snap("mem.available_pct", 8.0, "mem.available_bytes", 3.2e8, "mem.total_bytes", 4e9, "swap.used_pct", 0.0)
	s.TopMem = []collector.Proc{{Name: "java", RSS: 2.1e9}, {Name: "mysqld", RSS: 1.2e9}}
	e.Eval(ctx, s)
	*now = now.Add(6 * time.Minute)
	e.Eval(ctx, s)
	e.Flush(ctx)
	if sink.n() != 1 || sink.msgs[0]["severity"] != "warning" {
		t.Fatalf("want warning: %v", sink.msgs)
	}
	raw, _ := json.Marshal(sink.msgs[0])
	if !strings.Contains(string(raw), "Available memory 8.0%") || !strings.Contains(string(raw), "java 2.0 GB") {
		t.Fatalf("message: %s", raw)
	}
	s.Samples[0].Value = 4
	e.Eval(ctx, s)
	e.Flush(ctx)
	if sink.n() != 2 || sink.msgs[1]["severity"] != "critical" {
		t.Fatalf("want escalation to critical: %v", sink.msgs)
	}
}

func TestSilenceAndRateLimit(t *testing.T) {
	e, sink, now := setup(t, func(c *config.Config) { c.Alerts.RateLimit = 3 })
	ctx := context.Background()
	if _, err := e.Silence(ctx, db.Silence{Matcher: db.Matcher{Rule: "ssh_login"}, EndsAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	e.Fire(ctx, Event{Rule: "ssh_login", Once: true, Text: "root from 1.2.3.4"})
	e.Flush(ctx)
	if sink.n() != 0 {
		t.Fatal("silenced alert was sent")
	}
	for i := 0; i < 6; i++ {
		e.Fire(ctx, Event{Rule: "hardening_drift", Once: true, Text: "x"})
	}
	e.Flush(ctx)
	if sink.n() != 3 {
		t.Fatalf("rate limit: %d sent", sink.n())
	}
	*now = now.Add(61 * time.Second)
	e.Flush(ctx)
	if sink.n() != 4 || sink.msgs[3]["state"] != "summary" {
		t.Fatalf("want overflow summary: %v", sink.msgs[len(sink.msgs)-1])
	}
}

func TestQueueRetry(t *testing.T) {
	e, sink, now := setup(t, nil)
	ctx := context.Background()
	sink.code = 503
	e.Fire(ctx, Event{Rule: "ssh_rolled_back", Once: true, Text: "rolled back"})
	e.Flush(ctx)
	sink.mu.Lock()
	sink.code = 0
	sink.mu.Unlock()
	e.Flush(ctx) // backoff not elapsed
	if sink.n() != 0 {
		t.Fatal("retried before backoff")
	}
	*now = now.Add(3 * time.Second)
	e.Flush(ctx)
	if sink.n() != 1 {
		t.Fatal("not retried after backoff")
	}
	n := 0
	e.d.Store.List(queueBucket, func(string, []byte) error { n++; return nil })
	if n != 0 {
		t.Fatal("queue not drained")
	}
}

func TestBaselineZScore(t *testing.T) {
	var b baseline
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b.First = t0
	for i := 0; i < 8*24*60; i++ {
		ts := t0.Add(time.Duration(i) * time.Minute)
		b.EWMA.add(1e6+float64(i%10)*1e4, ewmaN)
		b.Week[hourOfWeek(ts)].add(1e6+float64(i%10)*1e4, weekN)
	}
	now := t0.Add(8 * 24 * time.Hour)
	if !b.ready(now) {
		t.Fatal("baseline should be ready after 7 days")
	}
	mean, sd := b.expect(now)
	if z := zscore(5e7, mean, sd); z < zLimit {
		t.Fatalf("spike z=%v", z)
	}
	e := &Engine{base: map[string]*baseline{"net.rx_bps_total": &b}}
	if _, bad := e.anomalous("net.rx_bps_total", 5e6, now); bad {
		t.Fatal("below the absolute floor must not alert")
	}
	if _, bad := e.anomalous("net.rx_bps_total", 5e7, now); !bad {
		t.Fatal("spike above floor must alert")
	}
}

func TestDDoSBody(t *testing.T) {
	s := snap("net.tcp.syn_recv", 900.0)
	s.Conns.TopIPs = []collector.IPCount{{IP: "198.51.100.7", Count: 300}}
	s.Conns.SynCookies = true
	txt, f := ddosText(s)
	if !strings.Contains(txt, "upstream mitigation") || f[0].Value != "198.51.100.7 (300)" || f[3].Value != "on" {
		t.Fatal(txt, f)
	}
}

// AL-6: auto-ban is off by default; when on it bans clear offenders, never allowlisted IPs, up to max_bans
func TestAutoBan(t *testing.T) {
	e, _, _ := setup(t, func(c *config.Config) {
		c.Alerts.AutoBan = config.AutoBan{Enabled: true, Duration: 30 * time.Minute, MaxBans: 2, Allowlist: []string{"203.0.113.0/24"}}
	})
	ex := executor.NewFake()
	ex.Outputs["iptables -S INPUT"] = "-P INPUT ACCEPT"
	ex.Errors["iptables -C INPUT -j KUROGANE"] = &executor.RunError{Cmd: "iptables"}
	ex.Errors["ip6tables -C INPUT -j KUROGANE"] = &executor.RunError{Cmd: "ip6tables"}
	for _, ip := range []string{"198.51.100.7", "198.51.100.8"} {
		ex.Errors["iptables -C KUROGANE -s "+ip+" -j DROP"] = &executor.RunError{Cmd: "iptables"}
	}
	e.d.Firewall = firewall.New(ex)
	e.d.Audit = &audit.Logger{Store: e.d.DB}
	ctx := context.Background()
	s := snap("net.tcp.syn_recv", 900.0)
	s.Conns.TopIPs = []collector.IPCount{{IP: "203.0.113.5", Count: 900}, {IP: "198.51.100.7", Count: 400},
		{IP: "198.51.100.8", Count: 300}, {IP: "198.51.100.9", Count: 250}, {IP: "192.0.2.1", Count: 3}}
	e.Eval(ctx, s)
	bans := e.d.Firewall.Bans()
	if len(bans) != 2 || bans[0].IP == "203.0.113.5" || bans[1].IP == "203.0.113.5" {
		t.Fatalf("want 2 bans (cap), never the allowlisted IP: %+v", bans)
	}
	if ex.Called("iptables -I KUROGANE -s 198.51.100.9") || ex.Called("iptables -I KUROGANE -s 192.0.2.1") {
		t.Fatal("cap exceeded or low-count source banned")
	}
	if !allowed([]string{"10.0.0.0/8"}, "10.1.2.3") || allowed([]string{"10.0.0.0/8"}, "11.1.2.3") {
		t.Fatal("allowlist matching")
	}
}

func certSnap(now time.Time, list ...certs.Cert) *collector.Snapshot {
	s := &collector.Snapshot{Certs: list}
	for _, c := range list {
		l := map[string]string{"name": c.Name}
		stale := 0.0
		if c.Stale {
			stale = 1
		}
		s.Samples = append(s.Samples,
			collector.Sample{Metric: "cert.days_left", Labels: l, Value: certs.Days(c.NotAfter, now)},
			collector.Sample{Metric: "cert.stale_served", Labels: l, Value: stale})
	}
	return s
}

func TestCertRules(t *testing.T) {
	e, sink, now := setup(t, nil)
	ctx := context.Background()
	day := 24 * time.Hour
	le := certs.Cert{Name: "example.com", Origin: certs.OriginLetsEncrypt, Path: "/etc/letsencrypt/live/example.com/fullchain.pem",
		Info: certs.Info{NotAfter: now.Add(10 * day), Issuer: "Let's Encrypt R11"}}
	shop := certs.Cert{Name: "shop.example.org", Origin: certs.OriginNginx, Info: certs.Info{NotAfter: now.Add(60 * day)},
		Stale: true, ServedNotAfter: now.Add(2 * day), ServedPort: 443}
	ok := certs.Cert{Name: "ok.example", Info: certs.Info{NotAfter: now.Add(80 * day)}}
	le.DaysLeft = 10

	e.Eval(ctx, certSnap(*now, le, shop, ok))
	e.Flush(ctx)
	if sink.n() != 1 || sink.msgs[0]["severity"] != "warning" {
		t.Fatalf("want one expiring warning (stale waits 1h): %v", sink.msgs)
	}
	raw, _ := json.Marshal(sink.msgs[0])
	for _, want := range []string{"example.com expires in 10.0 days", "certbot renew --dry-run", "Let's Encrypt R11",
		"/etc/letsencrypt/live/example.com/fullchain.pem"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("message lacks %q: %s", want, raw)
		}
	}

	// the stale certificate fires after an hour; expiring does not remind at 30 minutes
	*now = now.Add(time.Hour + time.Minute)
	e.Eval(ctx, certSnap(*now, le, shop, ok))
	e.Flush(ctx)
	if sink.n() != 2 {
		t.Fatalf("want stale alert: %v", sink.msgs)
	}
	raw, _ = json.Marshal(sink.msgs[1])
	if !strings.Contains(string(raw), "still sends the old certificate") || !strings.Contains(string(raw), "127.0.0.1:443") {
		t.Fatalf("stale message: %s", raw)
	}

	// under 3 days escalates to critical, and an expired certificate says so
	le.NotAfter = now.Add(-2 * day)
	le.DaysLeft = -2
	e.Eval(ctx, certSnap(*now, le, shop, ok))
	e.Flush(ctx)
	if sink.n() != 3 || sink.msgs[2]["severity"] != "critical" {
		t.Fatalf("want critical: %v", sink.msgs)
	}
	if raw, _ = json.Marshal(sink.msgs[2]); !strings.Contains(string(raw), "expired 2.0 days ago") {
		t.Fatalf("expired message: %s", raw)
	}

	// renewed and reloaded: both resolve
	le.NotAfter, le.DaysLeft = now.Add(90*day), 90
	shop.Stale = false
	e.Eval(ctx, certSnap(*now, le, shop, ok))
	e.Flush(ctx)
	if sink.n() != 5 || sink.msgs[3]["state"] != "resolved" || sink.msgs[4]["state"] != "resolved" {
		t.Fatalf("want two resolves: %v", sink.msgs)
	}
	if repeatOverride["cert_expiring"] != 24*time.Hour {
		t.Fatal("cert_expiring must remind daily")
	}
	if txt, _ := certText("cert_expiring", "gone", &collector.Snapshot{}); txt != "Certificate gone is expiring" {
		t.Fatal(txt)
	}
}

func redisSnap(in collector.RedisInstance, kv ...any) *collector.Snapshot {
	s := &collector.Snapshot{Redis: []collector.RedisInstance{in}}
	l := map[string]string{"instance": in.Name}
	for i := 0; i < len(kv); i += 2 {
		s.Samples = append(s.Samples, collector.Sample{Metric: kv[i].(string), Labels: l, Value: kv[i+1].(float64)})
	}
	return s
}

func TestRedisRules(t *testing.T) {
	healthy := []any{"redis.up", 1.0, "redis.rdb_ok", 1.0, "redis.memory_used_pct", 40.0, "redis.evicted_keys_ps", 0.0,
		"redis.clients_pct", 10.0, "redis.rejected_connections_ps", 0.0, "redis.ping_ms", 0.4}
	in := collector.RedisInstance{Name: "cache", Addr: "127.0.0.1:6379", Status: "up", MaxMemory: 1 << 30,
		MemoryUsed: 1 << 29, MaxMemoryPolicy: "noeviction", Clients: 9, MaxClients: 10, RDBStatus: "err",
		ChangesSinceSave: 1234}
	for _, tc := range []struct {
		rule, metric string
		v            float64
		wait         time.Duration
		sev, text    string
	}{
		{"redis_down", "redis.up", 0, time.Minute + time.Second, "critical", "does not answer"},
		{"redis_persistence_failing", "redis.rdb_ok", 0, 0, "critical", "1234 changes are not on disk"},
		{"redis_memory_high", "redis.memory_used_pct", 95, 5*time.Minute + time.Second, "warning", "95.0% of maxmemory 1.0 GB"},
		{"redis_evicting", "redis.evicted_keys_ps", 3, 5*time.Minute + time.Second, "warning", "evicting 3.0 keys/s"},
		{"redis_clients_high", "redis.rejected_connections_ps", 2, 0, "warning", "9 of 10 client connections"},
		{"redis_slow", "redis.ping_ms", 120, 5*time.Minute + time.Second, "warning", "120 ms to answer PING"},
	} {
		t.Run(tc.rule, func(t *testing.T) {
			e, sink, now := setup(t, nil)
			ctx := context.Background()
			kv := append([]any{}, healthy...)
			for i := 0; i < len(kv); i += 2 {
				if kv[i] == tc.metric {
					kv[i+1] = tc.v
				}
			}
			e.Eval(ctx, redisSnap(in, healthy...))
			e.Eval(ctx, redisSnap(in, kv...))
			*now = now.Add(tc.wait)
			e.Eval(ctx, redisSnap(in, kv...))
			e.Flush(ctx)
			if sink.n() != 1 || sink.msgs[0]["severity"] != tc.sev {
				t.Fatalf("messages = %v", sink.msgs)
			}
			raw, _ := json.Marshal(sink.msgs[0])
			if !strings.Contains(string(raw), tc.text) || !strings.Contains(string(raw), tc.rule) {
				t.Fatalf("message lacks %q: %s", tc.text, raw)
			}
		})
	}
	// a replica that lost its primary, and wrong credentials
	e, sink, now := setup(t, nil)
	ctx := context.Background()
	rep := collector.RedisInstance{Name: "replica", Status: "up", Role: "slave"}
	e.Eval(ctx, redisSnap(rep, "redis.up", 1.0, "redis.replica_link_up", 0.0))
	*now = now.Add(2*time.Minute + time.Second)
	e.Eval(ctx, redisSnap(rep, "redis.up", 1.0, "redis.replica_link_up", 0.0))
	e.Flush(ctx)
	if sink.n() != 1 || !strings.Contains(fmt.Sprint(sink.msgs[0]), "lost its link to the primary") {
		t.Fatalf("replication = %v", sink.msgs)
	}
	if txt := redisText("redis_down", "x", &collector.Snapshot{Redis: []collector.RedisInstance{{Name: "x",
		Status: collector.RedisAuthFailed}}}, 0); !strings.Contains(txt, "rejects Kurogane's credentials") {
		t.Fatal(txt)
	}
}
