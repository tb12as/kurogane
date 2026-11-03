package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/tb12as/serverman/internal/alert"
	"github.com/tb12as/serverman/internal/audit"
	"github.com/tb12as/serverman/internal/auth"
	"github.com/tb12as/serverman/internal/collector"
	"github.com/tb12as/serverman/internal/config"
	"github.com/tb12as/serverman/internal/db"
	"github.com/tb12as/serverman/internal/executor"
	"github.com/tb12as/serverman/internal/firewall"
	"github.com/tb12as/serverman/internal/harden"
	"github.com/tb12as/serverman/internal/hostfs"
	"github.com/tb12as/serverman/internal/secret"
	"github.com/tb12as/serverman/internal/sshmgr"
	"github.com/tb12as/serverman/internal/store"
	"golang.org/x/crypto/ssh"
)

type stack struct {
	t     *testing.T
	url   string
	admin string
	read  string
	srv   *Server
	sink  *[]map[string]any
}

func fixture(t *testing.T, root string, files map[string]string) {
	for p, c := range files {
		full := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func newKey() string {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
}

func newStack(t *testing.T) *stack {
	t.Helper()
	root := t.TempDir()
	old := hostfs.Root
	hostfs.Root = root
	t.Cleanup(func() { hostfs.Root = old })
	fixture(t, root, map[string]string{
		"/etc/passwd":                       "root:x:0:0:root:/root:/bin/bash\ndeploy:x:1000:1000::/home/deploy:/bin/bash\n",
		"/etc/group":                        "root:x:0:\nsudo:x:27:deploy\n",
		"/etc/shadow":                       "root:*:19000::::::\ndeploy:$6$x:19000::::::\n",
		"/etc/os-release":                   "ID=ubuntu\nVERSION_ID=24.04\nPRETTY_NAME=\"Ubuntu 24.04\"\n",
		"/etc/ssh/sshd_config":              "PasswordAuthentication yes\nKbdInteractiveAuthentication no\n",
		"/home/deploy/.ssh/authorized_keys": newKey() + " deploy@laptop\n",
	})
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
	box, _ := secret.New(strings.Repeat("cd", 32))

	var got []map[string]any
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		got = append(got, m)
	}))
	t.Cleanup(hook.Close)

	cfg := &config.Config{ServerName: "web-01", Listen: "127.0.0.1:0", DataDir: dir}
	cfg.Collector.Interval = 10 * time.Second
	cfg.Collector.RetentionRaw = 24 * time.Hour
	cfg.Collector.Prometheus = true
	cfg.SSH.ConfigPath = "/etc/ssh/sshd_config"
	cfg.SSH.RollbackTimeout = time.Minute
	cfg.Alerts.Channels = []config.Channel{{Name: "ops", Type: "webhook", WebhookURL: hook.URL}}
	ex := executor.NewFake()
	ex.Errors["systemctl is-active --quiet fail2ban"] = &executor.RunError{Cmd: "systemctl"}
	lg := &audit.Logger{Store: d}
	fw := firewall.New(ex)
	hub := NewHub()
	al, err := alert.NewEngine(alert.Deps{Cfg: cfg, DB: d, Store: st, Box: box, Audit: lg, Firewall: fw, Publish: hub.Publish})
	if err != nil {
		t.Fatal(err)
	}
	sm := sshmgr.New(sshmgr.Deps{Cfg: cfg, DB: d, Store: st, Ex: ex, Audit: lg, Alerts: al, Firewall: fw, Publish: hub.Publish})
	mm := collector.NewManager(cfg.Collector, ex)
	hs := harden.New(harden.Deps{Cfg: cfg, DB: d, Ex: ex, Audit: lg, SSH: sm, Firewall: fw, Alerts: al,
		ServerID: "local", Latest: mm.Latest, Publish: hub.Publish})
	as := auth.NewService(d, box, time.Hour)
	s := &Server{Cfg: cfg, DB: d, Store: st, Auth: as, Audit: lg, Box: box, Ex: ex, Metrics: mm, Alerts: al, SSH: sm,
		Harden: hs, Firewall: fw, Hub: hub, Version: "test",
		UI: fstest.MapFS{"index.html": {Data: []byte("<html>ui</html>")}, "app.js": {Data: []byte("js")}}}
	ts := httptest.NewServer(s.Build())
	t.Cleanup(ts.Close)
	adminTok, _, _ := as.CreateToken(context.Background(), "admin", []string{auth.ScopeAdmin}, "test", 0)
	readTok, _, _ := as.CreateToken(context.Background(), "ro", []string{auth.ScopeRead}, "test", 0)
	return &stack{t: t, url: ts.URL, admin: adminTok, read: readTok, srv: s, sink: &got}
}

func (s *stack) do(method, path, tok string, body any, want int) []byte {
	s.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, s.url+path, rd)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		s.t.Fatalf("%s %s: HTTP %d, want %d: %s", method, path, resp.StatusCode, want, b)
	}
	return b
}

func decode[T any](t *testing.T, b []byte) T {
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	return v
}

func TestAuthAndCore(t *testing.T) {
	s := newStack(t)
	s.do("GET", "/api/v1/health", "", nil, 200)
	s.do("GET", "/api/v1/status", "", nil, 401)
	s.do("GET", "/api/v1/status", "bogus", nil, 401)
	s.do("GET", "/api/v1/status", s.read, nil, 200)
	s.do("POST", "/api/v1/users", s.read, map[string]string{"username": "x", "password": "0123456789"}, 403)
	s.do("GET", "/api/v1/openapi.yaml", "", nil, 200)
	if b := s.do("GET", "/some/client/route", "", nil, 200); string(b) != "<html>ui</html>" {
		t.Fatalf("spa fallback: %s", b)
	}
	s.do("GET", "/app.js", "", nil, 200)

	// user + TOTP login + CSRF on a session
	b := s.do("POST", "/api/v1/users", s.admin, map[string]string{"username": "alice", "password": "correct horse battery", "role": "operator"}, 200)
	u := decode[struct {
		TOTPURL string `json:"totp_url"`
	}](t, b)
	q, _ := url.Parse(u.TOTPURL)
	code, _ := auth.TOTPCode(q.Query().Get("secret"), time.Now())
	s.do("POST", "/api/v1/auth/login", "", map[string]string{"username": "alice", "password": "nope-nope-nope", "totp": code}, 401)
	body, _ := json.Marshal(map[string]string{"username": "alice", "password": "correct horse battery", "totp": code})
	resp, err := http.Post(s.url+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("login: %v %d", err, resp.StatusCode)
	}
	var lr struct {
		CSRF string `json:"csrf"`
	}
	json.NewDecoder(resp.Body).Decode(&lr)
	resp.Body.Close()
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == auth.SessionCookie {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly {
		t.Fatal("session cookie missing or not HttpOnly")
	}
	req, _ := http.NewRequest("POST", s.url+"/api/v1/harden/scans", nil)
	req.AddCookie(cookie)
	r2, _ := http.DefaultClient.Do(req)
	if r2.StatusCode != 403 {
		t.Fatalf("session POST without CSRF must be 403, got %d", r2.StatusCode)
	}
	req, _ = http.NewRequest("GET", s.url+"/api/v1/auth/me", nil)
	req.AddCookie(cookie)
	r3, _ := http.DefaultClient.Do(req)
	if r3.StatusCode != 200 {
		t.Fatalf("me: %d", r3.StatusCode)
	}

	b = s.do("POST", "/api/v1/tokens", s.admin, map[string]any{"name": "ci", "scopes": []string{"read"}, "ttl": "24h"}, 200)
	if !strings.HasPrefix(decode[map[string]any](t, b)["token"].(string), "sk_") {
		t.Fatal("token format")
	}
	s.do("POST", "/api/v1/tokens", s.admin, map[string]any{"name": "x", "scopes": []string{"root"}}, 400)
	s.do("GET", "/api/v1/tokens", s.admin, nil, 200)
	s.do("DELETE", "/api/v1/tokens/ci", s.admin, nil, 200)
	s.do("GET", "/api/v1/users", s.admin, nil, 200)
	s.do("POST", "/api/v1/users/alice/unlock", s.admin, nil, 200)
	s.do("DELETE", "/api/v1/users/alice", s.admin, nil, 200)
	s.do("POST", "/api/v1/telemetry/first-dashboard", s.admin, nil, 200)
	s.do("POST", "/api/v1/auth/logout", "", nil, 200)

	b = s.do("GET", "/api/v1/audit?since=1h", s.admin, nil, 200)
	es := decode[[]db.AuditEntry](t, b)
	actions := map[string]bool{}
	for _, e := range es {
		actions[e.Action] = true
	}
	for _, a := range []string{"user.create", "auth.login", "auth.login_failed", "token.create", "user.delete"} {
		if !actions[a] {
			t.Errorf("audit missing %s: %v", a, actions)
		}
	}
}

func TestAlertRoutes(t *testing.T) {
	s := newStack(t)
	s.do("GET", "/api/v1/alerts/rules", s.read, nil, 200)
	s.do("POST", "/api/v1/alerts/rules", s.read, map[string]string{"id": "x"}, 403)
	s.do("POST", "/api/v1/alerts/rules", s.admin, map[string]any{"id": "load_high", "expr": "load.1 > ", "for": "1m"}, 400)
	s.do("POST", "/api/v1/alerts/rules", s.admin, map[string]any{"id": "load_high", "expr": "load.1 > 8", "for": "1m",
		"severity": "critical", "channels": []string{"ops"}}, 200)
	s.do("POST", "/api/v1/alerts/rules", s.admin, map[string]any{"id": "load_high", "expr": "load.1 > 8"}, 409)
	s.do("PUT", "/api/v1/alerts/rules/load_high", s.admin, map[string]any{"for": "2m"}, 200)
	s.do("DELETE", "/api/v1/alerts/rules/high_cpu", s.admin, nil, 400)
	s.do("PUT", "/api/v1/alerts/rules/high_cpu", s.admin, map[string]any{"enabled": false}, 200)
	s.do("DELETE", "/api/v1/alerts/rules/load_high", s.admin, nil, 200)

	s.do("POST", "/api/v1/alerts/channels", s.admin, map[string]string{"name": "x", "type": "nope", "webhook_url": "https://e"}, 400)
	s.do("POST", "/api/v1/alerts/channels", s.admin, map[string]string{"name": "hook2", "type": "webhook", "webhook_url": "https://example.invalid/h"}, 200)
	b := s.do("GET", "/api/v1/alerts/channels", s.read, nil, 200)
	if strings.Contains(string(b), "example.invalid") {
		t.Fatal("channel list leaked a secret")
	}
	chs, _ := s.srv.DB.ListChannels(context.Background())
	if len(chs) != 1 || !secret.IsSealed(chs[0].Config["webhook_url"]) {
		t.Fatal("webhook URL must be stored sealed")
	}
	s.do("POST", "/api/v1/alerts/channels/ops/test", s.admin, nil, 200)
	s.do("POST", "/api/v1/alerts/channels/nope/test", s.admin, nil, 502)
	s.do("DELETE", "/api/v1/alerts/channels/hook2", s.admin, nil, 200)

	s.do("POST", "/api/v1/alerts/silences", s.admin, map[string]string{"for": "2h"}, 400)
	b = s.do("POST", "/api/v1/alerts/silences", s.admin, map[string]string{"rule": "high_cpu", "for": "2h", "reason": "maintenance"}, 200)
	sl := decode[db.Silence](t, b)
	s.do("GET", "/api/v1/alerts/silences?active=true", s.read, nil, 200)
	s.do("DELETE", "/api/v1/alerts/silences/"+sl.ID, s.admin, nil, 200)

	s.srv.Alerts.Fire(context.Background(), alert.Event{Rule: "ssh_bruteforce", Text: "x", Labels: map[string]string{"ip": "1.2.3.4"}})
	evs := decode[[]db.AlertEvent](t, s.do("GET", "/api/v1/alerts/events?state=open", s.read, nil, 200))
	if len(evs) != 1 {
		t.Fatalf("events: %+v", evs)
	}
	s.do("POST", "/api/v1/alerts/events/"+evs[0].ID+"/ack", s.admin, nil, 200)
	s.do("POST", "/api/v1/alerts/events/"+evs[0].ID+"/ack", s.admin, nil, 400)
	s.do("POST", "/api/v1/alerts/events/"+evs[0].ID+"/noise", s.admin, map[string]bool{"noise": true}, 200)
	s.do("POST", "/api/v1/alerts/events/missing/ack", s.admin, nil, 404)
	if b := s.do("GET", "/api/v1/alerts/events/export?format=csv", s.read, nil, 200); !strings.HasPrefix(string(b), "id,rule_id") {
		t.Fatalf("csv: %s", b)
	}
	s.do("GET", "/api/v1/alerts/events/export?format=json", s.read, nil, 200)
}

func TestSSHRoutes(t *testing.T) {
	s := newStack(t)
	keys := decode[[]sshmgr.Key](t, s.do("GET", "/api/v1/ssh/keys", s.read, nil, 200))
	if len(keys) != 1 || keys[0].User != "deploy" {
		t.Fatalf("keys: %+v", keys)
	}
	s.do("POST", "/api/v1/ssh/keys", s.read, map[string]string{"user": "deploy"}, 403)
	s.do("POST", "/api/v1/ssh/keys", s.admin, map[string]string{"user": "deploy"}, 400)
	s.do("POST", "/api/v1/ssh/keys", s.admin, map[string]string{"user": "deploy", "public_key": "junk"}, 400)
	k := decode[db.SSHKey](t, s.do("POST", "/api/v1/ssh/keys", s.admin, map[string]string{"user": "deploy",
		"public_key": newKey(), "label": "budi laptop", "expires_at": "2099-01-31"}, 200))
	fp := url.PathEscape(k.Fingerprint)
	s.do("PATCH", "/api/v1/ssh/keys/"+fp, s.admin, map[string]string{"label": "budi desktop"}, 200)
	s.do("DELETE", "/api/v1/ssh/keys/"+fp+"?user=deploy", s.admin, nil, 200)
	s.do("DELETE", "/api/v1/ssh/keys/"+fp, s.admin, nil, 404)

	cfg := decode[map[string]any](t, s.do("GET", "/api/v1/ssh/config", s.read, nil, 200))
	if len(cfg["settings"].([]any)) < 10 {
		t.Fatalf("config: %v", cfg)
	}
	plan := decode[map[string]any](t, s.do("PATCH", "/api/v1/ssh/config", s.admin, map[string]any{
		"set": map[string]string{"PasswordAuthentication": "no"}, "dry_run": true}, 200))
	if !strings.Contains(plan["diff"].(string), "+PasswordAuthentication no") {
		t.Fatalf("plan: %v", plan)
	}
	s.do("PATCH", "/api/v1/ssh/config", s.admin, map[string]any{"set": map[string]string{"Bogus": "1"}}, 400)
	s.do("PATCH", "/api/v1/ssh/config", s.admin, map[string]any{"set": map[string]string{"MaxAuthTries": "3"}, "rollback": "1s"}, 400)
	s.do("PATCH", "/api/v1/ssh/config", s.admin, map[string]any{"set": map[string]string{"MaxAuthTries": "3"}, "rollback": "60s"}, 200)
	cfg = decode[map[string]any](t, s.do("GET", "/api/v1/ssh/config", s.read, nil, 200))
	if cfg["pending"] == nil {
		t.Fatal("pending change missing")
	}
	s.do("POST", "/api/v1/ssh/config/confirm", s.admin, map[string]string{}, 200)
	s.do("POST", "/api/v1/ssh/config/confirm", s.admin, map[string]string{}, 400)
	s.do("GET", "/api/v1/ssh/changes", s.read, nil, 200)
	s.do("GET", "/api/v1/ssh/sessions", s.read, nil, 200)
	s.do("DELETE", "/api/v1/ssh/sessions/abc", s.admin, nil, 400)
	s.do("GET", "/api/v1/ssh/logins?since=7d", s.read, nil, 200)
	s.do("GET", "/api/v1/ssh/logins?since=x", s.read, nil, 400)
	s.do("GET", "/api/v1/ssh/bans", s.read, nil, 200)
	s.do("POST", "/api/v1/ssh/ca/sign", s.admin, map[string]any{"public_key": newKey(), "principals": []string{"deploy"}}, 400)
	s.do("POST", "/api/v1/ssh/ca/init", s.admin, nil, 200)
	s.do("POST", "/api/v1/ssh/config/confirm", s.admin, map[string]string{}, 200)
	b := s.do("POST", "/api/v1/ssh/ca/sign", s.admin, map[string]any{"public_key": newKey(), "principals": []string{"deploy"}, "ttl": "1h"}, 200)
	if !strings.Contains(string(b), "cert-v01") {
		t.Fatalf("cert: %s", b)
	}
}

func TestHardenRoutes(t *testing.T) {
	s := newStack(t)
	s.do("POST", "/api/v1/harden/scans", s.read, nil, 403)
	sc := decode[db.Scan](t, s.do("POST", "/api/v1/harden/scans", s.admin, nil, 200))
	if sc.Grade == "" {
		t.Fatalf("scan: %+v", sc)
	}
	s.do("GET", "/api/v1/harden/scans", s.read, nil, 200)
	s.do("GET", "/api/v1/harden/scans/latest", s.read, nil, 200)
	s.do("GET", "/api/v1/harden/scans/"+sc.ID, s.read, nil, 200)
	for _, f := range []string{"json", "md", "pdf"} {
		s.do("GET", "/api/v1/harden/scans/"+sc.ID+"/report?format="+f, s.read, nil, 200)
	}
	s.do("GET", "/api/v1/harden/checks", s.read, nil, 200)
	s.do("POST", "/api/v1/harden/fixes", s.admin, map[string]any{"check_id": "SYS-SYNCOOKIES"}, 400)
	s.do("POST", "/api/v1/harden/fixes", s.admin, map[string]any{"check_id": "SYS-SYNCOOKIES", "dry_run": true}, 200)
	s.do("GET", "/api/v1/harden/fixes", s.read, nil, 200)
	s.do("POST", "/api/v1/harden/ignores", s.admin, map[string]any{"check_id": "SSH-PORT-NONDEFAULT"}, 400)
	s.do("POST", "/api/v1/harden/ignores", s.admin, map[string]any{"check_id": "SSH-PORT-NONDEFAULT", "reason": "provider console"}, 200)
	s.do("GET", "/api/v1/harden/ignores", s.read, nil, 200)
	s.do("DELETE", "/api/v1/harden/ignores/SSH-PORT-NONDEFAULT", s.admin, nil, 200)
}

func TestMetricsRoutesAndProm(t *testing.T) {
	s := newStack(t)
	s.do("GET", "/api/v1/metrics/current", s.read, nil, 503)
	s.do("GET", "/api/v1/metrics/history?names=cpu&from=1h", s.read, nil, 200)
	s.do("GET", "/metrics", "", nil, 401)
	s.do("GET", "/metrics", s.read, nil, 503)
}

func TestStorageRoutes(t *testing.T) {
	s := newStack(t)
	now := time.Now()
	for i := 0; i < 360; i++ {
		s.srv.Store.Append(now.Add(-time.Hour+time.Duration(i)*10*time.Second),
			[]collector.Sample{{Metric: "cpu.total_pct", Value: float64(i)}})
	}
	st := decode[StorageResponse](t, s.do("GET", "/api/v1/storage", s.read, nil, 200))
	if st.AgentStore == nil || st.AgentStore.RawOldest == nil || len(st.Entries) == 0 || st.TotalBytes == 0 {
		t.Fatalf("storage: %+v", st)
	}

	s.do("POST", "/api/v1/storage/history/clear", s.read, map[string]any{"older_than": "0"}, 403)
	s.do("POST", "/api/v1/storage/history/clear", s.admin, map[string]any{"older_than": "x"}, 400)
	s.do("POST", "/api/v1/storage/history/clear", s.admin, map[string]any{"older_than": "0"}, 200)
	st = decode[StorageResponse](t, s.do("GET", "/api/v1/storage", s.read, nil, 200))
	if st.AgentStore.RawOldest != nil {
		t.Fatalf("history not cleared: %+v", st.AgentStore)
	}

	s.do("POST", "/api/v1/uninstall", s.admin, map[string]any{"confirm": "nope"}, 400)
	// the test binary is not an allowlisted install path, so the executor refuses it
	b := s.do("POST", "/api/v1/uninstall", s.admin, map[string]any{"confirm": "web-01"}, 500)
	if !strings.Contains(string(b), "not allowlisted") {
		t.Fatalf("uninstall: %s", b)
	}
}

// opt-in onboarding telemetry sends only timing + version, once, and only when enabled with a URL
func TestTelemetryOptIn(t *testing.T) {
	got := make(chan map[string]any, 2)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		got <- m
	}))
	defer ts.Close()
	s := newStack(t)
	s.srv.DB.SetKV(context.Background(), "telemetry.installed_at", time.Now().Add(-3*time.Minute).UTC().Format(time.RFC3339))
	s.srv.Cfg.Telemetry.URL = ts.URL
	s.do("POST", "/api/v1/telemetry/first-dashboard", s.admin, nil, 200) // disabled: nothing sent
	s.srv.DB.SetKV(context.Background(), "telemetry.first_dashboard", "")
	s2 := newStack(t)
	s2.srv.Cfg.Telemetry = config.Telemetry{Enabled: true, URL: ts.URL}
	s2.srv.DB.SetKV(context.Background(), "telemetry.installed_at", time.Now().Add(-3*time.Minute).UTC().Format(time.RFC3339))
	s2.do("POST", "/api/v1/telemetry/first-dashboard", s2.admin, nil, 200)
	s2.do("POST", "/api/v1/telemetry/first-dashboard", s2.admin, nil, 200) // second call: already recorded
	select {
	case m := <-got:
		if len(m) != 3 || m["version"] != "test" || m["seconds_to_first_dashboard"].(float64) < 170 {
			t.Fatalf("payload: %v", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("telemetry not sent")
	}
	select {
	case m := <-got:
		t.Fatalf("telemetry sent twice or while disabled: %v", m)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestSSEStream(t *testing.T) {
	s := newStack(t)
	req, _ := http.NewRequest("GET", s.url+"/api/v1/stream", nil)
	req.Header.Set("Authorization", "Bearer "+s.read)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream: %v %v", err, resp)
	}
	defer resp.Body.Close()
	go func() {
		time.Sleep(100 * time.Millisecond)
		s.srv.Hub.Publish("alert", map[string]string{"rule": "high_cpu"})
	}()
	buf := make([]byte, 0, 256)
	tmp := make([]byte, 256)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(string(buf), "high_cpu") {
		n, _ := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
	}
	if !strings.Contains(string(buf), "event: alert") || !strings.Contains(string(buf), "high_cpu") {
		t.Fatalf("no event received: %q", buf)
	}
}
