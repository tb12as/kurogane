package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/serverkeeper/serverkeeper/internal/agentlink"
	"github.com/serverkeeper/serverkeeper/internal/auth"
	"github.com/serverkeeper/serverkeeper/internal/collector"
	"github.com/serverkeeper/serverkeeper/internal/config"
	"github.com/serverkeeper/serverkeeper/internal/db"
	"github.com/serverkeeper/serverkeeper/internal/notify"
	"github.com/serverkeeper/serverkeeper/internal/pb"
	"github.com/serverkeeper/serverkeeper/internal/secret"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type fakeVM struct {
	mu   sync.Mutex
	body strings.Builder
}

type fakeNotifier struct {
	mu  sync.Mutex
	got []notify.Alert
}

func (f *fakeNotifier) Send(_ context.Context, a notify.Alert) error {
	f.mu.Lock()
	f.got = append(f.got, a)
	f.mu.Unlock()
	return nil
}

func (f *fakeNotifier) states() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, a := range f.got {
		out = append(out, a.Rule+":"+a.State)
	}
	return out
}

type env struct {
	c    *Central
	addr string
	vm   *fakeVM
	n    *fakeNotifier
}

func setup(t *testing.T) *env {
	t.Helper()
	e := &env{vm: &fakeVM{}, n: &fakeNotifier{}}
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		e.vm.mu.Lock()
		e.vm.body.Write(b)
		e.vm.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(vm.Close)
	dir := t.TempDir()
	cfg := &config.Config{ServerName: "central", DataDir: dir, SecretKey: filepath.Join(dir, "secret.key")}
	cfg.Server.VM.URL = vm.URL
	cfg.Server.OfflineAfter = 2 * time.Minute
	cfg.Alerts.Channels = []config.Channel{{Name: "ops", Type: "slack"}}
	c, err := New(cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.NewNotifier = func(config.Channel, *secret.Box) (notify.Notifier, error) { return e.n, nil }
	g, err := c.GRPC()
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go g.Serve(lis)
	t.Cleanup(g.Stop)
	e.c, e.addr = c, lis.Addr().String()
	return e
}

func agentLink(t *testing.T, addr, token string) *agentlink.Link {
	dir := t.TempDir()
	cfg := &config.Config{ServerName: "web-01", Tags: []string{"prod"}, DataDir: dir}
	cfg.Central.Addr, cfg.Central.EnrollmentToken = addr, token
	adb, err := db.Open(filepath.Join(dir, "sk.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { adb.Close() })
	return &agentlink.Link{Cfg: cfg, DB: adb, Version: "1.0"}
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if f() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("timed out waiting for " + what)
}

func TestEnrollmentTokenOneTimeAndExpiry(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	tok, _, err := e.c.CreateEnrollToken(ctx, "web-01", "admin")
	if err != nil {
		t.Fatal(err)
	}
	l := agentLink(t, e.addr, tok)
	if err := l.Enroll(ctx); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"client.key", "client.crt", "ca.crt"} {
		st, err := os.Stat(filepath.Join(l.Cfg.DataDir, "central", f))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, err, st)
		}
	}
	srv, err := e.c.DB.GetServerByName(ctx, "web-01")
	if err != nil || srv.CertFingerprint == "" {
		t.Fatal(srv, err)
	}
	if err := agentLink(t, e.addr, tok).Enroll(ctx); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("token reuse: %v", err)
	}

	// expired token
	if err := e.c.DB.CreateEnrollToken(ctx, db.EnrollToken{Hash: auth.HashToken("old"), CreatedBy: "x",
		CreatedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	err = agentLink(t, e.addr, "old."+e.c.CA.Pin()).Enroll(ctx)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired token: %v", err)
	}
	// wrong CA pin: the agent refuses to talk to an impostor
	tok2, _, _ := e.c.CreateEnrollToken(ctx, "web-02", "admin")
	sec, _, _ := strings.Cut(tok2, ".")
	if err := agentLink(t, e.addr, sec+"."+strings.Repeat("0", 64)).Enroll(ctx); err == nil {
		t.Fatal("wrong pin accepted")
	}
}

func TestMTLSRejectsForeignAndMissingCert(t *testing.T) {
	e := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rogue, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certPEM, _, err := rogue.SignClient(&k.PublicKey, "evil")
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := marshalKey(k)
	cert, err := tls.X509KeyPair(certPEM, kd)
	if err != nil {
		t.Fatal(err)
	}
	for name, certs := range map[string][]tls.Certificate{"foreign": {cert}, "none": nil} {
		tc := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: ServerName, RootCAs: e.c.CA.Pool, Certificates: certs}
		conn, err := grpc.NewClient(e.addr, grpc.WithTransportCredentials(credentials.NewTLS(tc)))
		if err != nil {
			t.Fatal(err)
		}
		st, err := pb.NewFleetClient(conn).Connect(ctx)
		if err == nil {
			_, err = st.Recv()
		}
		conn.Close()
		if err == nil {
			t.Fatalf("%s cert: stream accepted", name)
		}
	}
	if len(e.c.sessions) != 0 {
		t.Fatal("session opened")
	}
}

func TestAgentRoundTrip(t *testing.T) {
	e := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tok, _, _ := e.c.CreateEnrollToken(ctx, "web-01", "admin")
	l := agentLink(t, e.addr, tok)
	added := make(chan string, 1)
	l.AddKey = func(_ context.Context, user, pub, label string, _ time.Time) (db.SSHKey, error) {
		added <- user + "|" + label
		return db.SSHKey{Fingerprint: "SHA256:abc", User: user, Type: "ssh-ed25519", PublicKey: pub}, nil
	}
	go l.Run(ctx)

	var srv db.Server
	eventually(t, "hello", func() bool {
		srv, _ = e.c.DB.GetServerByName(ctx, "web-01")
		return srv.Status == "online" && srv.AgentVersion == "1.0" && e.c.Connected(srv.ID)
	})

	l.OnSnapshot(&collector.Snapshot{TS: time.UnixMilli(1700000000000), Samples: []collector.Sample{
		{Metric: "cpu.total_pct", Value: 42.5},
		{Metric: "disk.used_pct", Labels: map[string]string{"mount": "/"}, Value: 70},
	}})
	eventually(t, "samples in VM", func() bool {
		e.c.Flush(ctx)
		e.vm.mu.Lock()
		defer e.vm.mu.Unlock()
		b := e.vm.body.String()
		return strings.Contains(b, `cpu.total_pct{server="web-01"} 42.5 1700000000000`) &&
			strings.Contains(b, `disk.used_pct{mount="/",server="web-01"} 70 1700000000000`)
	})

	o := addKeyOp{User: "deploy", PublicKey: "ssh-ed25519 AAAA", Label: "budi"}
	op, err := e.c.Enqueue(ctx, srv.ID, "add_key", o)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-added:
		if got != "deploy|budi" {
			t.Fatal(got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AddKey op not delivered")
	}
	eventually(t, "op result", func() bool {
		ops, _ := e.c.DB.ListOps(ctx, 10)
		return len(ops) == 1 && ops[0].ID == op.ID && ops[0].Status == "done"
	})
	if keys, _ := e.c.DB.FindKeys(ctx, "SHA256:abc"); len(keys) != 1 || keys[0].ServerID != srv.ID {
		t.Fatalf("central inventory: %+v", keys)
	}

	// agent audit and alert events are stored under the server id
	l.ForwardAudit(db.AuditEntry{Actor: "root", Action: "ssh.key.add", Target: "deploy"})
	eventually(t, "audit", func() bool {
		a, _ := e.c.DB.ListAudit(ctx, db.AuditFilter{Action: "ssh.key.add"})
		return len(a) == 1 && a[0].ServerID == srv.ID
	})
	ev := db.AlertEvent{ID: "e1", RuleID: "high_cpu", Fingerprint: "high_cpu", State: "firing", Severity: "warning",
		Summary: "CPU 95%", StartedAt: time.Now()}
	_ = l.DB.SaveEvent(ctx, ev)
	l.PollOnce(ctx)
	l.PollOnce(ctx) // unchanged: not re-sent
	eventually(t, "alert routed", func() bool { return len(e.n.states()) == 1 })
	got, err := e.c.DB.GetEvent(ctx, srv.ID+":e1")
	if err != nil || got.ServerID != srv.ID {
		t.Fatal(got, err)
	}
}

func TestOfflineDetection(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	s := db.Server{ID: "s1", Name: "web-01", Status: "online", LastSeen: time.Now().Add(-3 * time.Minute)}
	if err := e.c.DB.UpsertServer(ctx, s); err != nil {
		t.Fatal(err)
	}
	e.c.CheckOffline(ctx)
	e.c.CheckOffline(ctx) // dedup: still one alert
	ev, err := e.c.DB.OpenEvent(ctx, "agent_offline:s1")
	if err != nil || ev.Severity != "critical" || ev.ServerID != "s1" {
		t.Fatal(ev, err)
	}
	if got, _ := e.c.DB.GetServer(ctx, "s1"); got.Status != "offline" {
		t.Fatal(got.Status)
	}
	eventually(t, "offline notify", func() bool { return len(e.n.states()) == 1 })

	e.c.touch(ctx, "s1", time.Now())
	if _, err := e.c.DB.OpenEvent(ctx, "agent_offline:s1"); err == nil {
		t.Fatal("not resolved")
	}
	eventually(t, "resolve notify", func() bool {
		st := e.n.states()
		return len(st) == 2 && st[1] == "agent_offline:resolved"
	})
}

func TestRoutingAndFleetAPI(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.c.Cfg.Alerts.Routing = map[string][]string{"critical": {"pager"}, "tag:prod": {"ops"}}
	got := e.c.Channels(db.Server{Name: "a", Tags: []string{"prod"}}, "x", "critical")
	if strings.Join(got, ",") != "pager,ops" {
		t.Fatal(got)
	}

	for _, s := range []db.Server{{ID: "s1", Name: "web-01", Tags: []string{"prod"}}, {ID: "s2", Name: "db-01"}} {
		_ = e.c.DB.UpsertServer(ctx, s)
	}
	raw, _, err := e.c.API.Auth.CreateToken(ctx, "t", []string{auth.ScopeAdmin}, "test", 0)
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(e.c.API.Build())
	defer h.Close()
	call := func(method, path, body string, out any) int {
		req, _ := http.NewRequest(method, h.URL+"/api/v1"+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+raw)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if out != nil {
			json.NewDecoder(resp.Body).Decode(out)
		}
		return resp.StatusCode
	}
	var p db.Person
	if c := call("POST", "/fleet/people", `{"name":"budi","groups":["devs"]}`, &p); c != 200 {
		t.Fatal(c)
	}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl budi@laptop"
	var k db.PersonKey
	if c := call("POST", "/fleet/people/budi/keys", `{"public_key":"`+key+`"}`, &k); c != 200 ||
		!strings.HasPrefix(k.Fingerprint, "SHA256:") {
		t.Fatal(c, k)
	}
	var push struct {
		Ops     []db.FleetOp `json:"ops"`
		Servers int          `json:"servers"`
	}
	if c := call("POST", "/fleet/keys/push", `{"group":"devs","user":"deploy","tag":"prod"}`, &push); c != 200 ||
		len(push.Ops) != 1 || push.Ops[0].ServerID != "s1" {
		t.Fatal(c, push)
	}
	if c := call("POST", "/fleet/keys/revoke", `{"fingerprint":"`+k.Fingerprint+`"}`, &push); c != 200 ||
		len(push.Ops) != 2 {
		t.Fatal(c, push)
	}
	if pp, _ := e.c.DB.GetPerson(ctx, "budi"); len(pp.Keys) != 0 {
		t.Fatal("revoked key still assigned to person")
	}
	var ov []overviewRow
	if c := call("GET", "/fleet/overview", "", &ov); c != 200 || len(ov) != 2 {
		t.Fatal(c, ov)
	}
	var tk map[string]any
	if c := call("POST", "/fleet/enrollment-tokens", `{"name":"web-09"}`, &tk); c != 200 ||
		!strings.HasSuffix(tk["token"].(string), "."+e.c.CA.Pin()) {
		t.Fatal(c, tk)
	}
	if c := call("DELETE", "/servers/db-01", "", nil); c != 200 {
		t.Fatal(c)
	}
	if _, err := e.c.DB.GetServer(ctx, "s2"); err == nil {
		t.Fatal("server not deleted")
	}
}

func marshalKey(k *ecdsa.PrivateKey) ([]byte, error) {
	b, err := x509.MarshalECPrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), err
}
