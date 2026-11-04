package sites

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tb12as/kurogane/internal/db"
	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/store"
)

// seqExec fails `nginx -t` from the nth call on (0 = never), on top of the fake executor.
type seqExec struct {
	*executor.Fake
	mu       sync.Mutex
	tests    int
	failFrom int
}

func (s *seqExec) Run(ctx context.Context, cmd string, args ...string) ([]byte, error) {
	if cmd == "nginx" {
		s.mu.Lock()
		s.tests++
		n := s.tests
		s.mu.Unlock()
		if s.failFrom > 0 && n >= s.failFrom {
			s.Fake.Run(ctx, cmd, args...)
			return nil, &executor.RunError{Cmd: "nginx -t", Stderr: "nginx: [emerg] duplicate listen options for [::]:80"}
		}
	}
	return s.Fake.Run(ctx, cmd, args...)
}

type rig struct {
	m     *Manager
	ex    *seqExec
	db    *db.SQLite
	st    *store.Store
	f     *fired
	root  string
	down  map[string]bool // site names the probe reports as not answering
	mu    sync.Mutex
	after bool // probes after the change
}

func setup(t *testing.T) *rig {
	t.Helper()
	r := &rig{root: tree(t, debianNginx), ex: &seqExec{Fake: executor.NewFake()}, f: &fired{}, down: map[string]bool{}}
	dir := t.TempDir()
	var err error
	if r.db, err = db.Open(filepath.Join(dir, "m.db")); err != nil {
		t.Fatal(err)
	}
	if r.st, err = store.Open(filepath.Join(dir, "a.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.st.Close(); r.db.Close() })
	r.m = New(Deps{Ex: r.ex, DB: r.db, Store: r.st, Fire: r.f.fire, SelfPort: "9443"})
	r.m.probe = func(_ context.Context, s Site) bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return !(r.after && r.down[s.Name])
	}
	old, oldS := ProbeRetries, ProbeSpacing
	ProbeRetries, ProbeSpacing = 2, time.Millisecond
	t.Cleanup(func() { ProbeRetries, ProbeSpacing = old, oldS })
	r.m.Scan(ctx, true)
	return r
}

func (r *rig) id(name string) string {
	for _, s := range r.m.Inventory().Sites {
		if s.Name == name {
			return s.ID
		}
	}
	return "missing:" + name
}

func (r *rig) exists(p string) bool {
	_, err := os.Lstat(filepath.Join(r.root, p))
	return err == nil
}

func TestPlan(t *testing.T) {
	r := setup(t)
	p, err := r.m.Plan(ctx, r.id("_"), false)
	if err != nil {
		t.Fatal(err)
	}
	if p.Action != "disable" || len(p.Ops) != 1 || p.Ops[0] != (FileOp{Op: "unlink", From: "/etc/nginx/sites-available/default",
		To: "/etc/nginx/sites-enabled/default"}) || p.Diff != "- /etc/nginx/sites-enabled/default -> /etc/nginx/sites-available/default\n" {
		t.Fatalf("plan = %+v", p)
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "_ is the default site on port 80") {
		t.Errorf("warnings = %v", p.Warnings)
	}
	if !strings.Contains(p.Impact[0], "Stops serving _ on port 80.") || !strings.Contains(p.Impact[1], "nginx -t") {
		t.Errorf("impact = %v", p.Impact)
	}

	p, _ = r.m.Plan(ctx, r.id("shop.example.org"), false)
	w := strings.Join(p.Warnings, "\n")
	if len(p.Affected) != 2 || !strings.Contains(w, "holds 2 sites") || !strings.Contains(w, "port 443") {
		t.Errorf("shop plan = %+v", p)
	}
	p, _ = r.m.Plan(ctx, r.id("old.example.org"), true)
	if p.Ops[0].Op != "link" || p.Diff != "+ /etc/nginx/sites-enabled/old -> ../sites-available/old\n" {
		t.Errorf("enable plan = %+v", p)
	}
	p, _ = r.m.Plan(ctx, r.id("legacy.example.com"), true)
	if p.Ops[0] != (FileOp{Op: "rename", From: "/etc/nginx/conf.d/legacy.conf.disabled", To: "/etc/nginx/conf.d/legacy.conf"}) {
		t.Errorf("rename plan = %+v", p)
	}
	for id, want := range map[string]string{
		r.id("old.example.org"): "already disabled", r.id("status.local"): "cannot be toggled",
		r.id("app.example.com"): "upstream block",
	} {
		if _, err := r.m.Plan(ctx, id, false); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", id, err)
		}
	}
	if _, err := r.m.Plan(ctx, "nope", true); !errors.Is(err, ErrNotFound) {
		t.Errorf("not found: %v", err)
	}
}

func TestPlanWarnings(t *testing.T) {
	r := setup(t)
	inv := r.m.Inventory()
	for i := range inv.Sites {
		s := &inv.Sites[i]
		switch s.Name {
		case "api.example.com":
			s.Upstreams = []string{"http://127.0.0.1:9443"}
		case "old.example.org":
			d := 5.0
			s.CertDays, s.Names = &d, []string{"old.example.org", "local.example"}
		}
	}
	r.m.mu.Lock()
	r.m.inv = inv
	r.m.mu.Unlock()
	p, _ := r.m.Plan(ctx, r.id("api.example.com"), false)
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "proxies to Kurogane itself") {
		t.Errorf("self warning missing: %v", p.Warnings)
	}
	p, _ = r.m.Plan(ctx, r.id("old.example.org"), true)
	w := strings.Join(p.Warnings, "\n")
	if !strings.Contains(w, "expires in 5.0 days") || !strings.Contains(w, "local.example") {
		t.Errorf("enable warnings = %v", p.Warnings)
	}
}

func TestApplyDisableAndEnable(t *testing.T) {
	r := setup(t)
	ch, err := r.m.Apply(ctx, r.id("_"), false)
	if err != nil || ch.Status != "applied" || ch.Action != "disable" || ch.Ops != "unlink /etc/nginx/sites-enabled/default" {
		t.Fatalf("change = %+v %v", ch, err)
	}
	if r.exists("etc/nginx/sites-enabled/default") || !r.exists("etc/nginx/sites-available/default") {
		t.Fatal("link not removed")
	}
	if !r.ex.Called("systemctl reload nginx") {
		t.Fatal("not reloaded")
	}
	if s := r.m.Inventory().Find("_"); len(s) != 1 || s[0].Enabled {
		t.Fatalf("inventory not rescanned: %+v", s)
	}
	ch, err = r.m.Apply(ctx, r.id("_"), true)
	if err != nil || ch.Status != "applied" {
		t.Fatalf("enable = %+v %v", ch, err)
	}
	if got, _ := os.Readlink(filepath.Join(r.root, "etc/nginx/sites-enabled/default")); got != "../sites-available/default" {
		t.Fatalf("link = %q", got)
	}
	if _, err := r.m.Apply(ctx, r.id("api.example.com"), false); err != nil || !r.exists("etc/nginx/conf.d/api.conf.disabled") {
		t.Fatalf("rename disable: %v", err)
	}
	cs, _ := r.m.Changes(ctx)
	if len(cs) != 3 || cs[0].Status != "applied" {
		t.Fatalf("history = %+v", cs)
	}
	if len(r.f.evs) != 0 {
		t.Fatalf("unexpected alerts: %+v", r.f.evs)
	}
}

func TestApplyConfigTestFails(t *testing.T) {
	r := setup(t)
	r.ex.failFrom = r.ex.tests + 2 // the pre-check passes, the check after the move fails
	ch, err := r.m.Apply(ctx, r.id("old.example.org"), true)
	if err == nil || ch.Status != "failed" || !strings.Contains(err.Error(), "duplicate listen") ||
		!strings.Contains(err.Error(), "nothing was reloaded") {
		t.Fatalf("change = %+v %v", ch, err)
	}
	if r.exists("etc/nginx/sites-enabled/old") {
		t.Fatal("link not undone")
	}
	if r.ex.Called("systemctl reload") {
		t.Fatal("reloaded a broken config")
	}
}

func TestApplyRefusesBrokenConfig(t *testing.T) {
	r := setup(t)
	r.ex.failFrom = 1
	_, err := r.m.Apply(ctx, r.id("_"), false)
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "already fails") || !r.exists("etc/nginx/sites-enabled/default") {
		t.Fatalf("err = %v", err)
	}
}

func TestApplyReloadFails(t *testing.T) {
	r := setup(t)
	r.ex.Errors["systemctl reload nginx"] = &executor.RunError{Cmd: "systemctl reload nginx", Stderr: "Job failed"}
	ch, err := r.m.Apply(ctx, r.id("_"), false)
	if err == nil || ch.Status != "rolled_back" || !r.exists("etc/nginx/sites-enabled/default") {
		t.Fatalf("change = %+v %v", ch, err)
	}
	if len(r.f.evs) != 1 || r.f.evs[0].Rule != "site_change_rolled_back" || !r.f.evs[0].Once ||
		!strings.Contains(r.f.evs[0].Text, "systemctl reload nginx failed: Job failed.") {
		t.Fatalf("alert = %+v", r.f.evs)
	}
}

func TestApplyInactiveAfterReload(t *testing.T) {
	r := setup(t)
	r.ex.Errors["systemctl is-active --quiet nginx"] = errors.New("inactive")
	ch, err := r.m.Apply(ctx, r.id("_"), false)
	if err == nil || ch.Status != "rolled_back" || !strings.Contains(ch.Error, "not active") {
		t.Fatalf("change = %+v %v", ch, err)
	}
}

func TestApplyProbeLost(t *testing.T) {
	r := setup(t)
	r.down["api.example.com"] = true
	orig := r.ex.Fake
	r.ex.Fake = orig
	r.m.probe = func(_ context.Context, s Site) bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		// after the reload call, api.example.com stops answering
		return !(orig.Called("systemctl reload nginx") && r.down[s.Name])
	}
	ch, err := r.m.Apply(ctx, r.id("_"), false)
	if err == nil || ch.Status != "rolled_back" || !strings.Contains(ch.Error, "api.example.com stopped answering") {
		t.Fatalf("change = %+v %v", ch, err)
	}
	if !r.exists("etc/nginx/sites-enabled/default") {
		t.Fatal("not undone")
	}
}

func TestApplyOpFailsAndBusy(t *testing.T) {
	r := setup(t)
	r.ex.Errors["unlink-site /etc/nginx/sites-enabled/default"] = errors.New("permission denied")
	ch, err := r.m.Apply(ctx, r.id("_"), false)
	if err == nil || ch.Status != "failed" || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("change = %+v %v", ch, err)
	}
	if r.ex.Called("link-site") {
		t.Fatal("undid an operation that never happened")
	}
	r.m.applyMu.Lock()
	_, err = r.m.Apply(ctx, r.id("_"), false)
	r.m.applyMu.Unlock()
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("busy: %v", err)
	}
}

func TestResume(t *testing.T) {
	r := setup(t)
	// simulate a crash after the unlink
	os.Remove(filepath.Join(r.root, "etc/nginx/sites-enabled/default"))
	pd := pending{Change: db.SiteChange{ID: "c1", SiteName: "_", Kind: "nginx", Action: "disable", Status: "applying",
		TS: time.Now()}, Unit: "nginx", Undo: []FileOp{{Op: "link", From: "/etc/nginx/sites-available/default",
		To: "/etc/nginx/sites-enabled/default"}}}
	r.m.savePending(&pd)
	r.m.resume(ctx)
	if !r.exists("etc/nginx/sites-enabled/default") || !r.ex.Called("systemctl reload nginx") {
		t.Fatal("not restored")
	}
	cs, _ := r.m.Changes(ctx)
	if len(cs) != 1 || cs[0].Status != "rolled_back" || len(r.f.evs) != 1 {
		t.Fatalf("history = %+v alerts = %+v", cs, r.f.evs)
	}
	r.m.resume(ctx) // nothing pending any more
	if cs, _ := r.m.Changes(ctx); len(cs) != 1 {
		t.Fatal("resumed twice")
	}
}

func TestFileOps(t *testing.T) {
	for _, o := range []FileOp{{Op: "link", From: "/a/x", To: "/b/x"}, {Op: "unlink", From: "/a/x", To: "/b/x"},
		{Op: "rename", From: "/c/x.conf", To: "/c/x.conf.disabled"}} {
		if o.Undo().Undo() != o {
			t.Errorf("undo twice of %v", o)
		}
	}
	if (FileOp{Op: "rename", From: "a", To: "b"}).String() != "rename a -> b" {
		t.Error("string")
	}
}

func TestReloadAndConfig(t *testing.T) {
	r := setup(t)
	if err := r.m.Reload(ctx, "nginx"); err != nil || !r.ex.Called("systemctl reload nginx") {
		t.Fatalf("reload: %v", err)
	}
	if err := r.m.Reload(ctx, "apache"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("apache: %v", err)
	}
	r.ex.failFrom = 1
	if err := r.m.Reload(ctx, "nginx"); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "duplicate listen") {
		t.Fatalf("broken config reloaded: %v", err)
	}
	r.ex.failFrom = 0
	r.ex.Errors["systemctl reload nginx"] = errors.New("boom")
	if err := r.m.Reload(ctx, "nginx"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("reload error: %v", err)
	}
	f, text, err := r.m.Config(ctx, r.id("_"))
	if err != nil || f != "/etc/nginx/sites-available/default" || !strings.Contains(text, "default_server") {
		t.Fatalf("config = %q %q %v", f, text, err)
	}
	if _, _, err := r.m.Config(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
