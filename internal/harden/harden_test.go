package harden

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tb12as/serverman/internal/alert"
	"github.com/tb12as/serverman/internal/collector"
	"github.com/tb12as/serverman/internal/config"
	"github.com/tb12as/serverman/internal/db"
	"github.com/tb12as/serverman/internal/executor"
	"github.com/tb12as/serverman/internal/harden/checks"
	"github.com/tb12as/serverman/internal/hostfs"
)

type fixture struct {
	files  map[string]string
	modes  map[string]os.FileMode
	out    map[string]string
	errs   map[string]error
	ssh    map[string]string
	rocky  bool
	listen []collector.Listener
	cfg    *config.Config
}

type env struct {
	t     *testing.T
	root  string
	s     *Service
	fx    *executor.Fake
	db    *db.SQLite
	sets  []map[string]string // sshmgr safe-apply calls
	bf    []bool              // SetBruteforce calls
	fired []alert.Event
}

func newEnv(t *testing.T, f fixture) *env {
	t.Helper()
	root := t.TempDir()
	old := hostfs.Root
	hostfs.Root = root
	t.Cleanup(func() { hostfs.Root = old })
	files := map[string]string{"/etc/os-release": "ID=ubuntu\nVERSION_ID=\"22.04\"\n"}
	if f.rocky {
		files["/etc/os-release"] = "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.3\"\n"
	}
	for k, v := range f.files {
		files[k] = v
	}
	for p, c := range files {
		real := filepath.Join(root, p)
		if strings.HasSuffix(p, "/") {
			must(t, os.MkdirAll(real, 0o755))
			continue
		}
		must(t, os.MkdirAll(filepath.Dir(real), 0o755))
		must(t, os.WriteFile(real, []byte(c), 0o644))
	}
	for p, m := range f.modes {
		must(t, os.Chmod(filepath.Join(root, p), m))
	}
	fx := executor.NewFake()
	for k, v := range f.out {
		fx.Outputs[k] = v
	}
	for k, v := range f.errs {
		fx.Errors[k] = v
	}
	st, err := db.Open(":memory:")
	must(t, err)
	t.Cleanup(func() { st.Close() })
	cfg := f.cfg
	if cfg == nil {
		cfg = &config.Config{ServerName: "web-01"}
	}
	e := &env{t: t, root: root, fx: fx, db: st}
	var latest func() *collector.Snapshot
	if f.listen != nil {
		latest = func() *collector.Snapshot { return &collector.Snapshot{Conns: collector.ConnInfo{Listening: f.listen}} }
	}
	e.s = New(Deps{Cfg: cfg, DB: st, Ex: fx, Latest: latest})
	e.s.env.ConfigPath = "/etc/serverkeeper/config.yaml"
	if f.ssh != nil {
		e.s.env.Settings = func(context.Context) (map[string]string, error) { return f.ssh, nil }
	}
	e.s.env.SSHApply = func(_ context.Context, set map[string]string) error {
		e.sets = append(e.sets, set)
		return nil
	}
	e.s.env.Bruteforce = func() bool { return false }
	e.s.env.SetBruteforce = func(on bool) { e.bf = append(e.bf, on) }
	e.s.fire = func(_ context.Context, ev alert.Event) { e.fired = append(e.fired, ev) }
	return e
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// tree snapshots content and mode of every fixture file except the backup dir.
func (e *env) tree() map[string]string {
	m := map[string]string{}
	_ = filepath.WalkDir(e.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.Contains(p, "/var/lib/serverkeeper/") {
			return nil
		}
		b, _ := os.ReadFile(p)
		st, _ := os.Stat(p)
		m[strings.TrimPrefix(p, e.root)] = st.Mode().String() + "|" + string(b)
		return nil
	})
	return m
}

func (e *env) read(p string) string {
	b, _ := os.ReadFile(filepath.Join(e.root, p))
	return string(b)
}

func (e *env) called(prefixes ...string) {
	e.t.Helper()
	for _, p := range prefixes {
		if !e.fx.Called(p) {
			e.t.Errorf("missing call %q in %v", p, e.fx.Calls)
		}
	}
}

func eqTree(t *testing.T, a, b map[string]string) {
	t.Helper()
	for k, v := range a {
		if b[k] != v {
			t.Errorf("%s changed: %q -> %q", k, v, b[k])
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			t.Errorf("%s left behind after revert", k)
		}
	}
}

type fixCase struct {
	name  string
	id    string
	f     fixture
	calls []string          // expected after apply
	undo  []string          // expected after revert
	files map[string]string // path -> substring expected after apply
	ssh   bool              // expects a safe-apply call
	pass  bool              // re-run must pass (file-only fixes; fake commands cannot change state)
}

var sshd = map[string]string{"/etc/ssh/sshd_config": ""}

func fixCases() []fixCase {
	pub := func(port int) collector.Listener {
		return collector.Listener{Proto: "tcp", Addr: "0.0.0.0", Port: port}
	}
	ss := func(kv ...string) map[string]string {
		m := map[string]string{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	cs := []fixCase{
		{id: "SSH-ROOT-LOGIN", f: fixture{files: sshd, ssh: ss("permitrootlogin", "yes")}, ssh: true},
		{id: "SSH-PASSWORD-AUTH", f: fixture{files: sshd, ssh: ss("passwordauthentication", "yes")}, ssh: true},
		{id: "SSH-CIPHERS", f: fixture{files: sshd, ssh: ss("ciphers", "aes128-cbc,aes256-ctr")}, ssh: true},
		{id: "SSH-MAXAUTHTRIES", f: fixture{files: sshd, ssh: ss("maxauthtries", "6")}, ssh: true},
		{id: "SSH-X11", f: fixture{files: sshd, ssh: ss("x11forwarding", "yes")}, ssh: true},
		{id: "SSH-EMPTY-PASSWORDS", f: fixture{files: sshd, ssh: ss("permitemptypasswords", "yes")}, ssh: true},
		{id: "SSH-LOGINGRACE", f: fixture{files: sshd, ssh: ss("logingracetime", "120")}, ssh: true},
		{id: "SSH-CLIENTALIVE", f: fixture{files: sshd, ssh: ss("clientaliveinterval", "0")}, ssh: true},
		{id: "ACC-EMPTY-PASSWD", f: fixture{files: map[string]string{"/etc/shadow": "root:$6$x:1::::::\nbob::1::::::\n"}},
			calls: []string{"passwd -l bob"}},
		{id: "ACC-PASS-AGING", f: fixture{files: map[string]string{"/etc/login.defs": "UMASK 022\nPASS_MAX_DAYS\t99999\n"}},
			files: map[string]string{"/etc/login.defs": "PASS_MAX_DAYS\t365"}, pass: true},
		{name: "ufw", id: "FW-ACTIVE", f: fixture{files: map[string]string{"/usr/sbin/ufw": ""}, listen: []collector.Listener{pub(80)},
			out: map[string]string{"ufw status verbose": "Status: inactive\n"}},
			calls: []string{"ufw allow 22/tcp", "ufw allow 80/tcp", "ufw --force enable"}, undo: []string{"ufw disable"}},
		{name: "nft", id: "FW-ACTIVE", f: fixture{files: map[string]string{"/usr/sbin/nft": "", "/etc/nftables.conf": "#!/usr/sbin/nft -f\n"},
			listen: []collector.Listener{pub(443)}},
			calls: []string{"nft -f /etc/serverkeeper/nftables-harden.nft", "systemctl enable nftables"},
			undo:  []string{"nft delete table inet serverkeeper"},
			files: map[string]string{"/etc/serverkeeper/nftables-harden.nft": "tcp dport { 22, 443 } accept",
				"/etc/nftables.conf": `include "/etc/serverkeeper/nftables-harden.nft"`}},
		{name: "firewalld", id: "FW-ACTIVE", f: fixture{rocky: true, files: map[string]string{"/usr/bin/firewall-cmd": ""}},
			calls: []string{"systemctl enable firewalld", "systemctl start firewalld", "firewall-cmd --permanent --add-port=22/tcp",
				"firewall-cmd --reload"}, undo: []string{"systemctl stop firewalld", "systemctl disable firewalld"}},
		{name: "ufw", id: "FW-DEFAULT-DENY", f: fixture{files: map[string]string{"/usr/sbin/ufw": ""},
			out: map[string]string{"ufw status verbose": "Status: active\nDefault: allow (incoming), allow (outgoing)\n"}},
			calls: []string{"ufw allow 22/tcp", "ufw default deny incoming"}, undo: []string{"ufw default allow incoming"}},
		{name: "firewalld", id: "FW-DEFAULT-DENY", f: fixture{rocky: true, files: map[string]string{"/usr/bin/firewall-cmd": ""},
			out: map[string]string{"firewall-cmd --state": "running", "firewall-cmd --list-all": "public\n  target: ACCEPT\n"}},
			calls: []string{"firewall-cmd --permanent --add-port=22/tcp", "firewall-cmd --permanent --set-target=default",
				"firewall-cmd --reload"}, undo: []string{"firewall-cmd --permanent --set-target=ACCEPT"}},
		{name: "ubuntu", id: "UPD-UNATTENDED", f: fixture{}, calls: []string{"apt-get install -y unattended-upgrades"},
			files: map[string]string{"/etc/apt/apt.conf.d/20auto-upgrades": `APT::Periodic::Unattended-Upgrade "1";`}},
		{name: "rocky", id: "UPD-UNATTENDED", f: fixture{rocky: true, errs: map[string]error{"rpm -q dnf-automatic": errors.New("x")}},
			calls: []string{"dnf install -y dnf-automatic", "systemctl enable --now dnf-automatic-install.timer"},
			undo:  []string{"systemctl disable --now dnf-automatic-install.timer"}},
		{name: "ubuntu", id: "UPD-PENDING-SECURITY", f: fixture{out: map[string]string{
			"apt-get -s upgrade": "Inst openssl [1] (2 Ubuntu:22.04/jammy-security [amd64])\n"}},
			calls: []string{"apt-get install -y --only-upgrade openssl"}},
		{name: "rocky", id: "UPD-PENDING-SECURITY", f: fixture{rocky: true, out: map[string]string{
			"dnf -q --cacheonly updateinfo list --security": "RHSA-1 Important/Sec. openssl-3.el9.x86_64\n"}},
			calls: []string{"dnf -y upgrade --security"}},
		{id: "FILE-WORLD-WRITABLE", f: fixture{files: map[string]string{"/usr/bin/evil": ""},
			modes: map[string]os.FileMode{"/usr/bin/evil": 0o777}}, pass: true},
		{id: "SVC-UNUSED", f: fixture{out: map[string]string{
			"systemctl is-active avahi-daemon cups rpcbind nfs-server": "active\ninactive\ninactive\ninactive\n"}},
			calls: []string{"systemctl stop avahi-daemon", "systemctl disable avahi-daemon.socket"},
			undo:  []string{"systemctl enable avahi-daemon", "systemctl start avahi-daemon.socket"}},
		{id: "LOG-JOURNALD-PERSISTENT", f: fixture{files: map[string]string{"/etc/systemd/journald.conf": "[Journal]\n"}},
			calls: []string{"systemctl restart systemd-journald"}, undo: []string{"systemctl restart systemd-journald"},
			files: map[string]string{"/etc/systemd/journald.conf.d/99-serverkeeper.conf": "Storage=persistent"}, pass: true},
		{name: "ubuntu", id: "LOG-AUDITD", f: fixture{}, calls: []string{"apt-get install -y auditd", "systemctl enable auditd",
			"systemctl start auditd"}, undo: []string{"systemctl stop auditd", "systemctl disable auditd"}},
		{name: "rocky", id: "LOG-AUDITD", f: fixture{rocky: true}, calls: []string{"dnf install -y audit"}},
		{id: "LOG-LOGROTATE", f: fixture{files: map[string]string{"/etc/logrotate.conf": ""}},
			calls: []string{"systemctl enable --now logrotate.timer"}, undo: []string{"systemctl disable --now logrotate.timer"}},
		{id: "IPS-BRUTEFORCE", f: fixture{files: map[string]string{"/etc/serverkeeper/config.yaml": "# keep me\nserver_name: web-01\n"}},
			files: map[string]string{"/etc/serverkeeper/config.yaml": "enabled: true"}},
		{id: "TIME-NTP-SYNC", f: fixture{out: map[string]string{"timedatectl show": "NTP=no\nNTPSynchronized=no\n"}},
			calls: []string{"timedatectl set-ntp true"}, undo: []string{"timedatectl set-ntp false"}},
	}
	for _, c := range checks.All(&checks.Env{}) {
		m := c.Info()
		switch {
		case m.Category == "kernel":
			files := map[string]string{}
			var calls, undo []string
			for _, k := range sysctlKeys(c) {
				files["/proc/sys/"+strings.ReplaceAll(k, ".", "/")] = "7\n"
				calls = append(calls, "sysctl -w "+k+"=")
				undo = append(undo, "sysctl -w "+k+"=7")
			}
			cs = append(cs, fixCase{id: m.ID, f: fixture{files: files}, calls: calls, undo: undo,
				files: map[string]string{checks.SysctlFile: sysctlKeys(c)[0] + " = "}})
		case m.Category == "files" && m.AutoFix == checks.FixYes:
			p := map[string]string{"FILE-SHADOW-PERMS": "/etc/shadow", "FILE-PASSWD-PERMS": "/etc/passwd",
				"FILE-SSHD-PERMS": "/etc/ssh/sshd_config"}[m.ID]
			cs = append(cs, fixCase{id: m.ID, f: fixture{files: map[string]string{p: "x"}, modes: map[string]os.FileMode{p: 0o666}},
				pass: true})
		}
	}
	return cs
}

// sysctlKeys lists each built-in sysctl check's kernel parameters.
func sysctlKeys(c checks.Check) []string {
	keys := map[string][]string{
		"SYS-SYNCOOKIES":     {"net.ipv4.tcp_syncookies"},
		"SYS-RP-FILTER":      {"net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter"},
		"SYS-ICMP-REDIRECTS": {"net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.default.accept_redirects", "net.ipv6.conf.all.accept_redirects", "net.ipv6.conf.default.accept_redirects"},
		"SYS-SEND-REDIRECTS": {"net.ipv4.conf.all.send_redirects", "net.ipv4.conf.default.send_redirects"},
		"SYS-SOURCE-ROUTE":   {"net.ipv4.conf.all.accept_source_route", "net.ipv4.conf.default.accept_source_route", "net.ipv6.conf.all.accept_source_route", "net.ipv6.conf.default.accept_source_route"},
		"SYS-ASLR":           {"kernel.randomize_va_space"},
		"SYS-SUID-DUMPABLE":  {"fs.suid_dumpable"},
		"SYS-DMESG-RESTRICT": {"kernel.dmesg_restrict"},
	}
	return keys[c.ID()]
}

func TestFixAndRevert(t *testing.T) {
	covered := map[string]bool{}
	ctx := context.Background()
	for _, tc := range fixCases() {
		t.Run(tc.id+"/"+tc.name, func(t *testing.T) {
			e := newEnv(t, tc.f)
			if r := e.s.run(ctx, []checks.Check{e.s.byID[tc.id]})[0]; r.Status != checks.Fail {
				t.Fatalf("fixture must fail first: %s %s", r.Status, r.Evidence)
			}
			before := e.tree()

			dry, err := e.s.Fix(ctx, tc.id, true)
			must(t, err)
			if dry.Diff.Empty() || dry.Diff.Text == "" || dry.Fix != nil {
				t.Fatalf("dry run must show a diff and apply nothing: %+v", dry)
			}
			eqTree(t, before, e.tree())
			for _, c := range tc.calls {
				if e.fx.Called(c) {
					t.Fatalf("dry run executed %q", c)
				}
			}
			if len(e.sets) > 0 {
				t.Fatal("dry run called safe-apply")
			}

			res, err := e.s.Fix(ctx, tc.id, false)
			must(t, err)
			if res.Fix == nil || res.Verify == nil || res.Fix.BackupPath != BackupRoot+res.Fix.ID {
				t.Fatalf("fix not recorded: %+v", res)
			}
			if tc.pass && res.Verify.Status != checks.Pass {
				t.Fatalf("verification: %s %s", res.Verify.Status, res.Verify.Evidence)
			}
			if !strings.HasPrefix(e.read(res.Fix.BackupPath+"/manifest.json"), "{") {
				t.Fatal("manifest missing")
			}
			e.called(tc.calls...)
			for p, sub := range tc.files {
				if !strings.Contains(e.read(p), sub) {
					t.Errorf("%s missing %q:\n%s", p, sub, e.read(p))
				}
			}
			if tc.ssh && (len(e.sets) != 1 || len(e.sets[0]) == 0) {
				t.Fatalf("safe-apply calls %v", e.sets)
			}
			if tc.id == "IPS-BRUTEFORCE" && (len(e.bf) != 1 || !e.bf[0]) {
				t.Fatalf("bruteforce flag %v", e.bf)
			}
			if fs, _ := e.s.ListFixes(ctx, 0); len(fs) != 1 || fs[0].CheckID != tc.id {
				t.Fatalf("fixes %+v", fs)
			}

			f, err := e.s.Revert(ctx, res.Fix.ID)
			must(t, err)
			if f.RevertedAt.IsZero() || f.Status != "reverted" {
				t.Fatalf("revert not recorded: %+v", f)
			}
			eqTree(t, before, e.tree())
			e.called(tc.undo...)
			if tc.ssh {
				if len(e.sets) != 2 {
					t.Fatalf("revert must safe-apply old values: %v", e.sets)
				}
				for k, v := range e.sets[1] {
					if v != tc.f.ssh[strings.ToLower(k)] && tc.f.ssh[strings.ToLower(k)] != "" {
						t.Errorf("revert %s=%s, want %s", k, v, tc.f.ssh[strings.ToLower(k)])
					}
				}
			}
			if tc.id == "IPS-BRUTEFORCE" && (len(e.bf) != 2 || e.bf[1]) {
				t.Fatalf("bruteforce flag after revert %v", e.bf)
			}
			if _, err := e.s.Revert(ctx, res.Fix.ID); err == nil {
				t.Fatal("second revert must fail")
			}
			covered[tc.id] = true
		})
	}
	for _, c := range checks.All(&checks.Env{}) {
		if c.Info().AutoFix != checks.FixReport && !covered[c.ID()] {
			t.Errorf("%s: fixable check without fix/revert test", c.ID())
		}
	}
}

// two sysctl fixes share the drop-in; reverting one keeps the other's keys.
func TestSysctlSharedFileRevert(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, fixture{files: map[string]string{"/proc/sys/net/ipv4/tcp_syncookies": "0\n",
		"/proc/sys/kernel/randomize_va_space": "0\n"}})
	a, err := e.s.Fix(ctx, "SYS-SYNCOOKIES", false)
	must(t, err)
	_, err = e.s.Fix(ctx, "SYS-ASLR", false)
	must(t, err)
	got := e.read(checks.SysctlFile)
	if !strings.Contains(got, "net.ipv4.tcp_syncookies = 1") || !strings.Contains(got, "kernel.randomize_va_space = 2") {
		t.Fatalf("drop-in: %s", got)
	}
	_, err = e.s.Revert(ctx, a.Fix.ID)
	must(t, err)
	got = e.read(checks.SysctlFile)
	if strings.Contains(got, "tcp_syncookies") || !strings.Contains(got, "kernel.randomize_va_space = 2") {
		t.Fatalf("after revert: %s", got)
	}
	e.called("sysctl -w net.ipv4.tcp_syncookies=0")
}

func TestScoreAndGrade(t *testing.T) {
	r := func(st, sev string) checks.Result { return checks.Result{Status: st, Severity: sev} }
	cases := []struct {
		rs    []checks.Result
		score float64
		grade string
	}{
		{nil, 100, "A"},
		{[]checks.Result{r("pass", "critical"), r("fail", "low")}, 90.9, "A"},
		{[]checks.Result{r("pass", "high"), r("fail", "medium"), r("na", "critical"), r("ignored", "critical")}, 62.5, "C"},
		{[]checks.Result{r("pass", "medium"), r("fail", "high"), r("error", "critical")}, 37.5, "D"},
		{[]checks.Result{r("pass", "critical"), r("pass", "high"), r("fail", "high")}, 75, "B"},
	}
	for _, c := range cases {
		s, g := Score(c.rs)
		if s != c.score || g != c.grade {
			t.Errorf("%v: got %.1f %s, want %.1f %s", c.rs, s, g, c.score, c.grade)
		}
	}
	if Grade(89.9) != "B" || Grade(59.9) != "D" || Grade(60) != "C" {
		t.Fatal("grade thresholds")
	}
}

func TestScanIgnoreAndDrift(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{ServerName: "web-01", Harden: config.Harden{Ignore: []config.Ignore{
		{ID: "SSH-PORT-NONDEFAULT", Reason: "provider console"}}}}
	e := newEnv(t, fixture{cfg: cfg, files: map[string]string{"/etc/login.defs": "PASS_MAX_DAYS 90\n"}})

	sc, err := e.s.Scan(ctx)
	must(t, err)
	if sc.FinishedAt.Sub(sc.StartedAt) > ScanBudget {
		t.Fatal("scan exceeded budget")
	}
	got := map[string]checks.Result{}
	for _, r := range Results(sc) {
		got[r.CheckID] = r
	}
	if len(got) != len(e.s.list) || got["ACC-PASS-AGING"].Status != checks.Pass || got["ACC-PASS-AGING"].Rationale == "" {
		t.Fatalf("results: %d %+v", len(got), got["ACC-PASS-AGING"])
	}
	if s, g := Score(Results(sc)); s != sc.Score || g != sc.Grade {
		t.Fatal("stored score mismatch")
	}
	latest, err := e.s.GetScan(ctx, "latest")
	if err != nil || latest.ID != sc.ID {
		t.Fatalf("latest: %v %v", latest.ID, err)
	}

	// mandatory reason; ignored checks are reported as ignored
	if _, err := e.s.Ignore(ctx, "MAL-CRONTAB", "  "); err == nil {
		t.Fatal("empty reason accepted")
	}
	if _, err := e.s.Ignore(ctx, "NOPE", "x"); !errors.Is(err, ErrUnknownCheck) {
		t.Fatalf("unknown check: %v", err)
	}
	_, err = e.s.Ignore(ctx, "MAL-ROOTKIT-SCANNER", "accepted risk")
	must(t, err)
	if err := e.s.Unignore(ctx, "SSH-PORT-NONDEFAULT"); err == nil || !strings.Contains(err.Error(), "config.yaml") {
		t.Fatalf("config ignore must not be removable via API: %v", err)
	}

	// drift: ACC-PASS-AGING passed, now fails
	must(t, os.WriteFile(filepath.Join(e.root, "etc/login.defs"), []byte("PASS_MAX_DAYS 99999\n"), 0o644))
	sc2, err := e.s.Scan(ctx)
	must(t, err)
	st := map[string]checks.Result{}
	for _, r := range Results(sc2) {
		st[r.CheckID] = r
	}
	if st["MAL-ROOTKIT-SCANNER"].Status != checks.Ignored || st["MAL-ROOTKIT-SCANNER"].IgnoreReason != "accepted risk" {
		t.Fatalf("ignore not applied: %+v", st["MAL-ROOTKIT-SCANNER"])
	}
	if len(e.fired) != 1 || e.fired[0].Rule != "hardening_drift" || e.fired[0].Labels["check"] != "ACC-PASS-AGING" ||
		e.fired[0].Severity != "warning" || e.fired[0].Resolve {
		t.Fatalf("drift alerts: %+v", e.fired)
	}
	must(t, os.WriteFile(filepath.Join(e.root, "etc/login.defs"), []byte("PASS_MAX_DAYS 90\n"), 0o644))
	_, err = e.s.Scan(ctx)
	must(t, err)
	if len(e.fired) != 2 || !e.fired[1].Resolve {
		t.Fatalf("drift resolve: %+v", e.fired)
	}

	must(t, e.s.Unignore(ctx, "MAL-ROOTKIT-SCANNER"))
	for _, c := range e.s.Checks(ctx) {
		if c.ID == "MAL-ROOTKIT-SCANNER" && c.Ignored || c.ID == "SSH-PORT-NONDEFAULT" && !c.Ignored {
			t.Fatalf("catalog ignore state: %+v", c)
		}
	}
}

type slowCheck struct{ checks.Check }

func (slowCheck) ID() string { return "SLOW" }
func (slowCheck) Run(ctx context.Context) checks.Result {
	<-ctx.Done()
	time.Sleep(50 * time.Millisecond)
	return checks.Result{Status: checks.Pass}
}

func TestScanBudget(t *testing.T) {
	e := newEnv(t, fixture{})
	old := ScanBudget
	ScanBudget = 100 * time.Millisecond
	defer func() { ScanBudget = old }()
	c := e.s.byID["MAL-CRONTAB"]
	start := time.Now()
	rs := e.s.run(context.Background(), []checks.Check{slowCheck{c}, c})
	if time.Since(start) > time.Second || rs[0].Status != checks.Error || rs[0].CheckID != "SLOW" || rs[1].Status != checks.Pass {
		t.Fatalf("budget not enforced: %+v", rs)
	}
}

func TestFixAll(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, fixture{files: map[string]string{"/etc/shadow": "x", "/etc/passwd": "root:x:0:0::/root:/bin/sh\n",
		"/usr/sbin/ufw": "", "/proc/sys/kernel/dmesg_restrict": "0\n"},
		modes: map[string]os.FileMode{"/etc/shadow": 0o666, "/etc/passwd": 0o666},
		out:   map[string]string{"ufw status verbose": "Status: inactive\n"}})
	if _, err := e.s.FixAll(ctx, "urgent", true); err == nil {
		t.Fatal("bad severity accepted")
	}
	rs, err := e.s.FixAll(ctx, "high", true)
	must(t, err)
	ids := map[string]FixResult{}
	for _, r := range rs {
		ids[r.CheckID] = r
		if checks.Rank(e.s.byID[r.CheckID].Info().Severity) < checks.Rank(checks.High) {
			t.Errorf("%s below severity filter", r.CheckID)
		}
	}
	if ids["FILE-SHADOW-PERMS"].Diff.Empty() || ids["FW-ACTIVE"].Skipped == "" || ids["FILE-PASSWD-PERMS"].CheckID != "" {
		t.Fatalf("fix-all dry run: %+v", rs)
	}
	if e.fx.Called("ufw allow") {
		t.Fatal("firewall must not be changed by fix --all")
	}
	_, err = e.s.FixAll(ctx, "", false)
	must(t, err)
	if m, _ := os.Stat(filepath.Join(e.root, "etc/shadow")); m.Mode().Perm() != 0o640 {
		t.Fatalf("shadow mode %v", m.Mode())
	}
	if !strings.Contains(e.read(checks.SysctlFile), "kernel.dmesg_restrict = 1") {
		t.Fatal("low severity fix not applied with no filter")
	}
}

func TestReports(t *testing.T) {
	e := newEnv(t, fixture{})
	sc, err := e.s.Scan(context.Background())
	must(t, err)
	b, ct, err := e.s.Render(sc, "json")
	must(t, err)
	var r Report
	must(t, json.Unmarshal(b, &r))
	if ct != "application/json" || r.Server != "web-01" || len(r.Results) == 0 || r.Grade == "" {
		t.Fatalf("json report: %s", b)
	}
	md, _, err := e.s.Render(sc, "md")
	must(t, err)
	for _, s := range []string{"# Hardening report: web-01", "| Status | Severity | Check | CIS |", "## Failed checks",
		"- Remediation: ", "(CIS 3.5.1.3)", "(grade **"} {
		if !strings.Contains(string(md), s) {
			t.Errorf("markdown missing %q", s)
		}
	}
	pdf, ct, err := e.s.Render(sc, "pdf")
	must(t, err)
	if ct != "application/pdf" || len(pdf) < 1000 || !strings.HasPrefix(string(pdf), "%PDF") {
		t.Fatalf("pdf: %d bytes %q", len(pdf), pdf[:min(8, len(pdf))])
	}
	if _, _, err := e.s.Render(sc, "doc"); err == nil {
		t.Fatal("unknown format accepted")
	}
}

func TestPacks(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "site.yaml"), []byte(`checks:
  - id: CUSTOM-IP-FORWARD
    type: sysctl
    severity: medium
    title: IP forwarding off
    rationale: not a router
    remediation: set net.ipv4.ip_forward = 0
    key: net.ipv4.ip_forward
    value: "0"
    fix: true
  - id: CUSTOM-MOTD-MODE
    type: file_mode
    severity: low
    title: motd not writable
    path: /etc/motd
    mode: "0644"
    fix: true
  - id: CUSTOM-BANNER
    type: file_contains
    severity: low
    title: legal banner
    path: /etc/issue.net
    pattern: Authorized
  - id: CUSTOM-NO-TELNET
    type: file_not_contains
    severity: high
    title: no telnet in inetd
    path: /etc/inetd.conf
    pattern: telnet
  - id: CUSTOM-NGINX
    type: service_active
    severity: high
    title: nginx running
    unit: nginx
  - id: CUSTOM-KERNEL
    type: command_output
    severity: low
    title: kernel 6.x
    command: [uname, -r]
    pattern: ^6\.
`), 0o644))
	cfg := &config.Config{ServerName: "web-01", Harden: config.Harden{Packs: []string{dir}}}
	e := newEnv(t, fixture{cfg: cfg, files: map[string]string{"/proc/sys/net/ipv4/ip_forward": "1\n", "/etc/motd": "hi",
		"/etc/issue.net": "Authorized use only\n"}, modes: map[string]os.FileMode{"/etc/motd": 0o666},
		out: map[string]string{"systemctl is-active nginx": "active\n", "uname -r": "6.8.0-45-generic\n"}})
	want := map[string]string{"CUSTOM-IP-FORWARD": "fail", "CUSTOM-MOTD-MODE": "fail", "CUSTOM-BANNER": "pass",
		"CUSTOM-NO-TELNET": "pass", "CUSTOM-NGINX": "pass", "CUSTOM-KERNEL": "pass"}
	var cs []checks.Check
	for id := range want {
		if e.s.byID[id] == nil {
			t.Fatalf("pack check %s not loaded", id)
		}
		cs = append(cs, e.s.byID[id])
	}
	for _, r := range e.s.run(context.Background(), cs) {
		if r.Status != want[r.CheckID] || r.Category != "custom" {
			t.Errorf("%s: %s (%s)", r.CheckID, r.Status, r.Evidence)
		}
	}
	res, err := e.s.Fix(context.Background(), "CUSTOM-IP-FORWARD", false)
	must(t, err)
	e.called("sysctl -w net.ipv4.ip_forward=0")
	_, err = e.s.Revert(context.Background(), res.Fix.ID)
	must(t, err)
	e.called("sysctl -w net.ipv4.ip_forward=1")
	if _, err := e.s.Fix(context.Background(), "CUSTOM-BANNER", true); err == nil {
		t.Fatal("pack check without fix must be report-only")
	}

	// invalid packs: non-allowlisted command, duplicate id
	for _, y := range []string{
		"checks:\n  - {id: X1, type: command_output, severity: low, title: t, command: [bash, -c, id], pattern: x}\n",
		"checks:\n  - {id: SSH-X11, type: sysctl, severity: low, title: t, key: a.b, value: '1'}\n",
		"checks:\n  - {id: X2, type: nope, severity: low, title: t}\n",
	} {
		d := t.TempDir()
		must(t, os.WriteFile(filepath.Join(d, "bad.yml"), []byte(y), 0o644))
		seen := map[string]bool{"SSH-X11": true}
		if _, err := checks.LoadPacks(e.s.env, []string{d}, seen); err == nil {
			t.Errorf("pack accepted: %s", y)
		}
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	e := newEnv(t, fixture{cfg: &config.Config{Harden: config.Harden{Schedule: "not a cron"}}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.s.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
}

// TestRealHostScan is a read-only smoke scan of this machine: SK_REAL_SCAN=1 go test -run RealHost -v.
func TestRealHostScan(t *testing.T) {
	if os.Getenv("SK_REAL_SCAN") == "" {
		t.Skip("set SK_REAL_SCAN=1")
	}
	st, err := db.Open(":memory:")
	must(t, err)
	s := New(Deps{Cfg: &config.Config{ServerName: "this-host"}, DB: st, Ex: executor.Local{}})
	start := time.Now()
	sc, err := s.Scan(context.Background())
	must(t, err)
	md, _, _ := s.Render(sc, "md")
	t.Logf("%s\nscan took %s, score %.1f grade %s", md, time.Since(start), sc.Score, sc.Grade)
	if time.Since(start) > 30*time.Second {
		t.Fatal("scan exceeded 30 s")
	}
}
