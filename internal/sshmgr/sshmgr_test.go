package sshmgr

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tb12as/kurogane/internal/audit"
	"github.com/tb12as/kurogane/internal/config"
	"github.com/tb12as/kurogane/internal/db"
	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/firewall"
	"github.com/tb12as/kurogane/internal/hostfs"
	"github.com/tb12as/kurogane/internal/store"
	"golang.org/x/crypto/ssh"
)

func pubLine(t *testing.T, comment string) string {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))) + " " + comment
}

func write(t *testing.T, root, p, s string) {
	t.Helper()
	full := filepath.Join(root, p)
	os.MkdirAll(filepath.Dir(full), 0o755)
	if err := os.WriteFile(full, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, root, p string) string {
	b, _ := os.ReadFile(filepath.Join(root, p))
	return string(b)
}

type env struct {
	m    *Manager
	ex   *executor.Fake
	root string
	db   *db.SQLite
}

func setup(t *testing.T, sshdConfig string, withKey bool) *env {
	t.Helper()
	root := t.TempDir()
	old := hostfs.Root
	hostfs.Root = root
	t.Cleanup(func() { hostfs.Root = old })
	write(t, root, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndeploy:x:1000:1000::/home/deploy:/bin/bash\n"+
		"nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n")
	write(t, root, "/etc/group", "root:x:0:\nsudo:x:27:deploy\ndeploy:x:1000:\n")
	write(t, root, "/etc/shadow", "root:$6$abc:19000::::::\ndeploy:$6$def:19000::::::\n")
	write(t, root, "/etc/os-release", "ID=ubuntu\nVERSION_ID=24.04\n")
	write(t, root, "/etc/ssh/sshd_config", sshdConfig)
	if withKey {
		write(t, root, "/home/deploy/.ssh/authorized_keys", pubLine(t, "budi@laptop")+"\n")
	}
	d, err := db.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close(); d.Close() })
	ex := executor.NewFake()
	ex.Errors["systemctl is-active --quiet fail2ban"] = &executor.RunError{Cmd: "systemctl", Stderr: "inactive"}
	cfg := &config.Config{}
	cfg.SSH.ConfigPath = "/etc/ssh/sshd_config"
	cfg.SSH.RollbackTimeout = 120 * time.Second
	cfg.SSH.Bruteforce = config.Bruteforce{Enabled: true, MaxFailures: 5, Window: 10 * time.Minute, BanFor: time.Hour,
		Allowlist: []string{"203.0.113.10/32"}}
	fw := firewall.New(ex)
	m := New(Deps{Cfg: cfg, DB: d, Store: st, Ex: ex, Audit: &audit.Logger{Store: d}, Firewall: fw})
	return &env{m: m, ex: ex, root: root, db: d}
}

func TestAuthorizedKeysParsing(t *testing.T) {
	k1 := pubLine(t, "with options")
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rp, _ := ssh.NewPublicKey(&rk.PublicKey)
	weak := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(rp)))
	src := "# comment\n\n" + `command="echo hi, there",no-pty,from="10.0.0.0/8" ` + k1 + "\ngarbage line\n" + weak + "\n"
	ks := parseAuthorizedKeys([]byte(src))
	if len(ks) != 2 {
		t.Fatalf("want 2 keys, got %d", len(ks))
	}
	if len(ks[0].options) != 3 || ks[0].options[0] != `command="echo hi, there"` || ks[0].comment != "with options" {
		t.Fatalf("options: %q comment %q", ks[0].options, ks[0].comment)
	}
	if Bits(ks[1].pub) != 2048 || keyType(ks[1].pub) != "rsa" {
		t.Fatal("rsa bits")
	}
	f := weakFlags(Key{SSHKey: db.SSHKey{Type: "rsa", Bits: 2048}}, true)
	if strings.Join(f, ",") != "weak-rsa,duplicate,no-label" {
		t.Fatal(f)
	}
	nb, n := dropKey([]byte(src), ssh.FingerprintSHA256(ks[1].pub))
	if n != 1 || !strings.Contains(string(nb), "garbage line") || !strings.Contains(string(nb), "# comment") {
		t.Fatalf("dropKey must keep unrelated lines: %q", nb)
	}
}

func TestSSHDConfigParsing(t *testing.T) {
	e := setup(t, "Include /etc/ssh/sshd_config.d/*.conf\nport 2222\nPasswordAuthentication=yes\n"+
		"PasswordAuthentication no\nMatch User deploy\n  X11Forwarding yes\n", false)
	write(t, e.root, "/etc/ssh/sshd_config.d/50-cloud-init.conf", "PermitRootLogin \"no\"\n")
	s, err := e.m.Settings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s["port"] != "2222" || s["passwordauthentication"] != "yes" || s["permitrootlogin"] != "no" ||
		s["x11forwarding"] != "no" {
		t.Fatalf("effective settings wrong: %v", s)
	}
}

func TestKeysAddListRemove(t *testing.T) {
	e := setup(t, "PubkeyAuthentication yes\n", true)
	ctx := context.Background()
	line := pubLine(t, "")
	k, err := e.m.AddKey(ctx, "deploy", line, "budi laptop", time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, e.root, "/home/deploy/.ssh/authorized_keys"), "budi laptop") {
		t.Fatal("key not written")
	}
	if _, err := e.m.AddKey(ctx, "ghost", line, "", time.Time{}); err == nil {
		t.Fatal("unknown user must fail")
	}
	ks, _ := e.m.Keys(ctx, "deploy")
	if len(ks) != 2 {
		t.Fatalf("want 2 keys, got %d", len(ks))
	}
	if n, err := e.m.RemoveKey(ctx, k.Fingerprint, ""); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if strings.Contains(read(t, e.root, "/home/deploy/.ssh/authorized_keys"), "budi laptop") {
		t.Fatal("key not removed")
	}
	// expiry sweeper removes expired keys
	k2, _ := e.m.AddKey(ctx, "deploy", pubLine(t, "tmp"), "tmp", time.Now().Add(time.Hour))
	e.m.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	e.m.expire(ctx)
	if strings.Contains(read(t, e.root, "/home/deploy/.ssh/authorized_keys"), k2.PublicKey) {
		t.Fatal("expired key still present")
	}
}

func TestSafeApplyConfirm(t *testing.T) {
	e := setup(t, "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n", true)
	write(t, e.root, "/etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
	ctx := context.Background()
	plan, err := e.m.Plan(ctx, map[string]string{"passwordauthentication": "no"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Mode != "drop-in" || !strings.Contains(plan.Diff, "+PasswordAuthentication no") ||
		!strings.Contains(plan.Diff, "disabled by serverkeeper") {
		t.Fatalf("plan: %+v\n%s", plan, plan.Diff)
	}
	ch, err := e.m.SafeApplyFrom(ctx, map[string]string{"PasswordAuthentication": "no"}, time.Minute, "1.2.3.4 5 6.7.8.9 22")
	if err != nil {
		t.Fatal(err)
	}
	if !e.ex.Called("sshd -t -f /etc/ssh/sshd_config.sk-candidate") || !e.ex.Called("systemctl reload ssh") {
		t.Fatalf("calls: %v", e.ex.Calls)
	}
	if !strings.Contains(read(t, e.root, DropIn), "PasswordAuthentication no") {
		t.Fatal("drop-in not written")
	}
	if _, err := e.m.SafeApply(ctx, map[string]string{"MaxAuthTries": "3"}, time.Minute); err == nil {
		t.Fatal("second change while pending must fail")
	}
	if _, err := e.m.Confirm(ctx, "1.2.3.4 5 6.7.8.9 22"); err == nil {
		t.Fatal("confirm from the applying session must fail")
	}
	if _, err := e.m.Confirm(ctx, ""); err != nil {
		t.Fatal(err)
	}
	cs, _ := e.db.ListSSHChanges(ctx, 10)
	if len(cs) != 1 || cs[0].ID != ch.ID || cs[0].Status != "confirmed" || cs[0].OldValue != "yes" {
		t.Fatalf("change history: %+v", cs)
	}
}

// PRD §12 lockout test: a change with no confirmation must roll back within the timeout.
func TestLockoutRollback(t *testing.T) {
	orig := "PasswordAuthentication yes\nMaxAuthTries 6\n"
	e := setup(t, orig, true)
	ctx := context.Background()
	if _, err := e.m.SafeApply(ctx, map[string]string{"MaxAuthTries": "3"}, 200*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, e.root, "/etc/ssh/sshd_config"), "MaxAuthTries 3") {
		t.Fatal("in-place change not applied")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := e.m.pending(); !ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := read(t, e.root, "/etc/ssh/sshd_config"); got != orig {
		t.Fatalf("not rolled back: %q", got)
	}
	cs, _ := e.db.ListSSHChanges(ctx, 10)
	if len(cs) != 1 || cs[0].Status != "rolled_back" {
		t.Fatalf("status: %+v", cs)
	}
	reloads := 0
	for _, c := range e.ex.Calls {
		if c == "systemctl reload ssh" {
			reloads++
		}
	}
	if reloads != 2 {
		t.Fatalf("want reload on apply and rollback, got %d", reloads)
	}
}

// a change pending when the agent stopped is rolled back on start once its deadline passed
func TestRollbackResumeAfterRestart(t *testing.T) {
	orig := "MaxAuthTries 6\n"
	e := setup(t, orig, true)
	ctx := context.Background()
	if _, err := e.m.SafeApply(ctx, map[string]string{"MaxAuthTries": "3"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	m2 := New(e.m.d)
	m2.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	m2.resume(ctx)
	if got := read(t, e.root, "/etc/ssh/sshd_config"); got != orig {
		t.Fatalf("not rolled back on resume: %q", got)
	}
}

func TestSSH4Refusals(t *testing.T) {
	e := setup(t, "PasswordAuthentication yes\nKbdInteractiveAuthentication no\nPermitRootLogin yes\n", false)
	ctx := context.Background()
	if _, err := e.m.SafeApply(ctx, map[string]string{"PasswordAuthentication": "no"}, time.Minute); err == nil ||
		!strings.Contains(err.Error(), "no allowed user has a working SSH key") {
		t.Fatalf("want SSH-4 refusal, got %v", err)
	}
	// only root has a key and deploy has no key: disabling root login must be refused when password auth is off
	e2 := setup(t, "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n", false)
	write(t, e2.root, "/root/.ssh/authorized_keys", pubLine(t, "root")+"\n")
	if _, err := e2.m.SafeApply(ctx, map[string]string{"PermitRootLogin": "no"}, time.Minute); err == nil {
		t.Fatal("disabling root login with no other admin login must be refused")
	}
	// AllowUsers excluding everyone with a key is refused
	e3 := setup(t, "PasswordAuthentication no\nKbdInteractiveAuthentication no\n", true)
	if _, err := e3.m.SafeApply(ctx, map[string]string{"AllowUsers": "alice"}, time.Minute); err == nil {
		t.Fatal("AllowUsers lockout must be refused")
	}
	if _, err := e3.m.SafeApply(ctx, map[string]string{"AllowUsers": "deploy"}, time.Minute); err != nil {
		t.Fatal(err)
	}
}

func TestValidationErrorMapsLine(t *testing.T) {
	e := setup(t, "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n", true)
	e.ex.Errors["sshd -t -f /etc/ssh/sshd_config.sk-candidate"] = &executor.RunError{Cmd: "sshd", Stderr: "/etc/ssh/sshd_config.sk-candidate line 1: Bad configuration option"}
	_, err := e.m.SafeApply(context.Background(), map[string]string{"MaxAuthTries": "3"}, time.Minute)
	if err == nil || !strings.Contains(err.Error(), "rejected the new config: "+DropIn+" line 2: Bad") {
		t.Fatalf("want error mapped to original file line, got %v", err)
	}
	if read(t, e.root, DropIn) != "" {
		t.Fatal("nothing may be written when validation fails")
	}
}

func TestAuthLogAndBruteforce(t *testing.T) {
	now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.Local)
	l1 := "Nov  3 09:59:01 web-01 sshd[123]: Accepted publickey for deploy from 198.51.100.4 port 51234 ssh2: ED25519 SHA256:abc"
	l2 := "2026-11-03T09:59:02.123456+07:00 web-01 sshd[124]: Failed password for invalid user admin from 192.0.2.9 port 4444 ssh2"
	l3 := "Nov  3 09:59:03 web-01 sshd[125]: Invalid user test from 192.0.2.9 port 4445"
	a, ok := parseAuthLine(l1, now)
	if !ok || !a.Success || a.User != "deploy" || a.Fingerprint != "SHA256:abc" || a.TS.Hour() != 9 {
		t.Fatalf("%+v", a)
	}
	b, ok := parseAuthLine(l2, now)
	if !ok || b.Success || !b.Invalid || b.User != "admin" || b.IP != "192.0.2.9" {
		t.Fatalf("%+v", b)
	}
	if c, ok := parseAuthLine(l3, now); !ok || c.User != "test" {
		t.Fatalf("%+v", c)
	}

	e := setup(t, "PasswordAuthentication yes\n", true)
	e.m.now = func() time.Time { return now }
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		e.m.onFailure(ctx, Login{IP: "192.0.2.9", User: "root", TS: now})
	}
	if len(e.m.d.Firewall.Bans()) != 0 {
		t.Fatal("banned before max_failures")
	}
	e.m.onFailure(ctx, Login{IP: "192.0.2.9", User: "root", TS: now})
	if len(e.m.d.Firewall.Bans()) != 1 {
		t.Fatalf("want ban after 5 failures, calls %v", e.ex.Calls)
	}
	for i := 0; i < 6; i++ {
		e.m.onFailure(ctx, Login{IP: "203.0.113.10", User: "root", TS: now})
	}
	if len(e.m.d.Firewall.Bans()) != 1 {
		t.Fatal("allowlisted IP must never be banned")
	}
}

func TestUtmp(t *testing.T) {
	rec := make([]byte, utmpSize)
	rec[0] = 7
	rec[4] = 0x39
	copy(rec[8:], "pts/0")
	copy(rec[44:], "deploy")
	copy(rec[76:], "198.51.100.4")
	ss := parseUtmp(append(make([]byte, utmpSize), rec...))
	if len(ss) != 1 || ss[0].User != "deploy" || ss[0].TTY != "pts/0" || ss[0].PID != 0x39 || ss[0].From != "198.51.100.4" {
		t.Fatalf("%+v", ss)
	}
}

func TestCASign(t *testing.T) {
	e := setup(t, "PasswordAuthentication no\n", true)
	ctx := context.Background()
	e.m.d.Cfg.SSH.CA.MaxTTL = 24 * time.Hour
	if _, err := e.m.InitCA(ctx, time.Minute); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, e.root, "/etc/ssh/sshd_config"), "TrustedUserCAKeys "+CAPubPath) {
		t.Fatal("TrustedUserCAKeys not applied")
	}
	if _, err := e.m.Sign(ctx, pubLine(t, "x"), []string{"deploy"}, 48*time.Hour, ""); err == nil {
		t.Fatal("ttl above max must fail")
	}
	c, err := e.m.Sign(ctx, pubLine(t, "x"), []string{"deploy"}, 8*time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c))
	if err != nil {
		t.Fatal(err)
	}
	cert := pk.(*ssh.Certificate)
	caPub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(read(t, e.root, CAPubPath)))
	checker := ssh.CertChecker{IsUserAuthority: func(a ssh.PublicKey) bool {
		return string(a.Marshal()) == string(caPub.Marshal())
	}}
	if err := checker.CheckCert("deploy", cert); err != nil {
		t.Fatal(err)
	}
}

// RHEL 9: crypto-policies (outside /etc/ssh) sets Ciphers before our drop-in; we must not edit it
func TestPlanShadowedOutsideEtcSSH(t *testing.T) {
	e := setup(t, "# rhel\nInclude /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n", true)
	write(t, e.root, "/etc/ssh/sshd_config.d/50-redhat.conf", "Include /etc/crypto-policies/back-ends/opensshserver.config\n")
	write(t, e.root, "/etc/crypto-policies/back-ends/opensshserver.config", "Ciphers aes256-cbc,aes128-ctr\n")
	p, err := e.m.Plan(context.Background(), map[string]string{"Ciphers": ModernCiphers})
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != "in-place" || p.files["/etc/crypto-policies/back-ends/opensshserver.config"] != nil {
		t.Fatalf("plan must not touch crypto-policies: %+v", p.Mode)
	}
	main := string(p.files["/etc/ssh/sshd_config"])
	if strings.Index(main, "Ciphers "+ModernCiphers) > strings.Index(main, "\nInclude ") {
		t.Fatalf("settings must precede Include:\n%s", main)
	}
	if p.newEff["ciphers"] != ModernCiphers {
		t.Fatalf("not effective: %v", p.newEff["ciphers"])
	}
}

func TestLogindSessions(t *testing.T) {
	e := setup(t, "PasswordAuthentication yes\n", true)
	e.ex.Outputs["loginctl list-sessions --no-legend --no-pager"] = "  7 1000 deploy -  812 user  pts/0 no -\n  8 1000 deploy - 900 manager - no -\n"
	e.ex.Outputs["loginctl show-session 7 -p Name -p TTY -p RemoteHost -p Leader -p Timestamp -p Class"] =
		"Name=deploy\nTTY=pts/0\nRemoteHost=198.51.100.4\nLeader=812\nTimestamp=Tue 2026-11-03 08:09:46 UTC\nClass=user\n"
	e.ex.Outputs["loginctl show-session 8 -p Name -p TTY -p RemoteHost -p Leader -p Timestamp -p Class"] =
		"Name=deploy\nLeader=900\nClass=manager\n"
	ss, err := e.m.Sessions(context.Background())
	if err != nil || len(ss) != 1 || ss[0].ID != "7" || ss[0].From != "198.51.100.4" || ss[0].PID != 812 || ss[0].Started.IsZero() {
		t.Fatalf("%v %+v", err, ss)
	}
	if _, err := e.m.KillSession(context.Background(), 812); err != nil || !e.ex.Called("loginctl terminate-session 7") {
		t.Fatalf("kill: %v %v", err, e.ex.Calls)
	}
}
