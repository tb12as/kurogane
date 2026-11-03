//go:build integration

package sshmgr

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tb12as/serverman/internal/audit"
	"github.com/tb12as/serverman/internal/config"
	"github.com/tb12as/serverman/internal/db"
	"github.com/tb12as/serverman/internal/executor"
	"github.com/tb12as/serverman/internal/hostfs"
	"github.com/tb12as/serverman/internal/store"
)

// containers have no systemd: this shim turns `systemctl reload ssh|sshd` into SIGHUP for the real sshd
const systemctlShim = `#!/bin/sh
case "$1" in
  reload) kill -HUP "$(cat /run/sshd.pid 2>/dev/null || cat /var/run/sshd.pid)" ;;
  is-active) exit 3 ;;
  *) exit 0 ;;
esac
`

func sshdT(t *testing.T, key string) string {
	out, err := exec.Command("sshd", "-T").Output()
	if err != nil {
		t.Fatalf("sshd -T: %v", err)
	}
	for _, l := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(l, " "); ok && k == key {
			return v
		}
	}
	return ""
}

// PRD §12 lockout test against a real sshd: an unconfirmed change must roll back within the timeout.
func TestIntegrationLockoutRollback(t *testing.T) {
	if os.Getenv("SK_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("set SK_INTEGRATION=1 and run as root inside a disposable container")
	}
	hostfs.Root = "/"
	if err := os.WriteFile("/usr/local/sbin/systemctl", []byte(systemctlShim), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = exec.Command("useradd", "-m", "-s", "/bin/sh", "deploy").Run()
	os.MkdirAll("/home/deploy/.ssh", 0o700)
	if err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", "/tmp/deploy_key").Run(); err != nil {
		t.Fatal(err)
	}
	pub, _ := os.ReadFile("/tmp/deploy_key.pub")
	os.WriteFile("/home/deploy/.ssh/authorized_keys", pub, 0o600)
	if out, err := exec.Command("/usr/sbin/sshd").CombinedOutput(); err != nil {
		t.Fatalf("start sshd: %v %s", err, out)
	}
	defer exec.Command("pkill", "-x", "sshd").Run()

	orig, _ := os.ReadFile("/etc/ssh/sshd_config")
	was := sshdT(t, "maxauthtries")
	d, _ := db.Open(filepath.Join(t.TempDir(), "m.db"))
	st, _ := store.Open(filepath.Join(t.TempDir(), "a.db"))
	defer st.Close()
	defer d.Close()
	cfg := &config.Config{}
	cfg.SSH.ConfigPath = "/etc/ssh/sshd_config"
	m := New(Deps{Cfg: cfg, DB: d, Store: st, Ex: executor.Local{}, Audit: &audit.Logger{Store: d}})
	ctx := audit.WithActor(context.Background(), "integration", "")

	if _, err := m.SafeApply(ctx, map[string]string{"MaxAuthTries": "2"}, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := sshdT(t, "maxauthtries"); got != "2" {
		t.Fatalf("change not effective: maxauthtries %s", got)
	}
	time.Sleep(4 * time.Second)
	if got := sshdT(t, "maxauthtries"); got != was {
		t.Fatalf("not rolled back: maxauthtries %s, want %s", got, was)
	}
	now, _ := os.ReadFile("/etc/ssh/sshd_config")
	if string(now) != string(orig) {
		t.Fatal("sshd_config not restored byte-for-byte")
	}
	if _, err := os.Stat(DropIn); err == nil && !mainIncludesDropIn(orig) {
		t.Fatal("stray drop-in left behind")
	}

	// confirmed change stays; SSH-4 refuses disabling passwords when nobody has a key
	if _, err := m.SafeApply(ctx, map[string]string{"PasswordAuthentication": "no"}, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if sshdT(t, "passwordauthentication") != "no" {
		t.Fatal("confirmed change lost")
	}
}
