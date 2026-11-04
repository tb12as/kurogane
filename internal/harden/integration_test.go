//go:build integration

package harden

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/tb12as/kurogane/internal/audit"
	"github.com/tb12as/kurogane/internal/config"
	"github.com/tb12as/kurogane/internal/db"
	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/hostfs"
	"github.com/tb12as/kurogane/internal/sshmgr"
	"github.com/tb12as/kurogane/internal/store"
)

// containers have no systemd: `systemctl reload ssh|sshd` becomes SIGHUP for the real sshd
const shim = `#!/bin/sh
case "$1" in
  reload) kill -HUP "$(cat /run/sshd.pid 2>/dev/null || cat /var/run/sshd.pid)" ;;
  is-active) exit 3 ;;
  *) exit 0 ;;
esac
`

// sshSetup starts sshd and creates a sudo user with a key so SSH fixes pass the SSH-4 guard.
func sshSetup(t *testing.T) {
	if err := os.WriteFile("/usr/local/sbin/systemctl", []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}
	grp := "sudo"
	if hostfs.DetectDistro().Family == "rhel" {
		grp = "wheel"
	}
	_ = exec.Command("useradd", "-m", "-s", "/bin/sh", "-G", grp, "ops").Run()
	os.MkdirAll("/home/ops/.ssh", 0o700)
	_ = exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", "/tmp/ops_key").Run()
	pub, _ := os.ReadFile("/tmp/ops_key.pub")
	os.WriteFile("/home/ops/.ssh/authorized_keys", pub, 0o600)
	if out, err := exec.Command("/usr/sbin/sshd").CombinedOutput(); err != nil {
		t.Fatalf("start sshd: %v %s", err, out)
	}
	t.Cleanup(func() { exec.Command("pkill", "-x", "sshd").Run() })
}

// skipped: they need a firewall daemon, systemd-timedated or a full package upgrade, none of which exist in a
// CI container; they are covered by fixture tests.
var integrationSkip = map[string]bool{"FW-ACTIVE": true, "FW-DEFAULT-DENY": true, "UPD-PENDING-SECURITY": true,
	"TIME-NTP-SYNC": true, "IPS-BRUTEFORCE": true}

// Runs inside a disposable distro container as root (CI matrix, PRD §12): every check scans without error,
// and every failing fixable check is fixed and reverted with the real executor; revert must restore files.
func TestIntegrationScanFixRevert(t *testing.T) {
	if os.Getenv("KRGN_INTEGRATION") != "1" || os.Geteuid() != 0 {
		t.Skip("set KRGN_INTEGRATION=1 and run as root inside a disposable container")
	}
	hostfs.Root = "/"
	d, err := db.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	sshSetup(t)
	st, err := store.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg := &config.Config{ServerName: "it"}
	cfg.SSH.ConfigPath = "/etc/ssh/sshd_config"
	cfg.SSH.RollbackTimeout = time.Minute
	lg := &audit.Logger{Store: d}
	sm := sshmgr.New(sshmgr.Deps{Cfg: cfg, DB: d, Store: st, Ex: executor.Local{}, Audit: lg})
	s := New(Deps{Cfg: cfg, DB: d, Ex: executor.Local{}, Audit: lg, SSH: sm, ServerID: "local"})
	// the operator confirms SSH safe-apply changes from a new session; emulate that
	confirm := func() {
		if _, ok := sm.PendingChange(); ok {
			if _, err := sm.Confirm(context.Background(), ""); err != nil {
				t.Fatal(err)
			}
		}
	}
	ctx := audit.WithActor(context.Background(), "integration", "")
	start := time.Now()
	sc, err := s.Scan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > ScanBudget {
		t.Fatalf("scan took %s, budget %s (HD-1)", time.Since(start), ScanBudget)
	}
	t.Logf("%s: score %.1f grade %s", hostfs.DetectDistro().Name, sc.Score, sc.Grade)
	results := Results(sc)
	for _, r := range results {
		if string(r.Status) != "fail" || integrationSkip[r.CheckID] {
			continue
		}
		dry, err := s.Fix(ctx, r.CheckID, true)
		if err != nil || dry.Diff.Empty() {
			continue // report-only or not applicable here
		}
		// unprivileged containers cannot write /proc/sys (and privileged ones would change the host kernel)
		if len(dry.Diff.Sysctl) > 0 && os.Getenv("KRGN_INTEGRATION_NO_SYSCTL") == "1" {
			continue
		}
		before := map[string][]byte{}
		for _, f := range dry.Diff.Files {
			before[f.Path], _ = os.ReadFile(f.Path)
		}
		res, err := s.Fix(ctx, r.CheckID, false)
		if err != nil {
			t.Errorf("%s: fix failed: %v", r.CheckID, err)
			if res.Fix == nil {
				continue
			}
		}
		confirm()
		if res.Verify != nil && string(res.Verify.Status) != "pass" {
			t.Logf("%s: fix applied but check reports %s (%s)", r.CheckID, res.Verify.Status, res.Verify.Evidence)
		}
		if _, err := s.Revert(ctx, res.Fix.ID); err != nil {
			t.Errorf("%s: revert failed: %v", r.CheckID, err)
			continue
		}
		confirm()
		for p, b := range before {
			now, _ := os.ReadFile(p)
			if string(now) != string(b) {
				t.Errorf("%s: revert did not restore %s", r.CheckID, p)
			}
		}
	}
}
