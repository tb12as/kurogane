package executor

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tb12as/serverman/internal/hostfs"
)

func TestAllowlist(t *testing.T) {
	if err := Allowed("bash", []string{"-c", "id"}); err == nil {
		t.Fatal("bash must be denied")
	}
	if err := Allowed("systemctl", []string{"poweroff"}); err == nil {
		t.Fatal("systemctl poweroff must be denied")
	}
	if err := Allowed("systemctl", []string{"reload", "ssh"}); err != nil {
		t.Fatal(err)
	}
	if writable("/etc/../etc/shadow2") || writable("/home/bob/.bashrc") || !writable("/home/bob/.ssh/authorized_keys") {
		t.Fatal("path allowlist wrong")
	}
}

func TestUninstallAllowlist(t *testing.T) {
	ok := [][]string{
		append(append([]string{}, UninstallArgs...), "/usr/bin/serverkeeper", "uninstall", "--yes"),
		append(append([]string{}, UninstallArgs...), "/usr/local/bin/serverkeeper", "uninstall", "--yes", "--purge"),
	}
	for _, a := range ok {
		if err := Allowed("systemd-run", a); err != nil {
			t.Fatalf("%v denied: %v", a, err)
		}
	}
	bad := [][]string{
		append(append([]string{}, UninstallArgs...), "/tmp/serverkeeper", "uninstall", "--yes"),
		append(append([]string{}, UninstallArgs...), "/usr/bin/serverkeeper", "init", "--yes"),
		append(append([]string{}, UninstallArgs...), "/usr/bin/serverkeeper", "uninstall", "--yes", "--x"),
		append(append([]string{}, UninstallArgs...), "/usr/bin/serverkeeper", "uninstall", "--yes", "--purge", "x"),
		{"--unit=evil", "--collect", "--on-active=3", "/usr/bin/serverkeeper", "uninstall", "--yes"},
		{"/bin/sh", "-c", "id"},
		nil,
	}
	for _, a := range bad {
		if err := Allowed("systemd-run", a); err == nil {
			t.Fatalf("%v allowed", a)
		}
	}
}

func TestRemoteRoundTrip(t *testing.T) {
	dir := t.TempDir()
	old := hostfs.Root
	hostfs.Root = dir
	defer func() { hostfs.Root = old }()

	a, b := net.Pipe()
	f := NewFake()
	f.Outputs["sshd -t -f /etc/ssh/x"] = "ok"
	go Serve(a, f)
	r := NewRemote(b)

	if err := r.WriteFile("/etc/ssh/sshd_config", []byte("Port 22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "etc/ssh/sshd_config"))
	if err != nil || string(got) != "Port 22\n" {
		t.Fatalf("write failed: %v %q", err, got)
	}
	if _, err := r.ReadFile("/nope"); !os.IsNotExist(err) {
		t.Fatalf("want not-exist, got %v", err)
	}
	out, err := r.Run(context.Background(), "sshd", "-t", "-f", "/etc/ssh/x")
	if err != nil || string(out) != "ok" {
		t.Fatalf("run: %v %q", err, out)
	}
	if err := r.WriteFile("/usr/bin/evil", nil, 0o755); err == nil {
		t.Fatal("write outside allowlist must fail")
	}
}

func TestLocalFileOps(t *testing.T) {
	dir := t.TempDir()
	old := hostfs.Root
	hostfs.Root = dir
	defer func() { hostfs.Root = old }()
	var l Local
	if err := l.MkdirAll("/etc/ssh/sshd_config.d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := l.WriteFile("/etc/ssh/sshd_config.d/x.conf", []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := l.ReadFile("/etc/ssh/sshd_config.d/x.conf"); string(b) != "a" {
		t.Fatal("read back")
	}
	if err := l.Chmod("/etc/ssh/sshd_config.d/x.conf", 0o644); err != nil {
		t.Fatal(err)
	}
	if err := l.Remove("/etc/ssh/sshd_config.d/x.conf"); err != nil {
		t.Fatal(err)
	}
	if err := l.Remove("/etc/ssh/sshd_config.d/x.conf"); err != nil {
		t.Fatal("removing a missing file is not an error")
	}
	for _, bad := range []string{"/usr/bin/x", "relative", "/etc/passwd.d/../../x"} {
		if l.WriteFile(bad, nil, 0o600) == nil {
			t.Fatalf("write %s must be denied", bad)
		}
	}
	if l.Chown("/bin/sh", 0, 0) == nil || l.Remove("/bin/sh") == nil || l.MkdirAll("/usr/x", 0o755) == nil {
		t.Fatal("ops outside allowlist must be denied")
	}
	if _, err := l.Run(context.Background(), "rm", "-rf", "/"); err == nil {
		t.Fatal("rm must be denied")
	}
	out, err := l.Run(context.Background(), "uname", "-r")
	if err != nil || len(out) == 0 {
		t.Fatalf("uname: %v", err)
	}
	_, err = l.Run(context.Background(), "systemctl", "is-active", "serverkeeper-no-such-unit")
	if err == nil || ExitCode(err) <= 0 || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("want exit error, got %v", err)
	}
}

// a user must not be able to redirect root's writes by symlinking ~/.ssh elsewhere
func TestHomeSymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	old := hostfs.Root
	hostfs.Root = dir
	defer func() { hostfs.Root = old }()
	os.MkdirAll(filepath.Join(dir, "home/eve"), 0o755)
	os.MkdirAll(filepath.Join(dir, "etc/sudoers.d"), 0o755)
	if err := os.Symlink(filepath.Join(dir, "etc/sudoers.d"), filepath.Join(dir, "home/eve/.ssh")); err != nil {
		t.Fatal(err)
	}
	var l Local
	if err := l.WriteFile("/home/eve/.ssh/authorized_keys", []byte("k"), 0o600); err == nil {
		t.Fatal("write through a symlinked ~/.ssh must be refused")
	}
	if _, err := os.Stat(filepath.Join(dir, "etc/sudoers.d/authorized_keys")); err == nil {
		t.Fatal("file was created through the symlink")
	}
	for _, f := range []func() error{
		func() error { return l.Chown("/home/eve/.ssh/authorized_keys", 0, 0) },
		func() error { return l.Chmod("/home/eve/.ssh/authorized_keys", 0o600) },
		func() error { return l.MkdirAll("/home/eve/.ssh/x", 0o700) },
		func() error { return l.Remove("/home/eve/.ssh/authorized_keys") },
	} {
		if f() == nil {
			t.Fatal("op through a symlinked ~/.ssh must be refused")
		}
	}
	os.MkdirAll(filepath.Join(dir, "home/bob/.ssh"), 0o700)
	if err := l.WriteFile("/home/bob/.ssh/authorized_keys", []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// every op crosses the privsep socket with allowlist enforcement on the root side
func TestRemoteAllOps(t *testing.T) {
	dir := t.TempDir()
	old := hostfs.Root
	hostfs.Root = dir
	defer func() { hostfs.Root = old }()
	a, b := net.Pipe()
	go Serve(a, NewFake())
	r := NewRemote(b)
	if err := r.MkdirAll("/etc/ssh/sshd_config.d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := r.WriteFile("/etc/ssh/sshd_config.d/a.conf", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.Chmod("/etc/ssh/sshd_config.d/a.conf", 0o640); err != nil {
		t.Fatal(err)
	}
	if err := r.Chown("/etc/ssh/sshd_config.d/a.conf", 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := r.Remove("/etc/ssh/sshd_config.d/a.conf"); err != nil {
		t.Fatal(err)
	}
	if r.Remove("/bin/sh") == nil || r.Chown("/bin/sh", 0, 0) == nil || r.MkdirAll("/usr/x", 0o755) == nil {
		t.Fatal("denied ops must fail through the socket too")
	}
	if _, err := r.Run(context.Background(), "bash", "-c", "id"); err == nil {
		t.Fatal("bash must be denied client side")
	}
	var re *RunError
	err := &RunError{Cmd: "x", Err: os.ErrPermission}
	if !errors.As(error(err), &re) || !errors.Is(err, os.ErrPermission) {
		t.Fatal("RunError must unwrap")
	}
}
