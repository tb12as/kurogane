package executor

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/serverkeeper/serverkeeper/internal/hostfs"
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
