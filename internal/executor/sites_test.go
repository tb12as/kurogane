package executor

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/tb12as/serverman/internal/hostfs"
)

func siteRoot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := hostfs.Root
	hostfs.Root = dir
	t.Cleanup(func() { hostfs.Root = old })
	for _, d := range []string{"etc/nginx/sites-available", "etc/nginx/sites-enabled", "etc/nginx/conf.d",
		"etc/apache2/sites-available", "etc/apache2/sites-enabled", "etc/httpd/conf.d", "etc/ssh"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for p, c := range map[string]string{"etc/nginx/sites-available/shop": "server {}", "etc/nginx/conf.d/api.conf": "x",
		"etc/apache2/sites-available/blog.conf": "x", "etc/httpd/conf.d/a.conf": "x", "etc/ssh/sshd_config": "x"} {
		if err := os.WriteFile(filepath.Join(dir, p), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func denied(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, ErrDenied) {
		t.Errorf("%s: want ErrDenied, got %v", what, err)
	}
}

func TestLinkSite(t *testing.T) {
	dir := siteRoot(t)
	var l Local
	if err := l.LinkSite("/etc/nginx/sites-available/shop", "/etc/nginx/sites-enabled/shop"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.Readlink(filepath.Join(dir, "etc/nginx/sites-enabled/shop")); got != "../sites-available/shop" {
		t.Fatalf("link target = %q", got)
	}
	if err := l.LinkSite("/etc/nginx/sites-available/shop", "/etc/nginx/sites-enabled/shop"); err == nil {
		t.Error("existing link overwritten")
	}
	if err := l.LinkSite("/etc/apache2/sites-available/blog.conf", "/etc/apache2/sites-enabled/blog.conf"); err != nil {
		t.Fatal(err)
	}
	denied(t, "link outside sites-enabled", l.LinkSite("/etc/nginx/sites-available/shop", "/etc/nginx/conf.d/shop"))
	denied(t, "nginx target for apache link", l.LinkSite("/etc/nginx/sites-available/shop", "/etc/apache2/sites-enabled/shop"))
	denied(t, "renamed target", l.LinkSite("/etc/nginx/sites-available/shop", "/etc/nginx/sites-enabled/other"))
	denied(t, "target outside sites-available", l.LinkSite("/etc/ssh/sshd_config", "/etc/nginx/sites-enabled/sshd_config"))
	denied(t, "traversal", l.LinkSite("/etc/nginx/sites-available/../../ssh/sshd_config", "/etc/nginx/sites-enabled/x"))
	denied(t, "dot name", l.LinkSite("/etc/nginx/sites-available/.hidden", "/etc/nginx/sites-enabled/.hidden"))
	denied(t, "relative", l.LinkSite("sites-available/shop", "sites-enabled/shop"))
	if err := l.LinkSite("/etc/nginx/sites-available/missing", "/etc/nginx/sites-enabled/missing"); !os.IsNotExist(err) {
		t.Errorf("missing target: %v", err)
	}
	// a symlink in sites-available is not a regular file: it could point anywhere
	os.Symlink("/etc/ssh/sshd_config", filepath.Join(dir, "etc/nginx/sites-available/evil"))
	denied(t, "symlinked target", l.LinkSite("/etc/nginx/sites-available/evil", "/etc/nginx/sites-enabled/evil"))
}

func TestUnlinkSite(t *testing.T) {
	dir := siteRoot(t)
	var l Local
	os.Symlink("../sites-available/shop", filepath.Join(dir, "etc/nginx/sites-enabled/shop"))
	os.WriteFile(filepath.Join(dir, "etc/nginx/sites-enabled/plain"), []byte("x"), 0o644)
	if err := l.UnlinkSite("/etc/nginx/sites-enabled/shop"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "etc/nginx/sites-available/shop")); err != nil {
		t.Fatal("target removed with the link")
	}
	denied(t, "regular file", l.UnlinkSite("/etc/nginx/sites-enabled/plain"))
	denied(t, "outside sites-enabled", l.UnlinkSite("/etc/nginx/sites-available/shop"))
	if err := l.UnlinkSite("/etc/nginx/sites-enabled/gone"); !os.IsNotExist(err) {
		t.Errorf("missing link: %v", err)
	}
}

func TestRenameSite(t *testing.T) {
	dir := siteRoot(t)
	var l Local
	if err := l.RenameSite("/etc/nginx/conf.d/api.conf", "/etc/nginx/conf.d/api.conf.disabled"); err != nil {
		t.Fatal(err)
	}
	if err := l.RenameSite("/etc/nginx/conf.d/api.conf.disabled", "/etc/nginx/conf.d/api.conf"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "etc/httpd/conf.d/a.conf.disabled"), []byte("y"), 0o644)
	if err := l.RenameSite("/etc/httpd/conf.d/a.conf", "/etc/httpd/conf.d/a.conf.disabled"); !errors.Is(err, ErrExists) {
		t.Errorf("existing destination: %v", err)
	}
	denied(t, "wrong suffix", l.RenameSite("/etc/nginx/conf.d/api.conf", "/etc/nginx/conf.d/api.off"))
	denied(t, "other dir", l.RenameSite("/etc/nginx/conf.d/api.conf", "/etc/httpd/conf.d/api.conf.disabled"))
	denied(t, "outside conf.d", l.RenameSite("/etc/ssh/sshd_config", "/etc/ssh/sshd_config.disabled"))
	denied(t, "not .conf", l.RenameSite("/etc/nginx/conf.d/x.txt", "/etc/nginx/conf.d/x.txt.disabled"))
	os.Symlink("/etc/ssh/sshd_config", filepath.Join(dir, "etc/nginx/conf.d/link.conf"))
	denied(t, "symlink", l.RenameSite("/etc/nginx/conf.d/link.conf", "/etc/nginx/conf.d/link.conf.disabled"))
}

func TestSiteOpsRemote(t *testing.T) {
	dir := siteRoot(t)
	a, b := net.Pipe()
	f := NewFake()
	go Serve(a, f)
	r := NewRemote(b)
	if err := r.LinkSite("/etc/nginx/sites-available/shop", "/etc/nginx/sites-enabled/shop"); err != nil {
		t.Fatal(err)
	}
	if err := r.UnlinkSite("/etc/nginx/sites-enabled/shop"); err != nil {
		t.Fatal(err)
	}
	if err := r.RenameSite("/etc/nginx/conf.d/api.conf", "/etc/nginx/conf.d/api.conf.disabled"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "etc/nginx/conf.d/api.conf.disabled")); err != nil {
		t.Fatal(err)
	}
	if err := r.UnlinkSite("/etc/ssh/sshd_config"); err == nil {
		t.Fatal("remote unlink outside sites-enabled allowed")
	}
	f.Errors["link-site /etc/nginx/sites-enabled/shop"] = errors.New("boom")
	if err := r.LinkSite("/etc/nginx/sites-available/shop", "/etc/nginx/sites-enabled/shop"); err == nil {
		t.Fatal("injected error lost")
	}
	if !f.Called("unlink-site /etc/nginx/sites-enabled/shop") {
		t.Fatal("fake did not record the call")
	}
}
