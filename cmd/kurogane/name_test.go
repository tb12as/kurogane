package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCLIName(t *testing.T) {
	for arg0, want := range map[string]string{"/usr/bin/krgn": "krgn", "krgn": "krgn", "/usr/bin/kurogane": "kurogane",
		"./kurogane.test": "kurogane", "": "kurogane"} {
		if got := cliName(arg0); got != want {
			t.Errorf("cliName(%q) = %q, want %q", arg0, got, want)
		}
	}
}

func TestRemoveShortLink(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "kurogane")
	os.WriteFile(bin, []byte("x"), 0o755)
	os.Symlink("kurogane", filepath.Join(dir, "krgn"))
	removeShortLink(bin)
	if _, err := os.Lstat(filepath.Join(dir, "krgn")); !os.IsNotExist(err) {
		t.Fatal("krgn link not removed")
	}
	// a krgn that is not our link is left alone
	other := t.TempDir()
	os.WriteFile(filepath.Join(other, "kurogane"), []byte("x"), 0o755)
	os.Symlink("/usr/bin/something-else", filepath.Join(other, "krgn"))
	removeShortLink(filepath.Join(other, "kurogane"))
	if _, err := os.Lstat(filepath.Join(other, "krgn")); err != nil {
		t.Fatal("foreign krgn removed")
	}
	removeShortLink(filepath.Join(t.TempDir(), "kurogane")) // no link: no-op
}
