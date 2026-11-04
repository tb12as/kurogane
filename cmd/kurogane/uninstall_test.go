package main

import "testing"

func TestSafeDir(t *testing.T) {
	for p, want := range map[string]bool{
		"/var/lib/kurogane": true, "/etc/kurogane": true, "/var/lib/kurogane/vm/": true,
		"/": false, "": false, "/var": false, "/etc/": false, "relative/dir": false, "/var/..": false,
	} {
		if got := safeDir(p); got != want {
			t.Errorf("safeDir(%q) = %v, want %v", p, got, want)
		}
	}
}
