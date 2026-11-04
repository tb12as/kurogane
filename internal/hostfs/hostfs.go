// Package hostfs maps absolute host paths onto an optional root prefix so collectors,
// checks and parsers can run against fixture trees in tests.
package hostfs

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Root is the host root; KRGN_ROOT overrides it (tests, chroots, containers mounting the host at /host).
var Root = rootFromEnv()

func rootFromEnv() string {
	if r := os.Getenv("KRGN_ROOT"); r != "" {
		return r
	}
	return "/"
}

// P returns the real filesystem path for host path p.
func P(p string) string {
	if Root == "/" || Root == "" {
		return p
	}
	return filepath.Join(Root, p)
}

// Read reads host path p.
func Read(p string) ([]byte, error) { return os.ReadFile(P(p)) }

// ReadString reads host path p and trims whitespace; returns "" on error.
func ReadString(p string) string {
	b, err := Read(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Exists reports whether host path p exists.
func Exists(p string) bool {
	_, err := os.Stat(P(p))
	return err == nil
}

// Lines returns the lines of host file p.
func Lines(p string) ([]string, error) {
	b, err := Read(p)
	if err != nil {
		return nil, err
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out, sc.Err()
}

// Distro describes the host OS family.
type Distro struct {
	ID        string `json:"id"`
	VersionID string `json:"version_id"`
	Name      string `json:"name"`
	Family    string `json:"family"`  // debian | rhel | other
	PkgMgr    string `json:"pkg_mgr"` // apt | dnf | ""
}

// Supported reports whether the distro is on the official support list (HD-7, §11.3).
func (d Distro) Supported() bool {
	switch d.ID {
	case "ubuntu":
		return d.VersionID == "22.04" || d.VersionID == "24.04"
	case "debian":
		return d.VersionID == "12"
	case "rhel", "rocky", "almalinux":
		return strings.HasPrefix(d.VersionID, "9")
	}
	return false
}

// DetectDistro parses /etc/os-release.
func DetectDistro() Distro {
	var d Distro
	lines, _ := Lines("/etc/os-release")
	like := ""
	for _, l := range lines {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			d.ID = v
		case "VERSION_ID":
			d.VersionID = v
		case "PRETTY_NAME":
			d.Name = v
		case "ID_LIKE":
			like = v
		}
	}
	all := d.ID + " " + like
	switch {
	case strings.Contains(all, "debian") || strings.Contains(all, "ubuntu"):
		d.Family, d.PkgMgr = "debian", "apt"
	case strings.Contains(all, "rhel") || strings.Contains(all, "fedora") || strings.Contains(all, "centos") ||
		d.ID == "amzn":
		d.Family, d.PkgMgr = "rhel", "dnf"
	default:
		d.Family = "other"
	}
	return d
}

// HasBinary reports whether a binary is on PATH (or in the usual sbin dirs).
func HasBinary(name string) bool {
	if _, err := exec.LookPath(name); err == nil {
		return true
	}
	for _, d := range []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin", "/usr/local/sbin"} {
		if _, err := os.Stat(P(filepath.Join(d, name))); err == nil {
			return true
		}
	}
	return false
}

// Glob expands a host-path pattern under Root, sorted; a pattern without wildcards is returned when the file
// exists. A directory expands to the files directly inside it (Apache Include semantics).
func Glob(pat string) []string {
	if !strings.ContainsAny(pat, "*?[") {
		fi, err := os.Stat(P(pat))
		if err != nil {
			return nil
		}
		if !fi.IsDir() {
			return []string{pat}
		}
		pat = strings.TrimRight(pat, "/") + "/*"
	}
	ms, _ := filepath.Glob(P(pat))
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		if fi, err := os.Stat(m); err == nil && fi.IsDir() {
			continue
		}
		out = append(out, unroot(m))
	}
	sort.Strings(out)
	return out
}

func unroot(m string) string {
	if Root == "/" || Root == "" {
		return m
	}
	rel, err := filepath.Rel(Root, m)
	if err != nil {
		return m
	}
	return "/" + rel
}
