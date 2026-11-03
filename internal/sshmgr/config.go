package sshmgr

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tb12as/serverman/internal/hostfs"
)

// Directive is one sshd_config line.
type Directive struct {
	Key   string `json:"key"` // lower-cased
	Name  string `json:"name"`
	Value string `json:"value"`
	File  string `json:"file"`
	Line  int    `json:"line"`
	Match bool   `json:"match"` // inside a Match block (not global)
}

// source reads host files; extra holds candidate files so SafeApply can simulate a config before writing it.
type source struct {
	read  func(p string) ([]byte, error)
	extra map[string][]byte
}

func (s source) get(p string) ([]byte, error) {
	if b, ok := s.extra[p]; ok {
		return b, nil
	}
	return s.read(p)
}

// parseConfig reads path following Include (globs, relative to /etc/ssh) and marks Match-block lines.
func parseConfig(src source, p string) ([]Directive, error) {
	var out []Directive
	err := parseInto(src, p, false, 0, &out)
	return out, err
}

func parseInto(src source, p string, inMatch bool, depth int, out *[]Directive) error {
	if depth > 16 {
		return fmt.Errorf("sshd_config: Include nesting too deep at %s", p)
	}
	b, err := src.get(p)
	if err != nil {
		return err
	}
	match := inMatch
	for n, raw := range strings.Split(string(b), "\n") {
		l := strings.TrimSpace(raw)
		if l == "" || l[0] == '#' {
			continue
		}
		name, val := splitDirective(l)
		key := strings.ToLower(name)
		switch key {
		case "match":
			match = true
			*out = append(*out, Directive{Key: key, Name: name, Value: val, File: p, Line: n + 1, Match: true})
			continue
		case "include":
			for _, pat := range strings.Fields(val) {
				if !path.IsAbs(pat) {
					pat = path.Join("/etc/ssh", pat)
				}
				for _, f := range globHost(src, pat) {
					if err := parseInto(src, f, match, depth+1, out); err != nil && !errors.Is(err, fs.ErrNotExist) {
						return err
					}
				}
			}
			continue
		}
		*out = append(*out, Directive{Key: key, Name: name, Value: val, File: p, Line: n + 1, Match: match})
	}
	return nil
}

// splitDirective handles "Key value", "Key=value" and quoted values.
func splitDirective(l string) (string, string) {
	i := strings.IndexAny(l, " \t=")
	if i < 0 {
		return l, ""
	}
	name := l[:i]
	v := strings.TrimLeft(l[i:], " \t")
	v = strings.TrimSpace(strings.TrimPrefix(v, "="))
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	return name, v
}

func globHost(src source, pat string) []string {
	matches, _ := filepath.Glob(hostfs.P(pat))
	seen := map[string]bool{}
	var out []string
	for _, m := range matches {
		rel := m
		if hostfs.Root != "/" && hostfs.Root != "" {
			rel = "/" + strings.TrimPrefix(strings.TrimPrefix(m, hostfs.Root), "/")
		}
		seen[rel] = true
		out = append(out, rel)
	}
	// candidate files that do not exist on disk yet
	for p := range src.extra {
		if ok, _ := path.Match(pat, p); ok && !seen[p] {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// effective returns first-value-wins global settings (lower-cased keys); repeated list keys are joined.
func effective(ds []Directive) map[string]string {
	out := map[string]string{}
	for _, d := range ds {
		if d.Match || d.Key == "match" {
			continue
		}
		if _, ok := out[d.Key]; ok {
			if multi[d.Key] {
				out[d.Key] += " " + d.Value
			}
			continue
		}
		out[d.Key] = d.Value
	}
	return out
}

// multi lists keywords that accumulate instead of first-value-wins.
var multi = map[string]bool{"port": true, "listenaddress": true, "hostkey": true, "acceptenv": true,
	"allowusers": true, "allowgroups": true, "denyusers": true, "denygroups": true}

// sshd defaults for settings we reason about when they are absent.
var defaults = map[string]string{
	"port": "22", "permitrootlogin": "prohibit-password", "passwordauthentication": "yes",
	"pubkeyauthentication": "yes", "kbdinteractiveauthentication": "yes", "maxauthtries": "6",
	"logingracetime": "120", "clientaliveinterval": "0", "clientalivecountmax": "3", "x11forwarding": "no",
	"allowtcpforwarding": "yes", "permitemptypasswords": "no", "authorizedkeysfile": ".ssh/authorized_keys .ssh/authorized_keys2",
}

func (m *Manager) src(extra map[string][]byte) source {
	return source{read: m.d.Ex.ReadFile, extra: extra}
}

// Settings returns the effective sshd settings with lower-cased keys: `sshd -T` when available
// (needs root and a valid config), else parsed from the files plus sshd defaults.
func (m *Manager) Settings(ctx context.Context) (map[string]string, error) {
	if hostfs.Root == "/" || hostfs.Root == "" {
		if out, err := m.d.Ex.Run(ctx, "sshd", "-T"); err == nil && len(out) > 0 {
			res := map[string]string{}
			for _, l := range strings.Split(string(out), "\n") {
				k, v, ok := strings.Cut(strings.TrimSpace(l), " ")
				if !ok {
					continue
				}
				if old, dup := res[k]; dup {
					res[k] = old + " " + v
				} else {
					res[k] = v
				}
			}
			return res, nil
		}
	}
	ds, err := parseConfig(m.src(nil), m.d.Cfg.SSH.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w (is openssh-server installed? set ssh.config_path if the file lives elsewhere)",
			m.d.Cfg.SSH.ConfigPath, err)
	}
	return withDefaults(effective(ds)), nil
}

// Managed is one sshd setting ServerKeeper manages, with its recommendation (PRD §6.2).
type Managed struct {
	Name        string `json:"name"`
	Recommended string `json:"recommended"`
	Notes       string `json:"notes,omitempty"`
	ok          func(v string) bool
}

var weakAlgos = []string{"cbc", "sha1", "diffie-hellman-group1", "diffie-hellman-group14-sha1", "arcfour", "md5", "3des"}

// Modern algorithm sets used by `ssh config set ... recommended` and the SSH-CIPHERS fix.
const (
	ModernCiphers = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
	ModernKex     = "sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"
	ModernMACs    = "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"
)

func modern(v string) bool {
	if v == "" {
		return false
	}
	v = strings.ToLower(v)
	for _, w := range weakAlgos {
		if strings.Contains(v, w) {
			return false
		}
	}
	return true
}

func atMost(n int) func(string) bool {
	return func(v string) bool {
		var x int
		_, err := fmt.Sscan(v, &x)
		return err == nil && x > 0 && x <= n
	}
}

var ManagedSettings = []Managed{
	{"Port", "custom (e.g. 2222)", "Reduces log noise, not real security", func(v string) bool { return v != "22" }},
	{"PermitRootLogin", "no or prohibit-password", "", func(v string) bool {
		return v == "no" || v == "prohibit-password" || v == "without-password"
	}},
	{"PasswordAuthentication", "no", "Blocked unless at least one working key exists", eq("no")},
	{"PubkeyAuthentication", "yes", "", eq("yes")},
	{"KbdInteractiveAuthentication", "no", "", eq("no")},
	{"MaxAuthTries", "3", "", atMost(3)},
	{"LoginGraceTime", "30", "", atMost(30)},
	{"ClientAliveInterval", "300", "Drops idle sessions", func(v string) bool { return v != "0" && atMost(300)(v) }},
	{"ClientAliveCountMax", "2", "Drops idle sessions", atMost(2)},
	{"AllowUsers", "explicit list", "", func(v string) bool { return v != "" }},
	{"AllowGroups", "explicit list", "", func(v string) bool { return v != "" }},
	{"X11Forwarding", "no", "no unless needed", eq("no")},
	{"AllowTcpForwarding", "no", "no unless needed", eq("no")},
	{"Ciphers", "modern set only", "Drop CBC, SHA1, diffie-hellman-group1", modern},
	{"KexAlgorithms", "modern set only", "Drop CBC, SHA1, diffie-hellman-group1", modern},
	{"MACs", "modern set only", "Drop CBC, SHA1, diffie-hellman-group1", modern},
}

func eq(want string) func(string) bool {
	return func(v string) bool { return strings.EqualFold(v, want) }
}

// ConfigRow is one line of `ssh config show`.
type ConfigRow struct {
	Managed
	Current string `json:"current"`
	OK      bool   `json:"ok"`
}

// ShowConfig returns current vs recommended for every managed setting.
func (m *Manager) ShowConfig(ctx context.Context) ([]ConfigRow, error) {
	s, err := m.Settings(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ConfigRow, 0, len(ManagedSettings))
	for _, ms := range ManagedSettings {
		cur := s[strings.ToLower(ms.Name)]
		// AllowUsers/AllowGroups: either one being set satisfies the recommendation
		ok := ms.ok(cur)
		if ms.Name == "AllowUsers" || ms.Name == "AllowGroups" {
			ok = s["allowusers"] != "" || s["allowgroups"] != ""
		}
		out = append(out, ConfigRow{Managed: ms, Current: cur, OK: ok})
	}
	return out, nil
}

// allowedKeys are the sshd keywords SafeApply accepts (managed ones plus a few hardening-related).
var allowedKeys = map[string]string{}

func init() {
	for _, ms := range ManagedSettings {
		allowedKeys[strings.ToLower(ms.Name)] = ms.Name
	}
	for _, k := range []string{"TrustedUserCAKeys", "AuthenticationMethods", "PermitEmptyPasswords", "DenyUsers",
		"DenyGroups", "MaxSessions", "MaxStartups", "HostbasedAuthentication", "IgnoreRhosts", "PermitUserEnvironment",
		"LogLevel", "Banner", "UsePAM", "ChallengeResponseAuthentication", "AllowAgentForwarding", "PermitTunnel"} {
		allowedKeys[strings.ToLower(k)] = k
	}
}

var _ = os.ErrNotExist

func withDefaults(eff map[string]string) map[string]string {
	for k, v := range defaults {
		if _, ok := eff[k]; !ok {
			eff[k] = v
		}
	}
	return eff
}
