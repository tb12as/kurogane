package checks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/tb12as/kurogane/internal/hostfs"
)

// ---- sshd ----

// sshDefaults are OpenSSH 8.9+ defaults, used when the settings source only returns explicit options.
var sshDefaults = map[string]string{
	"port": "22", "permitrootlogin": "prohibit-password", "passwordauthentication": "yes", "maxauthtries": "6",
	"x11forwarding": "no", "permitemptypasswords": "no", "logingracetime": "120", "clientaliveinterval": "0",
	"clientalivecountmax": "3",
	"ciphers": "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com," +
		"aes256-gcm@openssh.com",
	"macs": "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com," +
		"hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com," +
		"hmac-sha2-256,hmac-sha2-512,hmac-sha1",
	"kexalgorithms": "sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org," +
		"ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256," +
		"diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256",
}

// SSHSettings returns effective sshd settings: the SSH manager first, `sshd -T` as fallback.
func SSHSettings(ctx context.Context, e *Env) (map[string]string, error) {
	return memo(ctx, "sshd", func() (map[string]string, error) {
		var m map[string]string
		if e.Settings != nil {
			m, _ = e.Settings(ctx)
		}
		if len(m) == 0 {
			if out, err := e.Ex.Run(ctx, "sshd", "-T"); err == nil {
				m = parseSSHD(string(out))
			}
		}
		if len(m) == 0 {
			return nil, errors.New("effective sshd settings unavailable: run `sshd -t` as root to check the config")
		}
		full := make(map[string]string, len(sshDefaults)+len(m))
		for k, v := range sshDefaults {
			full[k] = v
		}
		for k, v := range m {
			full[strings.ToLower(k)] = v
		}
		return full, nil
	})
}

func parseSSHD(s string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), " ")
		k = strings.ToLower(k)
		if ok && m[k] == "" {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

func sshInstalled() bool { return hostfs.Exists("/etc/ssh/sshd_config") }

// sshCheck evaluates effective sshd settings; plan (nil = report-only) returns the settings to set.
type sshCheck struct {
	base
	eval func(m map[string]string) (bool, string)
	plan func(m map[string]string) map[string]string
}

func (c *sshCheck) Run(ctx context.Context) Result {
	if !sshInstalled() {
		return c.res(NA, "sshd not installed (/etc/ssh/sshd_config missing)")
	}
	m, err := SSHSettings(ctx, c.e)
	if err != nil {
		return c.res(Error, err.Error())
	}
	ok, ev := c.eval(m)
	if ok {
		return c.res(Pass, ev)
	}
	return c.res(Fail, ev)
}

func (c *sshCheck) Fix(ctx context.Context, dryRun bool) (Diff, error) {
	if c.plan == nil {
		return Diff{}, ErrNoFix
	}
	m, err := SSHSettings(ctx, c.e)
	if err != nil {
		return Diff{}, err
	}
	d := Diff{SSH: map[string]string{}, SSHOld: map[string]string{}}
	for k, v := range c.plan(m) {
		if !strings.EqualFold(m[strings.ToLower(k)], v) {
			d.SSH[k] = v
			d.SSHOld[k] = m[strings.ToLower(k)]
		}
	}
	if len(d.SSH) == 0 {
		d.SSH, d.SSHOld = nil, nil
	}
	d.Note = "sshd change uses safe-apply: confirm with `serverkeeper ssh confirm` before the rollback timer expires"
	return c.finish(ctx, d, dryRun)
}

// sshEq builds a check that passes when key equals one of want; fix sets want[0].
func sshEq(m Meta, e *Env, key string, want ...string) *sshCheck {
	m.Category, m.AutoFix = "ssh", FixYes
	return &sshCheck{base: base{m, e},
		eval: func(s map[string]string) (bool, string) {
			v := s[key]
			for _, w := range want {
				if strings.EqualFold(v, w) {
					return true, key + " " + v
				}
			}
			return false, fmt.Sprintf("%s %s (want %s)", key, v, strings.Join(want, " or "))
		},
		plan: func(map[string]string) map[string]string { return map[string]string{sshName(key): want[0]} },
	}
}

// sshName maps a lower-cased sshd -T key to its sshd_config spelling.
func sshName(k string) string {
	names := map[string]string{
		"permitrootlogin": "PermitRootLogin", "passwordauthentication": "PasswordAuthentication",
		"maxauthtries": "MaxAuthTries", "x11forwarding": "X11Forwarding", "permitemptypasswords": "PermitEmptyPasswords",
		"logingracetime": "LoginGraceTime", "clientaliveinterval": "ClientAliveInterval",
		"clientalivecountmax": "ClientAliveCountMax", "ciphers": "Ciphers", "macs": "MACs",
		"kexalgorithms": "KexAlgorithms",
	}
	if n, ok := names[k]; ok {
		return n
	}
	return k
}

// ---- sysctl ----

// SysctlFile is the drop-in all sysctl fixes write.
const SysctlFile = "/etc/sysctl.d/99-serverkeeper.conf"

type kv struct{ k, v string }

type sysctlCheck struct {
	base
	want    []kv
	fixable bool
}

func sysctlPath(k string) string { return "/proc/sys/" + strings.ReplaceAll(k, ".", "/") }

// SysctlValue reads a live kernel parameter from /proc/sys; ok=false if it does not exist.
func SysctlValue(k string) (string, bool) {
	b, err := hostfs.Read(sysctlPath(k))
	if err != nil {
		return "", false
	}
	return strings.Join(strings.Fields(string(b)), " "), true
}

// mismatches returns wrong keys with their current values; present counts existing keys.
func (c *sysctlCheck) mismatches() (bad []kv, cur map[string]string, present int) {
	cur = map[string]string{}
	for _, w := range c.want {
		v, ok := SysctlValue(w.k)
		if !ok {
			continue
		}
		present++
		cur[w.k] = v
		if v != w.v {
			bad = append(bad, w)
		}
	}
	return bad, cur, present
}

func (c *sysctlCheck) Run(context.Context) Result {
	bad, cur, n := c.mismatches()
	if n == 0 {
		return c.res(NA, "kernel parameters not present")
	}
	var ev []string
	for _, w := range c.want {
		if v, ok := cur[w.k]; ok {
			ev = append(ev, w.k+" = "+v)
		}
	}
	if len(bad) == 0 {
		return c.res(Pass, strings.Join(ev, "; "))
	}
	var b []string
	for _, w := range bad {
		b = append(b, fmt.Sprintf("%s = %s (want %s)", w.k, cur[w.k], w.v))
	}
	return c.res(Fail, strings.Join(b, "; "))
}

func (c *sysctlCheck) Fix(ctx context.Context, dryRun bool) (Diff, error) {
	if !c.fixable {
		return Diff{}, ErrNoFix
	}
	bad, cur, _ := c.mismatches()
	d := Diff{}
	if len(bad) == 0 {
		return c.finish(ctx, d, dryRun)
	}
	set := map[string]string{}
	d.SysctlOld = map[string]string{}
	for _, w := range bad {
		set[w.k] = w.v
		d.SysctlOld[w.k] = cur[w.k]
		d.Cmds = append(d.Cmds, cmd("sysctl", "-w", w.k+"="+w.v))
		d.Undo = append(d.Undo, cmd("sysctl", "-w", w.k+"="+cur[w.k]))
	}
	old, _ := readFile(SysctlFile)
	d.Sysctl = set
	d.Files = []FileEdit{{Path: SysctlFile, New: SysctlEdit(old, set, nil), Mode: 0o644}}
	return c.finish(ctx, d, dryRun)
}

// SysctlEdit sets keys (replacing existing lines, appending new ones) and drops keys in del.
func SysctlEdit(content string, set map[string]string, del []string) string {
	done := map[string]bool{}
	var out []string
	for _, l := range splitLines(content) {
		k, _, ok := strings.Cut(l, "=")
		k = strings.TrimSpace(k)
		if ok && !strings.HasPrefix(k, "#") {
			if v, hit := set[k]; hit {
				out = append(out, k+" = "+v)
				done[k] = true
				continue
			}
			if contains(del, k) {
				continue
			}
		}
		out = append(out, l)
	}
	if len(out) == 0 && len(set) > 0 {
		out = append(out, "# managed by serverkeeper harden (revert with `serverkeeper harden revert <fix-id>`)")
	}
	for _, k := range sortedKeys(set) {
		if !done[k] {
			out = append(out, k+" = "+set[k])
		}
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "\n") + "\n"
}

func sysctlCk(m Meta, e *Env, want ...kv) Check {
	m.Category, m.AutoFix = "kernel", FixYes
	return &sysctlCheck{base: base{m, e}, want: want, fixable: true}
}

// ---- file permissions ----

type fileModeCheck struct {
	base
	path    string
	max     os.FileMode // permitted bits
	fixable bool
}

func (c *fileModeCheck) Run(context.Context) Result {
	mode, ok := fileMode(c.path)
	if !ok {
		return c.res(NA, c.path+" does not exist")
	}
	ev := fmt.Sprintf("%s mode %04o", c.path, mode)
	if mode&^c.max == 0 {
		return c.res(Pass, ev)
	}
	return c.res(Fail, fmt.Sprintf("%s (want %04o or stricter)", ev, c.max))
}

func (c *fileModeCheck) Fix(ctx context.Context, dryRun bool) (Diff, error) {
	if !c.fixable {
		return Diff{}, ErrNoFix
	}
	d := Diff{}
	if mode, ok := fileMode(c.path); ok && mode&^c.max != 0 {
		d.Modes = []ModeEdit{{Path: c.path, Old: mode, New: mode & c.max}}
	}
	return c.finish(ctx, d, dryRun)
}

func modeCk(m Meta, e *Env, path string, max os.FileMode) Check {
	m.Category, m.AutoFix = "files", FixYes
	return &fileModeCheck{base: base{m, e}, path: path, max: max, fixable: true}
}

// ---- small helpers ----

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// fnCheck builds a check from run and optional fix (nil = report-only) functions.
type fnCheck struct {
	base
	run func(ctx context.Context, c *fnCheck) Result
	fix func(ctx context.Context, c *fnCheck) (Diff, error)
}

func (c *fnCheck) Run(ctx context.Context) Result { return c.run(ctx, c) }

func (c *fnCheck) Fix(ctx context.Context, dryRun bool) (Diff, error) {
	if c.fix == nil {
		return Diff{}, ErrNoFix
	}
	d, err := c.fix(ctx, c)
	if err != nil {
		return Diff{}, err
	}
	return c.finish(ctx, d, dryRun)
}

func fn(m Meta, e *Env, run func(context.Context, *fnCheck) Result,
	fix func(context.Context, *fnCheck) (Diff, error)) *fnCheck {
	if m.AutoFix == "" {
		m.AutoFix = FixReport
		if fix != nil {
			m.AutoFix = FixYes
		}
	}
	return &fnCheck{base: base{m, e}, run: run, fix: fix}
}
