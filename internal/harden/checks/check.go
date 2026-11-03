// Package checks is the hardening check library (PRD §7.1): one file per check, each with metadata,
// a read-only Run and an optional Fix. Custom checks come from YAML packs (pack.go); Go plugins are not
// possible with CGO_ENABLED=0, so YAML is the plugin mechanism (HD-8).
package checks

import (
	"context"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/tb12as/serverman/internal/collector"
	"github.com/tb12as/serverman/internal/executor"
	"github.com/tb12as/serverman/internal/hostfs"
)

// Severities and their score weights (PRD §7.2).
const (
	Critical = "critical"
	High     = "high"
	Medium   = "medium"
	Low      = "low"
)

// Weight returns the score weight of a severity.
func Weight(sev string) float64 {
	switch sev {
	case Critical:
		return 10
	case High:
		return 5
	case Medium:
		return 3
	}
	return 1
}

// Rank orders severities (critical = 4 ... low = 1) for severity filters.
func Rank(sev string) int {
	switch sev {
	case Critical:
		return 4
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	}
	return 0
}

// Result statuses.
const (
	Pass    = "pass"
	Fail    = "fail"
	NA      = "na"
	Error   = "error"
	Ignored = "ignored"
)

// Auto-fix classes (PRD §7.1).
const (
	FixYes     = "yes"
	FixPartial = "partial"
	FixConfirm = "confirm" // applies only with explicit confirmation (firewall)
	FixReport  = "report-only"
)

// Meta describes a check for catalogs and reports.
type Meta struct {
	ID          string `json:"id" yaml:"id"`
	Title       string `json:"title" yaml:"title"`
	Category    string `json:"category" yaml:"category"`
	Severity    string `json:"severity" yaml:"severity"`
	CIS         string `json:"cis,omitempty" yaml:"cis"` // CIS Ubuntu 22.04 benchmark numbering
	Rationale   string `json:"rationale" yaml:"rationale"`
	Remediation string `json:"remediation" yaml:"remediation"`
	AutoFix     string `json:"auto_fix" yaml:"-"`
}

// Result is one check outcome; metadata fields are filled by the scanner for storage and reports.
type Result struct {
	CheckID      string `json:"check_id"`
	Status       string `json:"status"`
	Evidence     string `json:"evidence"`
	Title        string `json:"title,omitempty"`
	Category     string `json:"category,omitempty"`
	Severity     string `json:"severity,omitempty"`
	CIS          string `json:"cis,omitempty"`
	Rationale    string `json:"rationale,omitempty"`
	Remediation  string `json:"remediation,omitempty"`
	AutoFix      string `json:"auto_fix,omitempty"`
	IgnoreReason string `json:"ignore_reason,omitempty"`
}

// FileEdit replaces a whole file (the old content is captured by the fix backup).
type FileEdit struct {
	Path   string      `json:"path"`
	New    string      `json:"new"`
	Mode   os.FileMode `json:"mode"`
	Remove bool        `json:"remove,omitempty"`
}

// ModeEdit changes permissions only.
type ModeEdit struct {
	Path string      `json:"path"`
	Old  os.FileMode `json:"old"`
	New  os.FileMode `json:"new"`
}

// Diff is the planned (dry run) or applied change of a fix.
type Diff struct {
	CheckID   string            `json:"check_id"`
	Text      string            `json:"diff"` // unified diff plus commands, shown before applying
	Files     []FileEdit        `json:"files,omitempty"`
	Modes     []ModeEdit        `json:"modes,omitempty"`
	Sysctl    map[string]string `json:"sysctl,omitempty"` // keys owned in SysctlFile (per-key revert)
	SysctlOld map[string]string `json:"sysctl_old,omitempty"`
	SSH       map[string]string `json:"ssh,omitempty"` // applied via sshmgr safe-apply
	SSHOld    map[string]string `json:"ssh_old,omitempty"`
	Cmds      [][]string        `json:"cmds,omitempty"`
	Undo      [][]string        `json:"undo,omitempty"`   // run on revert after files are restored
	Backup    []string          `json:"backup,omitempty"` // extra files Cmds modify
	Confirm   bool              `json:"confirm,omitempty"`
	Note      string            `json:"note,omitempty"`
}

// Empty reports whether the diff changes nothing.
func (d Diff) Empty() bool {
	return len(d.Files) == 0 && len(d.Modes) == 0 && len(d.SSH) == 0 && len(d.Cmds) == 0
}

// Check is the PRD §9 interface plus metadata.
type Check interface {
	ID() string
	Info() Meta
	Run(ctx context.Context) Result
	Fix(ctx context.Context, dryRun bool) (Diff, error)
}

// AfterReverter is implemented by checks needing in-memory state restored after a revert.
type AfterReverter interface {
	AfterRevert(ctx context.Context) error
}

// ErrNoFix is returned by report-only checks.
var ErrNoFix = errors.New("this check is report-only: follow the remediation text")

// Env is what checks need from the host and the other services; func fields are test seams.
type Env struct {
	Ex            executor.Executor
	Settings      func(ctx context.Context) (map[string]string, error) // effective sshd settings
	SSHApply      func(ctx context.Context, set map[string]string) error
	Bruteforce    func() bool
	SetBruteforce func(on bool)
	Latest        func() *collector.Snapshot
	ExpectedPorts []int
	ConfigPath    string // agent config.yaml (IPS-BRUTEFORCE fix persists there)
}

var (
	regMu sync.Mutex
	reg   []func(*Env) Check
)

func register(f func(*Env) Check) {
	regMu.Lock()
	reg = append(reg, f)
	regMu.Unlock()
}

// All returns the built-in catalog sorted by ID.
func All(e *Env) []Check {
	regMu.Lock()
	defer regMu.Unlock()
	out := make([]Check, 0, len(reg))
	for _, f := range reg {
		out = append(out, f(e))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// base implements ID/Info and the report-only Fix.
type base struct {
	m Meta
	e *Env
}

func (b *base) ID() string                              { return b.m.ID }
func (b *base) Info() Meta                              { return b.m }
func (b *base) Fix(context.Context, bool) (Diff, error) { return Diff{}, ErrNoFix }

func (b *base) res(status, evidence string) Result {
	return Result{CheckID: b.m.ID, Status: status, Evidence: evidence}
}

// finish applies d unless dryRun.
func (b *base) finish(ctx context.Context, d Diff, dryRun bool) (Diff, error) {
	d.CheckID = b.m.ID
	if d.Text == "" {
		d.Text = d.Render()
	}
	if dryRun || d.Empty() {
		return d, nil
	}
	return d, Apply(ctx, b.e, d)
}

// ---- per-scan memo (keeps one sshd -T / firewall probe / fs walk per scan) ----

type memoKey struct{}

type memoVal struct {
	once sync.Once
	v    any
	err  error
}

type memoMap struct {
	mu sync.Mutex
	m  map[string]*memoVal
}

// WithMemo returns ctx carrying a fresh per-scan cache.
func WithMemo(ctx context.Context) context.Context {
	return context.WithValue(ctx, memoKey{}, &memoMap{m: map[string]*memoVal{}})
}

func memo[T any](ctx context.Context, key string, f func() (T, error)) (T, error) {
	mm, _ := ctx.Value(memoKey{}).(*memoMap)
	if mm == nil {
		return f()
	}
	mm.mu.Lock()
	v := mm.m[key]
	if v == nil {
		v = &memoVal{}
		mm.m[key] = v
	}
	mm.mu.Unlock()
	v.once.Do(func() { v.v, v.err = f() })
	t, _ := v.v.(T)
	return t, v.err
}

// ---- host helpers ----

func distro(ctx context.Context) hostfs.Distro {
	d, _ := memo(ctx, "distro", func() (hostfs.Distro, error) { return hostfs.DetectDistro(), nil })
	return d
}

// hasBin checks the usual binary dirs under hostfs.Root (no PATH lookup so fixtures stay hermetic).
func hasBin(name string) bool {
	for _, d := range []string{"/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/", "/usr/local/sbin/", "/usr/local/bin/"} {
		if hostfs.Exists(d + name) {
			return true
		}
	}
	return false
}

// pkgInstalled queries dpkg or rpm.
func pkgInstalled(ctx context.Context, e *Env, name string) bool {
	if distro(ctx).PkgMgr == "dnf" {
		_, err := e.Ex.Run(ctx, "rpm", "-q", name)
		return err == nil
	}
	out, err := e.Ex.Run(ctx, "dpkg-query", "-W", "-f=${Status}", name)
	return err == nil && strings.Contains(string(out), "install ok installed")
}

// installCmd returns the package install command for the distro.
func installCmd(ctx context.Context, pkg string) []string {
	if distro(ctx).PkgMgr == "dnf" {
		return []string{"dnf", "install", "-y", pkg}
	}
	return []string{"apt-get", "install", "-y", pkg}
}

// unitStates returns `systemctl is-active` per unit (one call for all units).
func unitStates(ctx context.Context, e *Env, units ...string) map[string]string {
	out, _ := e.Ex.Run(ctx, "systemctl", append([]string{"is-active"}, units...)...)
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	m := make(map[string]string, len(units))
	for i, u := range units {
		m[u] = "inactive"
		if i < len(lines) && strings.TrimSpace(lines[i]) != "" {
			m[u] = strings.TrimSpace(lines[i])
		}
	}
	return m
}

func active(ctx context.Context, e *Env, unit string) bool {
	return unitStates(ctx, e, unit)[unit] == "active"
}

func enabled(ctx context.Context, e *Env, unit string) bool {
	out, _ := e.Ex.Run(ctx, "systemctl", "is-enabled", unit)
	return strings.TrimSpace(string(out)) == "enabled"
}

// confFiles returns path plus *.conf files of its drop-in dir (sorted, as systemd/sysctl read them).
func confFiles(path, dropin string) []string {
	out := []string{path}
	ents, err := os.ReadDir(hostfs.P(dropin))
	if err != nil {
		return out
	}
	for _, en := range ents {
		if !en.IsDir() && strings.HasSuffix(en.Name(), ".conf") {
			out = append(out, dropin+"/"+en.Name())
		}
	}
	return out
}

// dirFiles lists regular files of a host dir.
func dirFiles(dir string) []string {
	ents, err := os.ReadDir(hostfs.P(dir))
	if err != nil {
		return nil
	}
	var out []string
	for _, en := range ents {
		if en.Type().IsRegular() {
			out = append(out, dir+"/"+en.Name())
		}
	}
	return out
}

// iniValue returns the last value of key (case-insensitive, "Key=Value") across files; later files win.
func iniValue(files []string, key string) string {
	v := ""
	for _, f := range files {
		lines, _ := hostfs.Lines(f)
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l == "" || l[0] == '#' || l[0] == ';' {
				continue
			}
			k, val, ok := strings.Cut(l, "=")
			if ok && strings.EqualFold(strings.TrimSpace(k), key) {
				v = strings.TrimSpace(val)
			}
		}
	}
	return v
}

func readFile(p string) (string, bool) {
	b, err := hostfs.Read(p)
	return string(b), err == nil
}

func fileMode(p string) (os.FileMode, bool) {
	st, err := os.Stat(hostfs.P(p))
	if err != nil {
		return 0, false
	}
	return st.Mode().Perm(), true
}

func cmd(a ...string) []string { return a }
