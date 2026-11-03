package sshmgr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tb12as/serverman/internal/alert"
	"github.com/tb12as/serverman/internal/audit"
	"github.com/tb12as/serverman/internal/db"
	"github.com/tb12as/serverman/internal/hostfs"
	"github.com/tb12as/serverman/internal/store"
)

const (
	DropIn        = "/etc/ssh/sshd_config.d/99-serverkeeper.conf"
	candidatePath = "/etc/ssh/sshd_config.sk-candidate"
	pendingBucket = "ssh_pending"
	pendingKey    = "current"
	backupRoot    = "/var/lib/serverkeeper/backups/ssh/"
)

// Pending is an applied, unconfirmed sshd change; persisted so the rollback survives restarts.
type Pending struct {
	Change  db.SSHChange       `json:"change"`
	Files   map[string]*string `json:"files"` // previous content, nil = did not exist
	Unit    string             `json:"unit"`
	Session string             `json:"session,omitempty"` // SSH_CONNECTION of the applier
}

// Plan is the dry-run result of a change (PRD §11.5).
type Plan struct {
	Set     map[string]string `json:"set"`
	Old     map[string]string `json:"old"`
	Diff    string            `json:"diff"`
	Mode    string            `json:"mode"` // drop-in | in-place
	Impact  []string          `json:"impact"`
	files   map[string][]byte
	newEff  map[string]string
	flat    string
	lineMap []string
}

var valueOK = regexp.MustCompile(`^[^\n\r#"]*$`)

// normalize maps keys to canonical sshd names and rejects unknown keywords.
func normalize(set map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range set {
		name, ok := allowedKeys[strings.ToLower(k)]
		if !ok {
			return nil, fmt.Errorf("sshd setting %q is not managed by ServerKeeper", k)
		}
		v = strings.TrimSpace(v)
		if v == "" || !valueOK.MatchString(v) {
			return nil, fmt.Errorf("invalid value %q for %s", v, name)
		}
		out[name] = v
	}
	if len(out) == 0 {
		return nil, errors.New("no settings given")
	}
	return out, nil
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// mainIncludesDropIn reports whether a global Include in the main config covers the drop-in path.
func mainIncludesDropIn(main []byte) bool {
	for _, raw := range strings.Split(string(main), "\n") {
		name, val := splitDirective(strings.TrimSpace(raw))
		switch strings.ToLower(name) {
		case "match":
			return false
		case "include":
			for _, pat := range strings.Fields(val) {
				if !path.IsAbs(pat) {
					pat = path.Join("/etc/ssh", pat)
				}
				if ok, _ := path.Match(pat, DropIn); ok {
					return true
				}
			}
		}
	}
	return false
}

// Plan computes the candidate files for set without touching the host.
func (m *Manager) Plan(ctx context.Context, set map[string]string) (*Plan, error) {
	set, err := normalize(set)
	if err != nil {
		return nil, err
	}
	cur, err := m.Settings(ctx)
	if err != nil {
		return nil, err
	}
	mainPath := m.d.Cfg.SSH.ConfigPath
	mainB, err := m.d.Ex.ReadFile(mainPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", mainPath, err)
	}
	p := &Plan{Set: set, Old: map[string]string{}, files: map[string][]byte{}}
	for k := range set {
		p.Old[k] = cur[strings.ToLower(k)]
	}
	if mainIncludesDropIn(mainB) {
		p.Mode = "drop-in"
		old, _ := m.d.Ex.ReadFile(DropIn)
		p.files[DropIn] = renderDropIn(old, set)
	} else {
		p.Mode = "in-place"
		p.files[mainPath] = editInPlace(mainB, set)
	}
	// first value wins: comment out earlier directives that would shadow ours
	for range 8 {
		ds, err := parseConfig(m.src(p.files), mainPath)
		if err != nil {
			return nil, err
		}
		eff := effective(ds)
		bad := false
		for k, v := range set {
			if strings.EqualFold(eff[strings.ToLower(k)], v) {
				continue
			}
			bad = true
			d := firstGlobal(ds, strings.ToLower(k))
			if d == nil {
				return nil, fmt.Errorf("cannot make %s effective", k)
			}
			if !strings.HasPrefix(d.File, "/etc/ssh/") {
				// shadowed by a file we must not edit (e.g. RHEL crypto-policies): put our settings at the top of the
				// main config, which sshd reads first, so first-value-wins picks them
				delete(p.files, DropIn)
				p.Mode = "in-place"
				p.files[mainPath] = prependMain(mainB, set)
				break
			}
			b, ok := p.files[d.File]
			if !ok {
				if b, err = m.d.Ex.ReadFile(d.File); err != nil {
					return nil, err
				}
			}
			lines := strings.Split(string(b), "\n")
			lines[d.Line-1] = "# disabled by serverkeeper (overrode " + k + "): " + lines[d.Line-1]
			p.files[d.File] = []byte(strings.Join(lines, "\n"))
		}
		if !bad {
			p.newEff = withDefaults(eff)
			p.flat, p.lineMap = flatten(ds)
			break
		}
	}
	if p.newEff == nil {
		return nil, errors.New("could not compute an sshd_config where the new settings take effect")
	}
	for _, f := range sortedFiles(p.files) {
		old, _ := m.d.Ex.ReadFile(f)
		p.Diff += Diff(f, string(old), string(p.files[f]))
	}
	p.Impact = impact(set, p.Old)
	return p, nil
}

func sortedFiles(m map[string][]byte) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func firstGlobal(ds []Directive, key string) *Directive {
	for i := range ds {
		if !ds[i].Match && ds[i].Key == key {
			return &ds[i]
		}
	}
	return nil
}

// renderDropIn merges set into the existing drop-in, keeping its other settings.
func renderDropIn(old []byte, set map[string]string) []byte {
	vals := map[string]string{}
	for _, raw := range strings.Split(string(old), "\n") {
		l := strings.TrimSpace(raw)
		if l == "" || l[0] == '#' {
			continue
		}
		n, v := splitDirective(l)
		if c, ok := allowedKeys[strings.ToLower(n)]; ok {
			vals[c] = v
		}
	}
	for k, v := range set {
		vals[k] = v
	}
	var b strings.Builder
	b.WriteString("# managed by serverkeeper: changes here are overwritten by `serverkeeper ssh config set`\n")
	for _, k := range sortedKeys(vals) {
		b.WriteString(k + " " + vals[k] + "\n")
	}
	return []byte(b.String())
}

// editInPlace replaces the first global occurrence of each key, or inserts it before the first Match block.
func editInPlace(main []byte, set map[string]string) []byte {
	lines := strings.Split(string(main), "\n")
	done := map[string]bool{}
	firstMatch := -1
	for i, raw := range lines {
		l := strings.TrimSpace(raw)
		if l == "" || l[0] == '#' {
			continue
		}
		n, _ := splitDirective(l)
		if strings.EqualFold(n, "match") {
			firstMatch = i
			break
		}
		if c, ok := allowedKeys[strings.ToLower(n)]; ok {
			if v, want := set[c]; want && !done[c] {
				lines[i] = c + " " + v
				done[c] = true
			}
		}
	}
	var add []string
	for _, k := range sortedKeys(set) {
		if !done[k] {
			add = append(add, k+" "+set[k])
		}
	}
	if len(add) == 0 {
		return []byte(strings.Join(lines, "\n"))
	}
	if firstMatch < 0 {
		for len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		lines = append(append(lines, add...), "")
	} else {
		lines = append(lines[:firstMatch], append(add, lines[firstMatch:]...)...)
	}
	return []byte(strings.Join(lines, "\n"))
}

// prependMain inserts set (replacing earlier copies of the same keys) before the first directive of main.
func prependMain(main []byte, set map[string]string) []byte {
	lines := strings.Split(string(main), "\n")
	at := len(lines)
	var kept []string
	for i, raw := range lines {
		l := strings.TrimSpace(raw)
		if l != "" && l[0] != '#' && at == len(lines) {
			at = i
		}
		n, _ := splitDirective(l)
		if _, mine := set[allowedKeys[strings.ToLower(n)]]; mine && i >= at && l != "" && l[0] != '#' {
			kept = append(kept, "# replaced by serverkeeper: "+raw)
			continue
		}
		kept = append(kept, raw)
	}
	head := []string{"# managed by serverkeeper (must precede Include so first-value-wins applies)"}
	for _, k := range sortedKeys(set) {
		head = append(head, k+" "+set[k])
	}
	if at > len(kept) {
		at = len(kept)
	}
	out := append(append(append([]string{}, kept[:at]...), head...), kept[at:]...)
	return []byte(strings.Join(out, "\n"))
}

// flatten writes all globals first, then each Match block, so `sshd -t` can validate the whole candidate in one
// file; lineMap maps candidate line numbers back to "file:line".
func flatten(ds []Directive) (string, []string) {
	var glob, match []Directive
	for _, d := range ds {
		if d.Match || d.Key == "match" {
			match = append(match, d)
		} else {
			glob = append(glob, d)
		}
	}
	var b strings.Builder
	lm := []string{""}
	for _, d := range append(glob, match...) {
		b.WriteString(d.Name + " " + d.Value + "\n")
		lm = append(lm, fmt.Sprintf("%s line %d", d.File, d.Line))
	}
	return b.String(), lm
}

var lineRe = regexp.MustCompile(`line (\d+)`)

// impact is the plain-language effect of a change (§11.5).
func impact(set, old map[string]string) []string {
	var out []string
	for _, k := range sortedKeys(set) {
		v := set[k]
		switch {
		case k == "PasswordAuthentication" && strings.EqualFold(v, "no"):
			out = append(out, "Password logins stop working; only SSH keys (or certificates) can log in.")
		case k == "PermitRootLogin" && strings.EqualFold(v, "no"):
			out = append(out, "root can no longer log in over SSH; use a sudo user.")
		case k == "Port":
			out = append(out, "sshd moves to port "+v+": open it in the firewall and provider security group first, "+
				"and connect with ssh -p "+v+".")
		case k == "AllowUsers" || k == "AllowGroups":
			out = append(out, "Only the listed users/groups can log in ("+v+").")
		case k == "Ciphers" || k == "KexAlgorithms" || k == "MACs":
			out = append(out, "Very old SSH clients without modern algorithms will fail to connect.")
		default:
			out = append(out, fmt.Sprintf("%s changes from %q to %q.", k, old[k], v))
		}
	}
	return append(out, "Existing sessions stay open; sshd is reloaded, not restarted.")
}

// SafeApply validates, backs up, applies (drop-in or in-place), reloads and starts the rollback timer (SSH-3).
func (m *Manager) SafeApply(ctx context.Context, set map[string]string, rollback time.Duration) (db.SSHChange, error) {
	return m.SafeApplyFrom(ctx, set, rollback, "")
}

// SafeApplyFrom is SafeApply recording the applier's SSH_CONNECTION so confirmation must come from a new session.
func (m *Manager) SafeApplyFrom(ctx context.Context, set map[string]string, rollback time.Duration, session string) (db.SSHChange, error) {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	if p, ok := m.pending(); ok {
		return db.SSHChange{}, fmt.Errorf("sshd change %s is waiting for confirmation until %s: run `serverkeeper ssh "+
			"confirm` from a new SSH session, or wait for the automatic rollback", p.Change.ID,
			p.Change.Deadline.Format("15:04:05"))
	}
	if rollback <= 0 {
		rollback = m.d.Cfg.SSH.RollbackTimeout
	}
	if rollback <= 0 {
		rollback = 120 * time.Second
	}
	plan, err := m.Plan(ctx, set)
	if err != nil {
		return db.SSHChange{}, err
	}
	cur, err := m.Settings(ctx)
	if err != nil {
		return db.SSHChange{}, err
	}
	if err := m.guard(ctx, cur, plan.newEff); err != nil {
		return db.SSHChange{}, err
	}
	// 1. validate the full candidate with sshd -t
	if err := m.validate(ctx, plan); err != nil {
		return db.SSHChange{}, err
	}
	// 2. timestamped backup
	id := db.NewID()
	bdir := backupRoot + m.now().Format("20060102T150405") + "-" + id
	p := Pending{Files: map[string]*string{}, Unit: m.sshUnit(), Session: session}
	for f := range plan.files {
		b, err := m.d.Ex.ReadFile(f)
		switch {
		case err == nil:
			s := string(b)
			p.Files[f] = &s
			if err := m.d.Ex.WriteFile(bdir+"/"+strings.ReplaceAll(strings.TrimPrefix(f, "/"), "/", "_"), b, 0o600); err != nil {
				return db.SSHChange{}, fmt.Errorf("backup %s: %w", f, err)
			}
		case errors.Is(err, os.ErrNotExist):
			p.Files[f] = nil
		default:
			return db.SSHChange{}, err
		}
	}
	manifest, _ := json.MarshalIndent(p.Files, "", "  ")
	if err := m.d.Ex.WriteFile(bdir+"/manifest.json", manifest, 0o600); err != nil {
		return db.SSHChange{}, fmt.Errorf("backup manifest: %w", err)
	}
	// 3. apply and reload (not restart)
	for _, f := range sortedFiles(plan.files) {
		if err := m.d.Ex.WriteFile(f, plan.files[f], 0o600); err != nil {
			m.restore(ctx, p)
			return db.SSHChange{}, fmt.Errorf("write %s: %w (previous config restored)", f, err)
		}
	}
	if err := m.reload(ctx, p.Unit); err != nil {
		m.restore(ctx, p)
		_ = m.reload(ctx, p.Unit)
		return db.SSHChange{}, fmt.Errorf("reload sshd: %w (previous config restored)", err)
	}
	if eff, err := m.Settings(ctx); err == nil {
		for k, v := range plan.Set {
			if got := eff[strings.ToLower(k)]; !strings.EqualFold(got, v) && !equivalent(k, got, v) {
				m.restore(ctx, p)
				_ = m.reload(ctx, p.Unit)
				return db.SSHChange{}, fmt.Errorf("after reload sshd reports %s %q, not %q (previous config restored)", k, got, v)
			}
		}
	}
	// 4. rollback timer
	keys := sortedKeys(plan.Set)
	ch := db.SSHChange{ID: id, ServerID: m.d.ServerID, Actor: audit.From(ctx).Actor, Setting: strings.Join(keys, ","),
		Status: "pending", TS: m.now(), Deadline: m.now().Add(rollback), BackupPath: bdir}
	if len(keys) == 1 {
		ch.OldValue, ch.NewValue = plan.Old[keys[0]], plan.Set[keys[0]]
	} else {
		ob, _ := json.Marshal(plan.Old)
		nb, _ := json.Marshal(plan.Set)
		ch.OldValue, ch.NewValue = string(ob), string(nb)
	}
	p.Change = ch
	if err := m.d.Store.Put(pendingBucket, pendingKey, p); err != nil {
		m.restore(ctx, p)
		_ = m.reload(ctx, p.Unit)
		return db.SSHChange{}, fmt.Errorf("persist pending change: %w (previous config restored)", err)
	}
	_ = m.d.DB.SaveSSHChange(ctx, ch)
	m.d.Audit.Record(ctx, "ssh.config.apply", ch.Setting, plan.Old, plan.Set)
	m.fire(ctx, alert.Event{Rule: "ssh_config_changed", Severity: "info", Once: true,
		Text: fmt.Sprintf("%s changed %s (%s). Rollback at %s unless confirmed.", ch.Actor, ch.Setting, plan.Mode,
			ch.Deadline.Format("15:04:05")), Fields: map[string]string{"Change": id}})
	m.publish("ssh", ch)
	m.startTimer(p)
	return ch, nil
}

// equivalent treats sshd -T spellings as equal (without-password == prohibit-password).
func equivalent(k, a, b string) bool {
	norm := func(s string) string {
		s = strings.ToLower(s)
		if s == "without-password" {
			return "prohibit-password"
		}
		return strings.ReplaceAll(s, " ", ",")
	}
	return norm(a) == norm(b)
}

func (m *Manager) validate(ctx context.Context, p *Plan) error {
	if !hostfs.HasBinary("sshd") && hostfs.Root == "/" {
		return errors.New("sshd binary not found: install openssh-server before changing its config")
	}
	if err := m.d.Ex.WriteFile(candidatePath, []byte(p.flat), 0o600); err != nil {
		return fmt.Errorf("write candidate: %w", err)
	}
	defer m.d.Ex.Remove(candidatePath)
	_, err := m.d.Ex.Run(ctx, "sshd", "-t", "-f", candidatePath)
	if err == nil {
		return nil
	}
	msg := lineRe.ReplaceAllStringFunc(err.Error(), func(s string) string {
		n, _ := strconv.Atoi(lineRe.FindStringSubmatch(s)[1])
		if n > 0 && n < len(p.lineMap) {
			return p.lineMap[n]
		}
		return s
	})
	msg = strings.ReplaceAll(strings.TrimPrefix(msg, "sshd -t -f "+candidatePath+" failed: "), candidatePath+" ", "")
	msg = strings.TrimPrefix(msg, "sshd failed: ")
	return fmt.Errorf("sshd -t rejected the new config: %s (nothing was changed)", msg)
}

func (m *Manager) sshUnit() string {
	if hostfs.DetectDistro().Family == "debian" {
		return "ssh"
	}
	return "sshd"
}

func (m *Manager) reload(ctx context.Context, unit string) error {
	_, err := m.d.Ex.Run(ctx, "systemctl", "reload", unit)
	return err
}

func (m *Manager) restore(ctx context.Context, p Pending) {
	for f, c := range p.Files {
		var err error
		if c == nil {
			err = m.d.Ex.Remove(f)
		} else {
			err = m.d.Ex.WriteFile(f, []byte(*c), 0o600)
		}
		if err != nil {
			slog.Error("ssh restore failed", "file", f, "err", err)
		}
	}
}

func (m *Manager) pending() (Pending, bool) {
	var p Pending
	if m.d.Store == nil || m.d.Store.Get(pendingBucket, pendingKey, &p) != nil {
		return p, false
	}
	return p, true
}

// PendingChange returns the change awaiting confirmation, if any.
func (m *Manager) PendingChange() (*db.SSHChange, bool) {
	p, ok := m.pending()
	if !ok {
		return nil, false
	}
	return &p.Change, true
}

func (m *Manager) startTimer(p Pending) {
	go func() {
		t := time.NewTimer(time.Until(p.Change.Deadline))
		defer t.Stop()
		for {
			select {
			case id := <-m.confirm:
				if id == p.Change.ID {
					return
				}
			case <-t.C:
				m.rollback(context.Background(), p.Change.ID, "no confirmation before "+p.Change.Deadline.Format("15:04:05"))
				return
			}
		}
	}()
}

// Confirm keeps the pending change. session is the confirmer's SSH_CONNECTION ("" from the UI).
func (m *Manager) Confirm(ctx context.Context, session string) (db.SSHChange, error) {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	p, ok := m.pending()
	if !ok {
		return db.SSHChange{}, errors.New("no sshd change is pending confirmation")
	}
	if session != "" && p.Session != "" && session == p.Session {
		return db.SSHChange{}, errors.New("confirm from a NEW SSH session: that proves logins still work with the " +
			"new config (this is the session that applied the change)")
	}
	if err := m.d.Store.Delete(pendingBucket, pendingKey); err != nil {
		return db.SSHChange{}, err
	}
	p.Change.Status = "confirmed"
	_ = m.d.DB.SaveSSHChange(ctx, p.Change)
	m.d.Audit.Record(ctx, "ssh.config.confirm", p.Change.ID, nil, map[string]string{"setting": p.Change.Setting})
	select {
	case m.confirm <- p.Change.ID:
	default:
	}
	m.publish("ssh", p.Change)
	return p.Change, nil
}

// rollback restores the backup, reloads sshd and alerts (SSH-3 step 5).
func (m *Manager) rollback(ctx context.Context, id, reason string) {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	p, ok := m.pending()
	if !ok || p.Change.ID != id {
		return
	}
	m.restore(ctx, p)
	err := m.reload(ctx, p.Unit)
	p.Change.Status = "rolled_back"
	_ = m.d.DB.SaveSSHChange(ctx, p.Change)
	_ = m.d.Store.Delete(pendingBucket, pendingKey)
	actx := audit.WithActor(ctx, "system:rollback", "")
	m.d.Audit.Record(actx, "ssh.config.rollback", id, p.Change.NewValue, p.Change.OldValue)
	text := fmt.Sprintf("sshd change %s (%s) was rolled back: %s.", id, p.Change.Setting, reason)
	if err != nil {
		text += " Reload failed: " + err.Error() + " - check sshd on the console."
	}
	m.fire(ctx, alert.Event{Rule: "ssh_rolled_back", Severity: "critical", Once: true, Text: text})
	m.publish("ssh", p.Change)
	slog.Warn("ssh change rolled back", "id", id, "reason", reason)
}

// resume restarts the timer of a change pending before an agent restart, or rolls back if it expired.
func (m *Manager) resume(ctx context.Context) {
	p, ok := m.pending()
	if !ok {
		return
	}
	if !m.now().Before(p.Change.Deadline) {
		m.rollback(ctx, p.Change.ID, "deadline passed while the agent was not running")
		return
	}
	m.startTimer(p)
}

// Changes lists sshd change history.
func (m *Manager) Changes(ctx context.Context) ([]db.SSHChange, error) {
	return m.d.DB.ListSSHChanges(ctx, 100)
}

var _ = store.ErrNotFound
