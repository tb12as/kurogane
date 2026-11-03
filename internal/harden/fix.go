package harden

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tb12as/serverman/internal/audit"
	"github.com/tb12as/serverman/internal/db"
	"github.com/tb12as/serverman/internal/harden/checks"
	"github.com/tb12as/serverman/internal/hostfs"
)

// BackupRoot holds one directory per fix with file copies and a manifest (HD-3).
const BackupRoot = "/var/lib/serverkeeper/backups/harden/"

// FixResult is a dry-run diff or an applied fix with its verification.
type FixResult struct {
	CheckID string         `json:"check_id"`
	DryRun  bool           `json:"dry_run"`
	Diff    checks.Diff    `json:"diff"`
	Fix     *db.Fix        `json:"fix,omitempty"`
	Verify  *checks.Result `json:"verify,omitempty"`
	Skipped string         `json:"skipped,omitempty"`
	Error   string         `json:"error,omitempty"`
}

type backupFile struct {
	Path    string      `json:"path"`
	Existed bool        `json:"existed"`
	Mode    os.FileMode `json:"mode"`
	Copy    string      `json:"copy,omitempty"`
}

type manifest struct {
	FixID   string       `json:"fix_id"`
	CheckID string       `json:"check_id"`
	Created time.Time    `json:"created"`
	Diff    checks.Diff  `json:"diff"`
	Files   []backupFile `json:"files"`
}

// Fix shows the dry-run diff, or backs up, applies, re-runs the check and records the fix.
func (s *Service) Fix(ctx context.Context, checkID string, dryRun bool) (FixResult, error) {
	c := s.byID[checkID]
	if c == nil {
		return FixResult{}, fmt.Errorf("%w (%q)", ErrUnknownCheck, checkID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	d, err := c.Fix(checks.WithMemo(ctx), true)
	if err != nil {
		return FixResult{}, fmt.Errorf("%s: %w", checkID, err)
	}
	res := FixResult{CheckID: checkID, DryRun: dryRun, Diff: d}
	if d.Empty() {
		res.Skipped = "nothing to change"
		return res, nil
	}
	if dryRun {
		return res, nil
	}

	f := db.Fix{ID: db.NewID(), ServerID: s.d.ServerID, CheckID: checkID, Diff: d.Text,
		AppliedBy: audit.From(ctx).Actor, AppliedAt: time.Now(), Status: "applied"}
	f.BackupPath = BackupRoot + f.ID
	if err := s.backup(f, d); err != nil {
		return res, fmt.Errorf("backup failed, nothing was changed: %w", err)
	}
	if _, err := c.Fix(checks.WithMemo(ctx), false); err != nil {
		f.Status = "failed"
		_ = s.d.DB.SaveFix(ctx, f)
		s.d.Audit.Record(ctx, "harden.fix", checkID, nil, map[string]string{"fix_id": f.ID, "error": err.Error()})
		res.Fix = &f
		return res, fmt.Errorf("%s fix failed (may be partly applied; undo with `serverkeeper harden revert %s`): %w",
			checkID, f.ID, err)
	}
	v := safeRun(checks.WithMemo(ctx), c)
	v.CheckID = checkID
	fill(&v, c.Info())
	if v.Status != checks.Pass {
		f.Status = "applied_unverified"
	}
	if err := s.d.DB.SaveFix(ctx, f); err != nil {
		return res, fmt.Errorf("fix %s applied but not recorded: %w", f.ID, err)
	}
	s.d.Audit.Record(ctx, "harden.fix", checkID, nil, map[string]string{"fix_id": f.ID, "diff": d.Text})
	s.publish(map[string]any{"type": "fix", "id": f.ID, "check_id": checkID, "verify": v.Status})
	res.Fix, res.Verify = &f, &v
	return res, nil
}

// FixAll fixes every failing, non-ignored, fixable check at or above severity ("" = all).
// Firewall fixes are skipped: they need an explicit `harden fix <id>`.
func (s *Service) FixAll(ctx context.Context, severity string, dryRun bool) ([]FixResult, error) {
	min := 0
	if severity != "" {
		if min = checks.Rank(strings.ToLower(severity)); min == 0 {
			return nil, fmt.Errorf("invalid severity %q: use critical, high, medium or low", severity)
		}
	}
	ign, _ := s.ignoreMap(ctx)
	var todo []checks.Check
	for _, c := range s.list {
		m := c.Info()
		if m.AutoFix != checks.FixReport && checks.Rank(m.Severity) >= min && ign[m.ID] == "" {
			todo = append(todo, c)
		}
	}
	var out []FixResult
	for _, r := range s.run(ctx, todo) {
		if r.Status != checks.Fail {
			continue
		}
		if r.AutoFix == checks.FixConfirm {
			out = append(out, FixResult{CheckID: r.CheckID, DryRun: dryRun,
				Skipped: "firewall change: apply it explicitly with `serverkeeper harden fix " + r.CheckID + "`"})
			continue
		}
		fr, err := s.Fix(ctx, r.CheckID, dryRun)
		if err != nil {
			fr.CheckID, fr.Error = r.CheckID, err.Error()
		}
		out = append(out, fr)
	}
	return out, nil
}

// ListFixes returns recent fixes.
func (s *Service) ListFixes(ctx context.Context, limit int) ([]db.Fix, error) {
	return s.d.DB.ListFixes(ctx, s.d.ServerID, limit)
}

func (s *Service) backup(f db.Fix, d checks.Diff) error {
	m := manifest{FixID: f.ID, CheckID: f.CheckID, Created: f.AppliedAt, Diff: d}
	paths := d.Backup
	for _, fe := range d.Files {
		paths = append(paths, fe.Path)
	}
	for _, p := range paths {
		bf := backupFile{Path: p}
		if st, err := os.Stat(hostfs.P(p)); err == nil {
			b, err := s.d.Ex.ReadFile(p)
			if err != nil {
				return err
			}
			bf.Existed, bf.Mode, bf.Copy = true, st.Mode().Perm(), f.BackupPath+"/files"+p
			if err := s.d.Ex.WriteFile(bf.Copy, b, 0o600); err != nil {
				return err
			}
		}
		m.Files = append(m.Files, bf)
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	return s.d.Ex.WriteFile(f.BackupPath+"/manifest.json", b, 0o600)
}

// Revert restores a fix's backup, re-applies kernel/sshd/service state and marks it reverted.
func (s *Service) Revert(ctx context.Context, fixID string) (db.Fix, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.d.DB.GetFix(ctx, fixID)
	if err != nil {
		return f, fmt.Errorf("fix %s: %w (list fixes with `serverkeeper harden fixes`)", fixID, err)
	}
	if !f.RevertedAt.IsZero() {
		return f, fmt.Errorf("fix %s was already reverted at %s", fixID, f.RevertedAt.Format(time.RFC3339))
	}
	raw, err := s.d.Ex.ReadFile(f.BackupPath + "/manifest.json")
	if err != nil {
		return f, fmt.Errorf("backup manifest missing in %s: %w", f.BackupPath, err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return f, fmt.Errorf("backup manifest unreadable: %w", err)
	}
	if err := s.restore(ctx, m); err != nil {
		return f, fmt.Errorf("revert %s: %w", fixID, err)
	}
	if c, ok := s.byID[f.CheckID].(checks.AfterReverter); ok {
		if err := c.AfterRevert(ctx); err != nil {
			return f, err
		}
	}
	f.RevertedAt, f.Status = time.Now(), "reverted"
	if err := s.d.DB.SaveFix(ctx, f); err != nil {
		return f, err
	}
	s.d.Audit.Record(ctx, "harden.revert", f.CheckID, map[string]string{"fix_id": f.ID}, nil)
	s.publish(map[string]any{"type": "revert", "id": f.ID, "check_id": f.CheckID})
	return f, nil
}

func (s *Service) restore(ctx context.Context, m manifest) error {
	ex := s.d.Ex
	for _, bf := range m.Files {
		var old []byte
		if bf.Existed {
			b, err := ex.ReadFile(bf.Copy)
			if err != nil {
				return fmt.Errorf("backup copy of %s missing: %w", bf.Path, err)
			}
			old = b
		}
		// the sysctl drop-in is shared by several fixes: undo only this fix's keys
		if bf.Path == checks.SysctlFile && len(m.Diff.Sysctl) > 0 {
			cur, _ := ex.ReadFile(bf.Path)
			prev := sysctlKV(string(old))
			set, del := map[string]string{}, []string{}
			for k := range m.Diff.Sysctl {
				if v, ok := prev[k]; ok {
					set[k] = v
				} else {
					del = append(del, k)
				}
			}
			nw := checks.SysctlEdit(string(cur), set, del)
			if strings.TrimSpace(stripComments(nw)) == "" && !bf.Existed {
				if err := ex.Remove(bf.Path); err != nil {
					return err
				}
				continue
			}
			if err := ex.WriteFile(bf.Path, []byte(nw), 0o644); err != nil {
				return err
			}
			continue
		}
		var err error
		if bf.Existed {
			err = ex.WriteFile(bf.Path, old, bf.Mode)
		} else {
			err = ex.Remove(bf.Path)
		}
		if err != nil {
			return err
		}
	}
	for _, me := range m.Diff.Modes {
		if err := ex.Chmod(me.Path, me.Old); err != nil {
			return err
		}
	}
	if len(m.Diff.SSHOld) > 0 {
		old := map[string]string{}
		for k, v := range m.Diff.SSHOld {
			if v != "" {
				old[k] = v
			}
		}
		if s.env.SSHApply == nil {
			return errors.New("SSH manager unavailable: cannot restore sshd settings")
		}
		if err := s.env.SSHApply(ctx, old); err != nil {
			return fmt.Errorf("ssh safe-apply: %w", err)
		}
	}
	return checks.RunCmds(ctx, s.env, m.Diff.Undo)
}

func sysctlKV(s string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(l, "=")
		if k = strings.TrimSpace(k); ok && !strings.HasPrefix(k, "#") {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

func stripComments(s string) string {
	var b strings.Builder
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" && t[0] != '#' {
			b.WriteString(t + "\n")
		}
	}
	return b.String()
}
