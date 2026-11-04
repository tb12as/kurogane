package harden

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/tb12as/kurogane/internal/audit"
	"github.com/tb12as/kurogane/internal/db"
	"github.com/tb12as/kurogane/internal/harden/checks"
)

// CheckInfo is a catalog entry with its ignore state.
type CheckInfo struct {
	checks.Meta
	Fixable      bool   `json:"fixable"`
	Ignored      bool   `json:"ignored"`
	IgnoreReason string `json:"ignore_reason,omitempty"`
}

// Checks returns the catalog (built-in and YAML packs).
func (s *Service) Checks(ctx context.Context) []CheckInfo {
	ign, _ := s.ignoreMap(ctx)
	out := make([]CheckInfo, 0, len(s.list))
	for _, c := range s.list {
		m := c.Info()
		r, ok := ign[m.ID]
		out = append(out, CheckInfo{Meta: m, Fixable: m.AutoFix != checks.FixReport, Ignored: ok, IgnoreReason: r})
	}
	return out
}

// Ignores merges config.yaml (harden.ignore) and API-created ignores; the database wins on conflict.
func (s *Service) Ignores(ctx context.Context) ([]db.Ignore, error) {
	var out []db.Ignore
	seen := map[string]bool{}
	l, err := s.d.DB.ListIgnores(ctx, s.d.ServerID)
	for _, ig := range l {
		seen[ig.CheckID] = true
		out = append(out, ig)
	}
	for _, ig := range s.cfg.Harden.Ignore {
		if !seen[ig.ID] {
			out = append(out, db.Ignore{ServerID: s.d.ServerID, CheckID: ig.ID, Reason: ig.Reason, CreatedBy: "config.yaml"})
		}
	}
	return out, err
}

func (s *Service) ignoreMap(ctx context.Context) (map[string]string, error) {
	l, err := s.Ignores(ctx)
	m := make(map[string]string, len(l))
	for _, ig := range l {
		m[ig.CheckID] = ig.Reason
	}
	return m, err
}

// Ignore accepts the risk of a check (HD-6); the reason is mandatory.
func (s *Service) Ignore(ctx context.Context, checkID, reason string) (db.Ignore, error) {
	if s.byID[checkID] == nil {
		return db.Ignore{}, fmt.Errorf("%w (%q)", ErrUnknownCheck, checkID)
	}
	if strings.TrimSpace(reason) == "" {
		return db.Ignore{}, fmt.Errorf("a reason is mandatory: pass --reason \"why this risk is accepted\"")
	}
	ig := db.Ignore{ServerID: s.d.ServerID, CheckID: checkID, Reason: strings.TrimSpace(reason),
		CreatedBy: audit.From(ctx).Actor, CreatedAt: time.Now()}
	if err := s.d.DB.SetIgnore(ctx, ig); err != nil {
		return ig, err
	}
	s.d.Audit.Record(ctx, "harden.ignore", checkID, nil, map[string]string{"reason": ig.Reason})
	s.publish(map[string]any{"type": "ignore", "check_id": checkID})
	return ig, nil
}

// Unignore removes an API-created ignore; config.yaml ignores must be removed there.
func (s *Service) Unignore(ctx context.Context, checkID string) error {
	l, _ := s.d.DB.ListIgnores(ctx, s.d.ServerID)
	for _, ig := range l {
		if ig.CheckID != checkID {
			continue
		}
		if err := s.d.DB.DeleteIgnore(ctx, s.d.ServerID, checkID); err != nil {
			return err
		}
		s.d.Audit.Record(ctx, "harden.unignore", checkID, map[string]string{"reason": ig.Reason}, nil)
		s.publish(map[string]any{"type": "unignore", "check_id": checkID})
		return nil
	}
	for _, ig := range s.cfg.Harden.Ignore {
		if ig.ID == checkID {
			return fmt.Errorf("%s is ignored in config.yaml (harden.ignore): remove it there and restart the agent",
				checkID)
		}
	}
	return fmt.Errorf("%w: %s is not ignored", db.ErrNotFound, checkID)
}
