package db

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStore(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sk.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("db mode %o", st.Mode().Perm())
	}

	if err := s.AppendAudit(ctx, AuditEntry{Actor: "root", Action: "ssh.key.add", Target: "deploy"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.w.ExecContext(ctx, "UPDATE audit SET actor='x'"); err == nil {
		t.Fatal("audit update must be blocked")
	}
	if _, err := s.w.ExecContext(ctx, "DELETE FROM audit"); err == nil {
		t.Fatal("recent audit delete must be blocked")
	}
	a, _ := s.ListAudit(ctx, AuditFilter{})
	if len(a) != 1 || a[0].Action != "ssh.key.add" {
		t.Fatal(a)
	}

	r := AlertRule{ID: "high_cpu", Expr: "cpu.total_pct > 90", For: 5 * time.Minute, Severity: "warning", Channels: []string{"ops"}, Enabled: true}
	s.UpsertRule(ctx, r)
	got, err := s.GetRule(ctx, "high_cpu")
	if err != nil || got.For != 5*time.Minute || got.Channels[0] != "ops" {
		t.Fatal(err, got)
	}

	s.SaveEvent(ctx, AlertEvent{ID: "e1", RuleID: "high_cpu", Fingerprint: "fp", State: "firing", Severity: "warning", StartedAt: time.Now()})
	if e, err := s.OpenEvent(ctx, "fp"); err != nil || e.ID != "e1" {
		t.Fatal(err)
	}

	now := time.Now()
	s.CreateEnrollToken(ctx, EnrollToken{Hash: "h", CreatedBy: "a", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if _, err := s.UseEnrollToken(ctx, "h", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UseEnrollToken(ctx, "h", now); err == nil {
		t.Fatal("enroll token reuse must fail")
	}
	if err := s.SetIgnore(ctx, Ignore{CheckID: "X", Reason: " "}); err == nil {
		t.Fatal("empty ignore reason must fail")
	}
	if err := s.VacuumInto(ctx, filepath.Join(t.TempDir(), "b.db")); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSiteChange(ctx, SiteChange{ID: "c1", Actor: "admin", SiteID: "nginx:/x#0", SiteName: "x", Kind: "nginx",
		Action: "disable", Ops: "unlink /x", Status: "applying", TS: now}); err != nil {
		t.Fatal(err)
	}
	s.SaveSiteChange(ctx, SiteChange{ID: "c1", Status: "applied", Actor: "admin", SiteID: "nginx:/x#0", SiteName: "x",
		Kind: "nginx", Action: "disable", TS: now})
	if cs, err := s.ListSiteChanges(ctx, 0); err != nil || len(cs) != 1 || cs[0].Status != "applied" || cs[0].Ops != "unlink /x" {
		t.Fatalf("site changes = %+v %v", cs, err)
	}
	// later migrations roll back one at a time; the initial schema never does
	for {
		if err := s.MigrateDown(); err != nil {
			break
		}
	}
	if _, err := s.ListSiteChanges(ctx, 0); err == nil {
		t.Fatal("site_changes survived its migration rollback")
	}
	if err := s.MigrateDown(); err == nil {
		t.Fatal("initial schema must not be rolled back")
	}
}
