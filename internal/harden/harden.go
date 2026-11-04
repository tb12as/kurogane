// Package harden runs the hardening check library, scoring, fixes and reports (PRD §7).
package harden

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/tb12as/serverman/internal/alert"
	"github.com/tb12as/serverman/internal/audit"
	"github.com/tb12as/serverman/internal/certs"
	"github.com/tb12as/serverman/internal/collector"
	"github.com/tb12as/serverman/internal/config"
	"github.com/tb12as/serverman/internal/db"
	"github.com/tb12as/serverman/internal/executor"
	"github.com/tb12as/serverman/internal/firewall"
	"github.com/tb12as/serverman/internal/harden/checks"
	"github.com/tb12as/serverman/internal/sshmgr"
)

type Deps struct {
	Cfg      *config.Config
	DB       db.Store
	Ex       executor.Executor
	Audit    *audit.Logger
	SSH      *sshmgr.Manager
	Firewall *firewall.Manager
	Alerts   *alert.Engine
	ServerID string
	Latest   func() *collector.Snapshot
	Publish  func(event string, v any)
}

// ScanBudget is the total scan time limit (HD-1).
var ScanBudget = 30 * time.Second

const defaultSchedule = "0 3 * * *"

// ErrUnknownCheck is returned for check ids not in the catalog.
var ErrUnknownCheck = errors.New("unknown check id: list them with `serverkeeper harden checks`")

type Service struct {
	d    Deps
	cfg  *config.Config
	env  *checks.Env
	list []checks.Check
	byID map[string]checks.Check
	fire func(context.Context, alert.Event) // drift alerts (test seam)
	mu   sync.Mutex                         // serialises fixes and reverts
}

func New(d Deps) *Service {
	cfg := d.Cfg
	if cfg == nil {
		cfg = &config.Config{}
	}
	if d.ServerID == "" {
		d.ServerID = "local"
	}
	env := &checks.Env{Ex: d.Ex, Latest: d.Latest, ExpectedPorts: cfg.Harden.ExpectedPorts,
		ConfigPath: config.DefaultPath, SetBruteforce: func(on bool) { cfg.SSH.Bruteforce.Enabled = on },
		Certs:    certs.Options{Paths: cfg.Collector.Certs.Paths, Ports: cfg.Collector.Certs.ProbePorts},
		CertsOff: !cfg.Collector.Certs.Enabled, WebOff: !cfg.Web.Enabled}
	if d.SSH != nil {
		env.Settings = d.SSH.Settings
		env.Bruteforce = d.SSH.BruteforceActive
		env.SSHApply = func(ctx context.Context, set map[string]string) error {
			rb := cfg.SSH.RollbackTimeout
			if rb <= 0 {
				rb = 120 * time.Second
			}
			_, err := d.SSH.SafeApply(ctx, set, rb)
			return err
		}
	}
	s := &Service{d: d, cfg: cfg, env: env}
	if d.Alerts != nil {
		s.fire = d.Alerts.Fire
	}
	s.load()
	return s
}

// load builds the catalog: built-in checks plus YAML packs (HD-8).
func (s *Service) load() {
	s.list = checks.All(s.env)
	s.byID = map[string]checks.Check{}
	seen := map[string]bool{}
	for _, c := range s.list {
		s.byID[c.ID()] = c
		seen[c.ID()] = true
	}
	ps, err := checks.LoadPacks(s.env, s.cfg.Harden.Packs, seen)
	if err != nil {
		slog.Error("harden check pack skipped: fix the YAML and restart the agent", "err", err)
	}
	for _, c := range ps {
		s.list = append(s.list, c)
		s.byID[c.ID()] = c
	}
}

// Run schedules scans (HD-5, daily by default) until ctx is done.
func (s *Service) Run(ctx context.Context) {
	spec := s.cfg.Harden.Schedule
	if spec == "" {
		spec = defaultSchedule
	}
	c := cron.New()
	job := func() {
		if _, err := s.Scan(ctx); err != nil {
			slog.Error("scheduled hardening scan failed", "err", err)
		}
	}
	if _, err := c.AddFunc(spec, job); err != nil {
		slog.Error("invalid harden.schedule, using daily 03:00", "schedule", spec, "err", err)
		_, _ = c.AddFunc(defaultSchedule, job)
	}
	c.Start()
	<-ctx.Done()
	<-c.Stop().Done()
}

// Scan runs all checks (read-only) and stores the result (contract used by API, scheduler and central).
func (s *Service) Scan(ctx context.Context) (db.Scan, error) {
	start := time.Now()
	res := s.run(ctx, s.list)
	ign, _ := s.ignoreMap(ctx)
	for i := range res {
		if r, ok := ign[res[i].CheckID]; ok {
			res[i].Status, res[i].IgnoreReason = checks.Ignored, r
		}
	}
	score, grade := Score(res)
	prev := s.previous(ctx)
	b, err := json.Marshal(res)
	if err != nil {
		return db.Scan{}, err
	}
	sc := db.Scan{ID: db.NewID(), ServerID: s.d.ServerID, StartedAt: start, FinishedAt: time.Now(), Score: score,
		Grade: grade, Results: b}
	if err := s.d.DB.SaveScan(ctx, sc); err != nil {
		return sc, fmt.Errorf("save scan: %w", err)
	}
	s.drift(ctx, prev, res)
	s.publish(map[string]any{"type": "scan", "id": sc.ID, "score": score, "grade": grade})
	return sc, nil
}

// run executes checks concurrently within ScanBudget and fills metadata.
func (s *Service) run(ctx context.Context, cs []checks.Check) []checks.Result {
	ctx, cancel := context.WithTimeout(checks.WithMemo(ctx), ScanBudget)
	defer cancel()
	type item struct {
		i int
		r checks.Result
	}
	ch := make(chan item, len(cs))
	sem := make(chan struct{}, 8)
	for i, c := range cs {
		go func() {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			ch <- item{i, safeRun(ctx, c)}
		}()
	}
	out := make([]checks.Result, len(cs))
	got := make([]bool, len(cs))
	for n := 0; n < len(cs); n++ {
		select {
		case it := <-ch:
			out[it.i], got[it.i] = it.r, true
		case <-ctx.Done():
			n = len(cs)
		}
	}
	for i, c := range cs {
		if !got[i] {
			out[i] = checks.Result{Status: checks.Error, Evidence: fmt.Sprintf("did not finish within the %s scan "+
				"budget", ScanBudget)}
		}
		out[i].CheckID = c.ID()
		fill(&out[i], c.Info())
	}
	return out
}

func safeRun(ctx context.Context, c checks.Check) (r checks.Result) {
	defer func() {
		if p := recover(); p != nil {
			r = checks.Result{Status: checks.Error, Evidence: fmt.Sprintf("check panicked: %v", p)}
		}
	}()
	return c.Run(ctx)
}

func fill(r *checks.Result, m checks.Meta) {
	r.Title, r.Category, r.Severity, r.CIS = m.Title, m.Category, m.Severity, m.CIS
	r.Rationale, r.Remediation, r.AutoFix = m.Rationale, m.Remediation, m.AutoFix
}

// Score is 100 × weighted passed / weighted applicable; N/A, ignored and errored checks are excluded (§7.2).
func Score(rs []checks.Result) (float64, string) {
	var pass, all float64
	for _, r := range rs {
		if r.Status != checks.Pass && r.Status != checks.Fail {
			continue
		}
		w := checks.Weight(r.Severity)
		all += w
		if r.Status == checks.Pass {
			pass += w
		}
	}
	score := 100.0
	if all > 0 {
		score = math.Round(1000*pass/all) / 10
	}
	return score, Grade(score)
}

// Grade maps a score to A ≥ 90, B ≥ 75, C ≥ 60, else D.
func Grade(score float64) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	}
	return "D"
}

// Results decodes a scan's per-check results.
func Results(sc db.Scan) []checks.Result {
	var rs []checks.Result
	_ = json.Unmarshal(sc.Results, &rs)
	return rs
}

// GetScan returns a scan by id, or the newest one for "latest".
func (s *Service) GetScan(ctx context.Context, id string) (db.Scan, error) {
	if id != "latest" {
		return s.d.DB.GetScan(ctx, id)
	}
	l, err := s.d.DB.ListScans(ctx, s.d.ServerID, 1)
	if err != nil {
		return db.Scan{}, err
	}
	if len(l) == 0 {
		return db.Scan{}, fmt.Errorf("%w: no scan yet, run `serverkeeper harden scan`", db.ErrNotFound)
	}
	return s.d.DB.GetScan(ctx, l[0].ID)
}

// ListScans returns recent scans (without results).
func (s *Service) ListScans(ctx context.Context, limit int) ([]db.Scan, error) {
	return s.d.DB.ListScans(ctx, s.d.ServerID, limit)
}

func (s *Service) previous(ctx context.Context) map[string]string {
	sc, err := s.GetScan(ctx, "latest")
	if err != nil {
		return nil
	}
	m := map[string]string{}
	for _, r := range Results(sc) {
		m[r.CheckID] = r.Status
	}
	return m
}

// drift fires "hardening_drift" when a previously passing check fails, and resolves it when it passes again.
func (s *Service) drift(ctx context.Context, prev map[string]string, res []checks.Result) {
	if s.fire == nil || prev == nil {
		return
	}
	for _, r := range res {
		was := prev[r.CheckID]
		ev := alert.Event{Rule: "hardening_drift", Severity: "warning", Labels: map[string]string{"check": r.CheckID},
			Title: "Hardening drift: " + r.CheckID, Text: r.Title + ": " + r.Evidence,
			Fields: map[string]string{"severity": r.Severity, "remediation": r.Remediation}}
		switch {
		case was == checks.Pass && r.Status == checks.Fail:
			s.fire(ctx, ev)
		case was == checks.Fail && r.Status == checks.Pass:
			ev.Resolve = true
			s.fire(ctx, ev)
		}
	}
}

func (s *Service) publish(v any) {
	if s.d.Publish != nil {
		s.d.Publish("harden", v)
	}
}
