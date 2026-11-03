// Package agent wires the single-server agent: collectors, stores, alerts, SSH, hardening and API.
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/tb12as/serverman/internal/alert"
	"github.com/tb12as/serverman/internal/api"
	"github.com/tb12as/serverman/internal/audit"
	"github.com/tb12as/serverman/internal/auth"
	"github.com/tb12as/serverman/internal/collector"
	"github.com/tb12as/serverman/internal/config"
	"github.com/tb12as/serverman/internal/db"
	"github.com/tb12as/serverman/internal/executor"
	"github.com/tb12as/serverman/internal/firewall"
	"github.com/tb12as/serverman/internal/harden"
	"github.com/tb12as/serverman/internal/secret"
	"github.com/tb12as/serverman/internal/sshmgr"
	"github.com/tb12as/serverman/internal/store"
	"github.com/tb12as/serverman/web"
)

// Agent holds all running components.
type Agent struct {
	Cfg      *config.Config
	Ex       executor.Executor
	Store    *store.Store
	DB       *db.SQLite
	Box      *secret.Box
	Auth     *auth.Service
	Audit    *audit.Logger
	Firewall *firewall.Manager
	Alerts   *alert.Engine
	SSH      *sshmgr.Manager
	Harden   *harden.Service
	Metrics  *collector.Manager
	API      *api.Server
	Hub      *api.Hub
	Version  string

	// OnSnapshot hooks (e.g. central link) receive every collection.
	OnSnapshot []func(*collector.Snapshot)
	// Extra goroutines started with the agent (e.g. central link).
	Extra []func(ctx context.Context)
}

// Hooks lets optional subsystems (agentlink) attach to a built agent before Run.
var Hooks []func(a *Agent) error

// New builds the agent with executor ex.
func New(cfg *config.Config, ex executor.Executor, version string) (*Agent, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir %s: %w (run as root or set data_dir)", cfg.DataDir, err)
	}
	a := &Agent{Cfg: cfg, Ex: ex, Version: version, Hub: api.NewHub()}
	var err error
	if a.Box, err = secret.LoadOrCreate(cfg.SecretKey); err != nil {
		return nil, err
	}
	if a.Store, err = store.Open(cfg.AgentDB()); err != nil {
		return nil, fmt.Errorf("open %s: %w (is another agent running?)", cfg.AgentDB(), err)
	}
	if a.DB, err = db.Open(cfg.MetaDB()); err != nil {
		return nil, err
	}
	a.Audit = &audit.Logger{Store: a.DB, ServerID: "local"}
	a.Auth = auth.NewService(a.DB, a.Box, cfg.Auth.SessionTTL)
	if o, err := auth.NewOIDC(context.Background(), cfg.Auth.OIDC); err != nil {
		slog.Warn("oidc disabled", "err", err)
	} else {
		a.Auth.OIDC = o
	}
	a.Firewall = firewall.New(ex)
	if a.Alerts, err = alert.NewEngine(alert.Deps{Cfg: cfg, DB: a.DB, Store: a.Store, Box: a.Box, Audit: a.Audit,
		Firewall: a.Firewall, ServerID: cfg.ServerName, Publish: a.Hub.Publish}); err != nil {
		return nil, err
	}
	a.SSH = sshmgr.New(sshmgr.Deps{Cfg: cfg, DB: a.DB, Store: a.Store, Ex: ex, Audit: a.Audit, Alerts: a.Alerts,
		Firewall: a.Firewall, ServerID: "local", Publish: a.Hub.Publish})
	a.Metrics = collector.NewManager(cfg.Collector, ex)
	a.Metrics.StoreSize = a.Store.Size
	a.Harden = harden.New(harden.Deps{Cfg: cfg, DB: a.DB, Ex: ex, Audit: a.Audit, SSH: a.SSH, Firewall: a.Firewall,
		Alerts: a.Alerts, ServerID: "local", Latest: a.Metrics.Latest, Publish: a.Hub.Publish})
	a.API = &api.Server{Cfg: cfg, DB: a.DB, Store: a.Store, Auth: a.Auth, Audit: a.Audit, Box: a.Box, Ex: ex,
		Metrics: a.Metrics, Alerts: a.Alerts, SSH: a.SSH, Harden: a.Harden, Firewall: a.Firewall, Hub: a.Hub,
		UI: web.FS(), Version: version}
	for _, h := range Hooks {
		if err := h(a); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// CLITokenPath is where the local admin token for the CLI is kept (0600).
func CLITokenPath(cfg *config.Config) string { return cfg.DataDir + "/cli.token" }

func (a *Agent) ensureCLIToken(ctx context.Context) error {
	p := CLITokenPath(a.Cfg)
	old, _ := os.ReadFile(p)
	tok, err := a.Auth.EnsureLocalToken(ctx, strings.TrimSpace(string(old)))
	if err != nil {
		return err
	}
	return os.WriteFile(p, []byte(tok+"\n"), 0o600) // #nosec G703 -- path comes from the root-owned config
}

// Run starts every component and blocks until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if os.Getenv("GOMEMLIMIT") == "" {
		// soft limit: GC earlier instead of growing the heap (PRD §11.2: agent RSS < 50 MB)
		debug.SetMemoryLimit(40 << 20)
	}
	defer a.close()
	if err := a.ensureCLIToken(ctx); err != nil {
		return fmt.Errorf("cli token: %w", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	start := func(f func(context.Context)) {
		wg.Add(1)
		go func() { defer wg.Done(); f(ctx) }()
	}
	start(func(ctx context.Context) {
		a.Metrics.Run(ctx, func(s *collector.Snapshot) {
			if err := a.Store.Append(s.TS, s.Samples); err != nil {
				slog.Error("store append", "err", err)
			}
			a.Alerts.Eval(ctx, s)
			a.Hub.Publish("metrics", s)
			for _, h := range a.OnSnapshot {
				h(s)
			}
		})
	})
	start(a.prune)
	start(a.Firewall.Run)
	start(a.Alerts.Run)
	start(a.SSH.Run)
	start(a.Harden.Run)
	for _, f := range a.Extra {
		start(f)
	}
	errc := make(chan error, 1)
	go func() { errc <- a.API.ListenAndServe(ctx, a.Cfg.Listen) }()
	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
		cancel()
	}
	wg.Wait()
	return err
}

func (a *Agent) prune(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := a.Store.Prune(a.Cfg.Collector.RetentionRaw, a.Cfg.Collector.RetentionRollup); err != nil {
				slog.Error("prune", "err", err)
			}
			_ = a.DB.PruneSessions(ctx, time.Now())
			if _, err := a.DB.PruneAudit(ctx, time.Now().Add(-365*24*time.Hour)); err != nil {
				slog.Warn("audit prune", "err", err)
			}
		}
	}
}

func (a *Agent) close() {
	if a.Store != nil {
		a.Store.Close()
	}
	if a.DB != nil {
		a.DB.Close()
	}
}
