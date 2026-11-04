// Package server is the v1 central server (`serverkeeper server run`, PRD §9): SQLite metadata, its own CA,
// gRPC with mutual TLS for agents, fleet metrics in VictoriaMetrics, alert routing and typed fleet operations.
//
// Ports: one gRPC port (server.grpc_listen, default :9444) serves both RPCs. TLS 1.3 with
// VerifyClientCertIfGiven: a presented client cert must chain to the central CA or the handshake fails;
// Connect additionally requires a verified cert whose CN is a known server id and whose fingerprint matches the
// enrolled one, while Enroll is the only RPC accepted without a client cert and needs a one-time token.
// The REST API and web UI listen on server.http_listen (127.0.0.1:9443).
package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
	"github.com/tb12as/kurogane/internal/agent"
	"github.com/tb12as/kurogane/internal/alert"
	"github.com/tb12as/kurogane/internal/api"
	"github.com/tb12as/kurogane/internal/audit"
	"github.com/tb12as/kurogane/internal/auth"
	"github.com/tb12as/kurogane/internal/backup"
	"github.com/tb12as/kurogane/internal/config"
	"github.com/tb12as/kurogane/internal/db"
	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/metricsdb"
	"github.com/tb12as/kurogane/internal/notify"
	"github.com/tb12as/kurogane/internal/pb"
	"github.com/tb12as/kurogane/internal/secret"
	"github.com/tb12as/kurogane/web"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	_ "google.golang.org/grpc/encoding/gzip" // agents compress the stream
	"google.golang.org/grpc/keepalive"
)

// TokenTTL is the enrollment token lifetime (§11.1).
const TokenTTL = time.Hour

// maxVMBuf caps buffered import data while VictoriaMetrics is down (oldest dropped).
const maxVMBuf = 64 << 20

// Central is the running central server.
type Central struct {
	Cfg     *config.Config
	DB      *db.SQLite
	Box     *secret.Box
	Audit   *audit.Logger
	CA      *CA
	VM      *metricsdb.Client
	API     *api.Server
	Version string

	// NewNotifier builds channel notifiers (tests replace it).
	NewNotifier func(config.Channel, *secret.Box) (notify.Notifier, error)

	mu       sync.Mutex
	sessions map[string]*session
	latest   map[string]map[string]float64 // server id -> cpu/mem/disk

	vmMu  sync.Mutex
	vmBuf []byte
}

type session struct {
	id     string
	kick   chan struct{}
	cancel context.CancelFunc
}

var (
	regMu  sync.Mutex
	byAPI  = map[*api.Server]*Central{}
	routed sync.Once
)

// New opens the metadata store, CA and secret box under cfg.DataDir.
func New(cfg *config.Config, version string) (*Central, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir %s: %w (run as the serverkeeper user or set data_dir)", cfg.DataDir, err)
	}
	c := &Central{Cfg: cfg, Version: version, NewNotifier: notify.New, sessions: map[string]*session{},
		latest: map[string]map[string]float64{}, VM: metricsdb.New(cfg.Server.VM.URL)}
	var err error
	if c.Box, err = secret.LoadOrCreate(cfg.SecretKey); err != nil {
		return nil, err
	}
	if c.CA, err = LoadOrCreateCA(cfg.DataDir + "/ca"); err != nil {
		return nil, err
	}
	if c.DB, err = db.Open(cfg.MetaDB()); err != nil {
		return nil, err
	}
	c.Audit = &audit.Logger{Store: c.DB, ServerID: "central"}
	au := auth.NewService(c.DB, c.Box, cfg.Auth.SessionTTL)
	if o, err := auth.NewOIDC(context.Background(), cfg.Auth.OIDC); err != nil {
		slog.Warn("oidc disabled", "err", err)
	} else {
		au.OIDC = o
	}
	hub := api.NewHub()
	al, err := alert.NewEngine(alert.Deps{Cfg: cfg, DB: c.DB, Box: c.Box, Audit: c.Audit, ServerID: "central",
		Publish: hub.Publish})
	if err != nil {
		return nil, err
	}
	c.API = &api.Server{Cfg: cfg, DB: c.DB, Auth: au, Audit: c.Audit, Box: c.Box, Ex: executor.Local{}, Alerts: al,
		Hub: hub, UI: web.FS(), Version: version, Central: true}
	regMu.Lock()
	byAPI[c.API] = c
	regMu.Unlock()
	routed.Do(func() {
		api.Register(func(s *api.Server) {
			regMu.Lock()
			c := byAPI[s]
			regMu.Unlock()
			if s.Central && c != nil {
				c.routes(s)
			}
		})
	})
	return c, nil
}

// Close releases the database.
func (c *Central) Close() error {
	regMu.Lock()
	delete(byAPI, c.API)
	regMu.Unlock()
	return c.DB.Close()
}

// GRPC builds the gRPC server with mutual TLS (see package doc).
func (c *Central) GRPC() (*grpc.Server, error) {
	cert, err := c.CA.ServerCert()
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientCAs: c.CA.Pool,
		ClientAuth: tls.VerifyClientCertIfGiven}
	g := grpc.NewServer(grpc.Creds(credentials.NewTLS(tc)), grpc.MaxRecvMsgSize(4<<20),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 20 * time.Second, PermitWithoutStream: true}))
	pb.RegisterFleetServer(g, &fleetSrv{c: c})
	return g, nil
}

// Run serves gRPC, the REST API and background loops until ctx is done.
func (c *Central) Run(ctx context.Context) error {
	defer c.Close()
	tok, _ := os.ReadFile(agent.CLITokenPath(c.Cfg))
	raw, err := c.API.Auth.EnsureLocalToken(ctx, strings.TrimSpace(string(tok)))
	if err != nil {
		return fmt.Errorf("cli token: %w", err)
	}
	if err := os.WriteFile(agent.CLITokenPath(c.Cfg), []byte(raw+"\n"), 0o600); err != nil { // #nosec G703 -- path comes from the root-owned config
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	g, err := c.GRPC()
	if err != nil {
		return err
	}
	lis, err := net.Listen("tcp", c.Cfg.Server.GRPCListen)
	if err != nil {
		return fmt.Errorf("grpc listen %s: %w (port in use? set server.grpc_listen)", c.Cfg.Server.GRPCListen, err)
	}
	errc := make(chan error, 2)
	go func() { errc <- g.Serve(lis) }()
	go func() { <-ctx.Done(); g.GracefulStop() }()
	go func() { errc <- c.API.ListenAndServe(ctx, c.Cfg.Server.HTTPListen) }()
	slog.Info("central server listening", "grpc", c.Cfg.Server.GRPCListen, "api", c.Cfg.Server.HTTPListen)

	if c.Cfg.Server.VM.Mode == "child" {
		go func() {
			if err := metricsdb.Supervise(ctx, c.Cfg.Server.VM); err != nil {
				slog.Error("victoriametrics supervisor", "err", err)
			}
		}()
	}
	go c.API.Alerts.Run(ctx)
	go c.every(ctx, 5*time.Second, c.Flush)
	go c.every(ctx, 15*time.Second, c.CheckOffline)
	go c.every(ctx, 24*time.Hour, func(ctx context.Context) {
		if _, err := c.DB.PruneAudit(ctx, time.Now().Add(-c.Cfg.Server.AuditRetention)); err != nil {
			slog.Warn("audit prune", "err", err)
		}
		_ = c.DB.PruneSessions(ctx, time.Now())
	})
	if s := c.Cfg.Server.Backup.Schedule; s != "" {
		cr := cron.New()
		if _, err := cr.AddFunc(s, func() { c.backup(ctx) }); err != nil {
			return fmt.Errorf("server.backup.schedule %q: %w", s, err)
		}
		cr.Start()
		defer cr.Stop()
	}
	select {
	case <-ctx.Done():
		err = nil
	case err = <-errc:
	}
	cancel()
	c.Flush(context.Background())
	if errors.Is(err, grpc.ErrServerStopped) {
		err = nil
	}
	return err
}

func (c *Central) backup(ctx context.Context) {
	dir, _, err := backup.Run(ctx, backup.Options{Cfg: c.Cfg, DB: c.DB, VM: c.VM, Keep: c.Cfg.Server.Backup.Keep})
	if err != nil {
		slog.Error("nightly backup failed", "err", err)
		c.Audit.Record(ctx, "backup.failed", "", nil, err.Error())
		return
	}
	c.Audit.Record(ctx, "backup.create", dir, nil, nil)
}

func (c *Central) every(ctx context.Context, d time.Duration, f func(context.Context)) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f(ctx)
		}
	}
}

// Flush sends buffered samples to VictoriaMetrics (batched every 5 s); on failure data stays buffered.
func (c *Central) Flush(ctx context.Context) {
	c.vmMu.Lock()
	b := c.vmBuf
	c.vmBuf = nil
	c.vmMu.Unlock()
	if len(b) == 0 {
		return
	}
	if err := c.VM.Import(ctx, b); err != nil {
		slog.Warn("victoriametrics import failed, will retry", "err", err, "bytes", len(b))
		c.vmMu.Lock()
		c.vmBuf = append(b, c.vmBuf...)
		if len(c.vmBuf) > maxVMBuf {
			cut := len(c.vmBuf) - maxVMBuf
			if i := bytes.IndexByte(c.vmBuf[cut:], '\n'); i >= 0 {
				cut += i + 1
			}
			c.vmBuf = c.vmBuf[cut:]
		}
		c.vmMu.Unlock()
	}
}

// kick wakes a connected agent's session so it delivers newly queued ops.
func (c *Central) kick(id string) {
	c.mu.Lock()
	s := c.sessions[id]
	c.mu.Unlock()
	if s == nil {
		return
	}
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// Connected reports whether an agent stream is open.
func (c *Central) Connected(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessions[id] != nil
}

// audit writes a fleet audit entry attributed to serverID.
func (c *Central) audit(ctx context.Context, serverID, action, target string, after any) {
	l := audit.Logger{Store: c.DB, ServerID: serverID}
	l.Record(ctx, action, target, nil, after)
}
