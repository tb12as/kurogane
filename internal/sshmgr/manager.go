// Package sshmgr manages authorized_keys, sshd_config safe-apply, sessions, login audit,
// brute-force banning and the SSH CA (PRD §6).
package sshmgr

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/serverkeeper/serverkeeper/internal/alert"
	"github.com/serverkeeper/serverkeeper/internal/audit"
	"github.com/serverkeeper/serverkeeper/internal/config"
	"github.com/serverkeeper/serverkeeper/internal/db"
	"github.com/serverkeeper/serverkeeper/internal/executor"
	"github.com/serverkeeper/serverkeeper/internal/firewall"
	"github.com/serverkeeper/serverkeeper/internal/store"
)

type Deps struct {
	Cfg      *config.Config
	DB       db.Store
	Store    *store.Store
	Ex       executor.Executor
	Audit    *audit.Logger
	Alerts   *alert.Engine
	Firewall *firewall.Manager
	ServerID string
	Publish  func(event string, v any)
}

// Manager owns SSH keys, sshd_config changes and login auditing for this host.
type Manager struct {
	d   Deps
	now func() time.Time

	applyMu sync.Mutex // one sshd change at a time
	confirm chan string
	timerMu sync.Mutex
	timerOn bool

	bfMu     sync.Mutex
	failures map[string][]time.Time
	alerted  map[string]time.Time
	f2b      bool
	f2bAt    time.Time

	tailOff  int64
	tailPath string
	lastJrnl time.Time
}

func New(d Deps) *Manager {
	if d.ServerID == "" {
		d.ServerID = "local"
	}
	if d.Cfg == nil {
		d.Cfg = &config.Config{}
	}
	if d.Cfg.SSH.ConfigPath == "" {
		d.Cfg.SSH.ConfigPath = "/etc/ssh/sshd_config"
	}
	m := &Manager{d: d, now: time.Now, confirm: make(chan string, 1), failures: map[string][]time.Time{},
		alerted: map[string]time.Time{}}
	if d.Firewall != nil {
		allow := append(append([]string{}, d.Cfg.SSH.Bruteforce.Allowlist...), d.Cfg.Alerts.AutoBan.Allowlist...)
		if err := d.Firewall.SetAllowlist(allow); err != nil {
			slog.Error("firewall allowlist invalid", "err", err)
		}
		d.Firewall.SetStore(d.Store)
	}
	return m
}

// Run resumes pending sshd changes, sweeps expired keys and tails the auth log.
func (m *Manager) Run(ctx context.Context) {
	m.resume(ctx)
	if err := m.SyncKeys(ctx); err != nil {
		slog.Warn("ssh key inventory sync failed", "err", err)
	}
	m.tailInit()
	tail := time.NewTicker(5 * time.Second)
	defer tail.Stop()
	sweep := time.NewTicker(time.Minute)
	defer sweep.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tail.C:
			m.tail(ctx)
		case <-sweep.C:
			m.expire(ctx)
		}
	}
}

func (m *Manager) publish(ev string, v any) {
	if m.d.Publish != nil {
		m.d.Publish(ev, v)
	}
}

func (m *Manager) fire(ctx context.Context, ev alert.Event) {
	if m.d.Alerts != nil {
		m.d.Alerts.Fire(ctx, ev)
	}
}

// BruteforceActive reports whether the built-in SSH ban or fail2ban is active.
func (m *Manager) BruteforceActive() bool {
	if m.d.Cfg.SSH.Bruteforce.Enabled && m.d.Firewall != nil {
		return true
	}
	return m.fail2ban(context.Background())
}

func (m *Manager) fail2ban(ctx context.Context) bool {
	m.bfMu.Lock()
	defer m.bfMu.Unlock()
	if m.now().Sub(m.f2bAt) < time.Minute {
		return m.f2b
	}
	_, err := m.d.Ex.Run(ctx, "systemctl", "is-active", "--quiet", "fail2ban")
	m.f2b, m.f2bAt = err == nil, m.now()
	return m.f2b
}
