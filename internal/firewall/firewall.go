// Package firewall abstracts nftables/iptables/ufw/firewalld for IP bans. When ufw or firewalld manage the
// host firewall, bans go through them instead of beside them (PRD §13: never fight them).
package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/store"
)

type Ban struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// MaxBans caps active bans so a spoofed flood cannot grow rules without bound.
var MaxBans = 4096

var (
	ErrExempt = errors.New("ip is loopback or allowlisted and is never banned")
	ErrCap    = errors.New("ban limit reached")
)

const bucket = "fw_bans"

// nftBackend is the netlink side; swapped in tests so the host ruleset is never touched.
type nftBackend interface {
	setup(bans []Ban) error
	add(ip net.IP, d time.Duration) error
	del(ip net.IP) error
}

var newNft = func() nftBackend { return &netlinkNft{} }

// nftForTests lets in-package tests exercise the nft path with a stub backend.
var nftForTests = false

type Manager struct {
	ex executor.Executor

	mu      sync.Mutex
	backend string // "" until detected
	nft     nftBackend
	bans    map[string]Ban
	allow   []*net.IPNet
	st      *store.Store
}

func New(ex executor.Executor) *Manager { return &Manager{ex: ex, bans: map[string]Ban{}} }

// SetStore persists bans in bbolt and loads the ones saved before a restart; expired ones are
// kept until the sweeper removes them, because ufw/firewalld/iptables rules outlive the agent.
func (m *Manager) SetStore(st *store.Store) {
	if st == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.st = st
	_ = st.List(bucket, func(k string, raw []byte) error {
		var b Ban
		if json.Unmarshal(raw, &b) == nil && net.ParseIP(b.IP) != nil {
			m.bans[b.IP] = b
		}
		return nil
	})
}

// SetAllowlist sets CIDRs (or bare IPs) that are never banned, in addition to loopback.
func (m *Manager) SetAllowlist(cidrs []string) error {
	var nets []*net.IPNet
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.Contains(c, "/") {
			if ip := net.ParseIP(c); ip != nil && ip.To4() != nil {
				c += "/32"
			} else {
				c += "/128"
			}
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return fmt.Errorf("invalid allowlist entry %q: use an IP or CIDR like 203.0.113.10/32", c)
		}
		nets = append(nets, n)
	}
	m.mu.Lock()
	m.allow = nets
	m.mu.Unlock()
	return nil
}

// Exempt reports whether ip must never be banned (unparsable, loopback, unspecified or allowlisted).
func (m *Manager) Exempt(ip string) bool {
	p := parseIP(ip)
	if p == nil || p.IsLoopback() || p.IsUnspecified() {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, n := range m.allow {
		if n.Contains(p) {
			return true
		}
	}
	return false
}

func parseIP(s string) net.IP {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "%")
	p := net.ParseIP(s)
	if v4 := p.To4(); v4 != nil {
		return v4
	}
	return p
}

// Ban blocks ip for d. Re-banning an IP extends its expiry.
func (m *Manager) Ban(ctx context.Context, ip string, d time.Duration, reason string) error {
	p := parseIP(ip)
	if p == nil {
		return fmt.Errorf("invalid IP %q", ip)
	}
	if d <= 0 {
		return fmt.Errorf("ban duration must be positive (got %s)", d)
	}
	if m.Exempt(ip) {
		return fmt.Errorf("%s: %w", p, ErrExempt)
	}
	key := p.String()
	now := time.Now()
	b := Ban{IP: key, Reason: reason, CreatedAt: now, ExpiresAt: now.Add(d)}

	m.mu.Lock()
	defer m.mu.Unlock()
	old, exists := m.bans[key]
	if !exists && m.activeLocked() >= MaxBans {
		return fmt.Errorf("%w (%d active): raise firewall.MaxBans or unban old entries", ErrCap, MaxBans)
	}
	be := m.detectLocked(ctx)
	if be == "none" {
		return errors.New("no supported firewall found: install nftables or iptables, or enable ufw/firewalld")
	}
	if exists {
		b.CreatedAt = old.CreatedAt
		if old.ExpiresAt.After(b.ExpiresAt) {
			b.ExpiresAt = old.ExpiresAt
		}
		if be == "nftables" {
			// element timeouts are fixed at insert time
			_ = m.nft.del(p)
		}
	}
	if !exists || be == "nftables" {
		if err := m.apply(ctx, be, p, time.Until(b.ExpiresAt)); err != nil {
			return fmt.Errorf("ban %s via %s: %w", key, be, err)
		}
	}
	m.bans[key] = b
	m.persist(b)
	slog.Info("firewall ban", "ip", key, "until", b.ExpiresAt, "backend", be, "reason", reason)
	return nil
}

// Unban removes a ban; returns store.ErrNotFound if ip is not banned.
func (m *Manager) Unban(ctx context.Context, ip string) error {
	p := parseIP(ip)
	if p == nil {
		return fmt.Errorf("invalid IP %q", ip)
	}
	key := p.String()
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.bans[key]; !ok {
		return fmt.Errorf("%s is not banned: %w", key, store.ErrNotFound)
	}
	if err := m.remove(ctx, m.detectLocked(ctx), p); err != nil {
		return fmt.Errorf("unban %s: %w", key, err)
	}
	delete(m.bans, key)
	if m.st != nil {
		_ = m.st.Delete(bucket, key)
	}
	return nil
}

// Bans lists active bans, soonest expiry first.
func (m *Manager) Bans() []Ban {
	m.mu.Lock()
	out := make([]Ban, 0, len(m.bans))
	now := time.Now()
	for _, b := range m.bans {
		if b.ExpiresAt.After(now) {
			out = append(out, b)
		}
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ExpiresAt.Before(out[j].ExpiresAt) })
	return out
}

// Backend returns the ban backend: nftables | iptables | ufw | firewalld | none.
func (m *Manager) Backend() string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.detectLocked(ctx)
}

// Run sweeps expired bans until ctx is done.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	m.Sweep(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Sweep(ctx)
		}
	}
}

// Sweep removes expired bans from the firewall and the store.
func (m *Manager) Sweep(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, b := range m.bans {
		if b.ExpiresAt.After(now) {
			continue
		}
		be := m.detectLocked(ctx)
		if err := m.remove(ctx, be, parseIP(k)); err != nil && be != "nftables" {
			slog.Warn("firewall unban of expired ban failed; will retry", "ip", k, "err", err)
			continue
		}
		delete(m.bans, k)
		if m.st != nil {
			_ = m.st.Delete(bucket, k)
		}
	}
}

func (m *Manager) activeLocked() int {
	n, now := 0, time.Now()
	for _, b := range m.bans {
		if b.ExpiresAt.After(now) {
			n++
		}
	}
	return n
}

func (m *Manager) persist(b Ban) {
	if m.st == nil {
		return
	}
	if err := m.st.Put(bucket, b.IP, b); err != nil {
		slog.Warn("persist ban", "ip", b.IP, "err", err)
	}
}

// detectLocked picks the ban backend once and re-applies loaded bans to it.
func (m *Manager) detectLocked(ctx context.Context) string {
	if m.backend != "" {
		return m.backend
	}
	m.backend = m.pick(ctx)
	if m.backend != "nftables" && m.backend != "none" {
		now := time.Now()
		for k, b := range m.bans {
			if b.ExpiresAt.After(now) {
				if err := m.apply(ctx, m.backend, parseIP(k), b.ExpiresAt.Sub(now)); err != nil {
					slog.Warn("re-apply ban", "ip", k, "err", err)
				}
			}
		}
	}
	slog.Info("firewall backend", "backend", m.backend)
	return m.backend
}

func (m *Manager) pick(ctx context.Context) string {
	if out, err := m.ex.Run(ctx, "firewall-cmd", "--state"); err == nil && strings.TrimSpace(string(out)) == "running" {
		return "firewalld"
	}
	if out, err := m.ex.Run(ctx, "ufw", "status"); err == nil && strings.Contains(string(out), "Status: active") {
		return "ufw"
	}
	// netlink bypasses the executor: only the real root executor may use it (never fakes or the privsep worker)
	_, local := m.ex.(executor.Local)
	if _, err := m.ex.Run(ctx, "nft", "list", "tables"); err == nil && (local || nftForTests) {
		n := newNft()
		var bans []Ban
		for _, b := range m.bans {
			bans = append(bans, b)
		}
		err := n.setup(bans)
		if err == nil {
			m.nft = n
			return "nftables"
		}
		slog.Warn("nftables setup failed, trying iptables", "err", err)
	}
	if _, err := m.ex.Run(ctx, "iptables", "-S", "INPUT"); err == nil {
		m.ensureChain(ctx, "iptables")
		m.ensureChain(ctx, "ip6tables")
		return "iptables"
	}
	return "none"
}

const chain = "SERVERKEEPER"

func (m *Manager) ensureChain(ctx context.Context, bin string) {
	_, _ = m.ex.Run(ctx, bin, "-N", chain)
	if _, err := m.ex.Run(ctx, bin, "-C", "INPUT", "-j", chain); err != nil {
		if _, err := m.ex.Run(ctx, bin, "-I", "INPUT", "1", "-j", chain); err != nil {
			slog.Warn("cannot hook ban chain", "bin", bin, "err", err)
		}
	}
}

func ipt(p net.IP) string {
	if p.To4() != nil {
		return "iptables"
	}
	return "ip6tables"
}

func rich(p net.IP) string {
	fam := "ipv6"
	if p.To4() != nil {
		fam = "ipv4"
	}
	return fmt.Sprintf(`rule family="%s" source address="%s" drop`, fam, p)
}

func (m *Manager) apply(ctx context.Context, be string, p net.IP, d time.Duration) error {
	var err error
	switch be {
	case "nftables":
		err = m.nft.add(p, d)
	case "iptables":
		if _, e := m.ex.Run(ctx, ipt(p), "-C", chain, "-s", p.String(), "-j", "DROP"); e == nil {
			return nil
		}
		_, err = m.ex.Run(ctx, ipt(p), "-I", chain, "-s", p.String(), "-j", "DROP")
	case "ufw":
		// prepend so the deny is evaluated before existing allow rules (e.g. 22/tcp)
		_, err = m.ex.Run(ctx, "ufw", "prepend", "deny", "from", p.String())
	case "firewalld":
		_, err = m.ex.Run(ctx, "firewall-cmd", "--add-rich-rule", rich(p))
	default:
		err = errors.New("no firewall backend")
	}
	return err
}

func (m *Manager) remove(ctx context.Context, be string, p net.IP) error {
	var err error
	switch be {
	case "nftables":
		err = m.nft.del(p)
	case "iptables":
		_, err = m.ex.Run(ctx, ipt(p), "-D", chain, "-s", p.String(), "-j", "DROP")
	case "ufw":
		_, err = m.ex.Run(ctx, "ufw", "--force", "delete", "deny", "from", p.String())
	case "firewalld":
		_, err = m.ex.Run(ctx, "firewall-cmd", "--remove-rich-rule", rich(p))
	}
	return err
}
