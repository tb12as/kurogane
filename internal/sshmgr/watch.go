package sshmgr

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/tb12as/serverman/internal/alert"
	"github.com/tb12as/serverman/internal/audit"
	"github.com/tb12as/serverman/internal/hostfs"
)

const seenBucket = "ssh_seen_ips"

// bruteforce thresholds for the alert (PRD §8.1: > 20 failed logins from one IP in 5 min).
const (
	bfAlertCount  = 20
	bfAlertWindow = 5 * time.Minute
)

// tailInit starts tailing at the current end so old lines are not replayed.
func (m *Manager) tailInit() {
	m.tailPath = authLogPath()
	m.lastJrnl = m.now()
	if m.tailPath == "" {
		return
	}
	f, err := os.Open(hostfs.P(m.tailPath))
	if err != nil {
		// unreadable as the privsep worker (e.g. RHEL /var/log/secure is root-only): read journald via the executor
		slog.Info("auth log not readable, using journald", "path", m.tailPath, "err", err)
		m.tailPath = ""
		return
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil {
		m.tailOff = st.Size()
	}
}

// tail reads new auth-log lines (handles rotation) or polls journald.
func (m *Manager) tail(ctx context.Context) {
	if m.tailPath == "" {
		now := m.now()
		out, err := m.d.Ex.Run(ctx, "journalctl", "_COMM=sshd", "--since", m.lastJrnl.Format("2006-01-02 15:04:05"),
			"-o", "short-iso", "--no-pager")
		m.lastJrnl = now
		if err == nil {
			m.handleLines(ctx, string(out))
		}
		return
	}
	f, err := os.Open(hostfs.P(m.tailPath))
	if err != nil {
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return
	}
	if st.Size() < m.tailOff { // rotated or truncated
		m.tailOff = 0
	}
	if st.Size() == m.tailOff {
		return
	}
	if _, err := f.Seek(m.tailOff, io.SeekStart); err != nil {
		return
	}
	b, err := io.ReadAll(io.LimitReader(f, 8<<20))
	if err != nil {
		return
	}
	// only consume complete lines
	if i := strings.LastIndexByte(string(b), '\n'); i >= 0 {
		b = b[:i+1]
	} else {
		return
	}
	m.tailOff += int64(len(b))
	m.handleLines(ctx, string(b))
}

func (m *Manager) handleLines(ctx context.Context, text string) {
	now := m.now()
	for _, l := range strings.Split(text, "\n") {
		ev, ok := parseAuthLine(l, now)
		if !ok {
			continue
		}
		if ev.Success {
			m.onLogin(ctx, ev)
		} else {
			m.onFailure(ctx, ev)
		}
	}
}

func (m *Manager) onLogin(ctx context.Context, ev Login) {
	if ev.Fingerprint != "" && m.d.DB != nil {
		if ks, err := m.d.DB.FindKeys(ctx, ev.Fingerprint); err == nil {
			for _, k := range ks {
				if k.User == ev.User && k.ServerID == m.d.ServerID {
					k.LastUsedAt = ev.TS
					_ = m.d.DB.UpsertKey(ctx, k)
				}
			}
		}
	}
	cfg := m.d.Cfg.Alerts
	newIP := true
	if m.d.Store != nil {
		var seen time.Time
		newIP = m.d.Store.Get(seenBucket, ev.User+"|"+ev.IP, &seen) != nil
		_ = m.d.Store.Put(seenBucket, ev.User+"|"+ev.IP, ev.TS)
	}
	if cfg.NewLoginOnlyNewIP && !newIP {
		return
	}
	if cfg.NewLoginOnlyRoot && ev.User != "root" {
		return
	}
	fields := map[string]string{"User": ev.User, "From": ev.IP, "Method": ev.Method}
	if ev.Fingerprint != "" {
		fields["Key"] = ev.Fingerprint
	}
	if newIP {
		fields["New source"] = "yes"
	}
	m.fire(ctx, alert.Event{Rule: "ssh_login", Severity: "info", Once: true,
		Text: fmt.Sprintf("%s logged in from %s (%s)", ev.User, ev.IP, ev.Method), Fields: fields})
}

// onFailure feeds the brute-force blocker (SSH-6) and the brute-force alert.
func (m *Manager) onFailure(ctx context.Context, ev Login) {
	bf := m.d.Cfg.SSH.Bruteforce
	now := m.now()
	keep := bf.Window
	if keep < bfAlertWindow {
		keep = bfAlertWindow
	}
	m.bfMu.Lock()
	ts := append(m.failures[ev.IP], ev.TS)
	cut := 0
	for cut < len(ts) && now.Sub(ts[cut]) > keep {
		cut++
	}
	ts = ts[cut:]
	m.failures[ev.IP] = ts
	inWin, inAlert := 0, 0
	for _, t := range ts {
		if now.Sub(t) <= bf.Window {
			inWin++
		}
		if now.Sub(t) <= bfAlertWindow {
			inAlert++
		}
	}
	alertNow := inAlert > bfAlertCount && now.Sub(m.alerted[ev.IP]) > time.Hour
	if alertNow {
		m.alerted[ev.IP] = now
	}
	m.bfMu.Unlock()

	banned := false
	if bf.Enabled && bf.MaxFailures > 0 && inWin >= bf.MaxFailures && m.d.Firewall != nil && !m.fail2ban(ctx) &&
		!m.d.Firewall.Exempt(ev.IP) && !m.isBanned(ev.IP) {
		reason := fmt.Sprintf("ssh brute force: %d failures in %s", inWin, bf.Window)
		if err := m.d.Firewall.Ban(ctx, ev.IP, bf.BanFor, reason); err != nil {
			slog.Warn("ssh ban failed", "ip", ev.IP, "err", err)
		} else {
			banned = true
			m.d.Audit.Record(audit.WithActor(ctx, "system:bruteforce", ""), "firewall.ban", ev.IP, nil,
				map[string]any{"reason": reason, "for": bf.BanFor.String()})
		}
	}
	if alertNow {
		txt := fmt.Sprintf("%d failed SSH logins from %s in 5 min (last user tried: %s)", inAlert, ev.IP, ev.User)
		if banned || m.isBanned(ev.IP) {
			txt += "; the IP is banned"
		}
		m.fire(ctx, alert.Event{Rule: "ssh_bruteforce", Severity: "warning", Once: true, Text: txt,
			Fields: map[string]string{"Source IP": ev.IP}})
	}
}

func (m *Manager) isBanned(ip string) bool {
	if m.d.Firewall == nil {
		return false
	}
	for _, b := range m.d.Firewall.Bans() {
		if b.IP == ip && b.ExpiresAt.After(m.now()) {
			return true
		}
	}
	return false
}
