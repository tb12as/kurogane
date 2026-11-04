package sites

import (
	"context"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/tb12as/kurogane/internal/alert"
	"github.com/tb12as/kurogane/internal/audit"
	"github.com/tb12as/kurogane/internal/certs"
	"github.com/tb12as/kurogane/internal/collector"
	"github.com/tb12as/kurogane/internal/db"
	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/store"
)

// Scan cadence: files are parsed often (cheap), the config test runs less often and after every change.
var (
	ScanEvery = 5 * time.Minute
	TestEvery = 15 * time.Minute
)

// Deps are the Manager's collaborators; nil ones disable the matching feature.
type Deps struct {
	Ex      executor.Executor
	DB      db.Store
	Store   *store.Store
	Audit   *audit.Logger
	Fire    func(context.Context, alert.Event) // alert.Engine.Fire
	Certs   func() []certs.Cert                // latest certificate scan, for days left per site
	Publish func(event string, v any)
	Now     func() time.Time
	// SelfPort is the port ServerKeeper's own API listens on, to warn before disabling a site that proxies to it.
	SelfPort string
}

// Manager keeps the site inventory and applies toggles.
type Manager struct {
	d Deps

	mu       sync.Mutex
	inv      Inventory
	tested   map[string]WebServer // last config test per kind
	failures map[string]int       // consecutive failing config tests per kind

	applyMu sync.Mutex // one change at a time
	probe   prober
}

func New(d Deps) *Manager {
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Manager{d: d, tested: map[string]WebServer{}, failures: map[string]int{}, probe: httpProbe}
}

// Run rescans until ctx is done, after undoing any change interrupted by a restart.
func (m *Manager) Run(ctx context.Context) {
	m.resume(ctx)
	m.Scan(ctx, true)
	t := time.NewTicker(ScanEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.mu.Lock()
			due := false
			for _, w := range m.tested {
				due = due || m.d.Now().Sub(w.TestedAt) >= TestEvery
			}
			m.mu.Unlock()
			m.Scan(ctx, due || len(m.tested) == 0)
		}
	}
}

// Inventory returns the latest scan.
func (m *Manager) Inventory() Inventory {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inv
}

// Scan re-reads the configuration; test also runs the config test and refreshes versions and unit state.
func (m *Manager) Scan(ctx context.Context, test bool) Inventory {
	inv := inventory(m.d.Ex)
	inv.ScannedAt = m.d.Now()
	days := m.certDays()
	for i := range inv.Sites {
		s := &inv.Sites[i]
		for _, p := range s.Certs {
			if d, ok := days[p]; ok && (s.CertDays == nil || d < *s.CertDays) {
				s.CertDays = &d
			}
		}
	}
	sortSites(inv.Sites)
	for i := range inv.Servers {
		w := &inv.Servers[i]
		if test {
			w.ConfigOK, w.ConfigError = configTest(ctx, m.d.Ex, w.Kind)
			w.TestedAt = m.d.Now()
			_, err := m.d.Ex.Run(ctx, "systemctl", "is-active", "--quiet", w.Unit)
			w.Active = err == nil
			w.Version = version(ctx, m.d.Ex, *w)
			m.alertConfig(ctx, *w)
		} else {
			m.mu.Lock()
			if old, ok := m.tested[w.Kind]; ok {
				w.ConfigOK, w.ConfigError, w.TestedAt, w.Active, w.Version = old.ConfigOK, old.ConfigError,
					old.TestedAt, old.Active, old.Version
			}
			m.mu.Unlock()
		}
	}
	m.mu.Lock()
	for _, w := range inv.Servers {
		if test {
			m.tested[w.Kind] = w
		}
	}
	m.inv = inv
	m.mu.Unlock()
	if m.d.Publish != nil {
		m.d.Publish("sites", inv)
	}
	return inv
}

// certDays maps certificate paths to days left from the latest certificate scan.
func (m *Manager) certDays() map[string]float64 {
	out := map[string]float64{}
	if m.d.Certs == nil {
		return out
	}
	for _, c := range m.d.Certs() {
		if c.Path != "" && c.Error == "" {
			out[c.Path] = math.Round(c.DaysLeft*10) / 10
		}
	}
	return out
}

// alertConfig fires web_config_invalid after two consecutive failing tests (one failure may be an edit in
// progress) and resolves it on the next passing test.
func (m *Manager) alertConfig(ctx context.Context, w WebServer) {
	m.mu.Lock()
	prev := m.failures[w.Kind]
	if w.ConfigOK {
		m.failures[w.Kind] = 0
	} else {
		m.failures[w.Kind]++
	}
	n := m.failures[w.Kind]
	m.mu.Unlock()
	if m.d.Fire == nil {
		return
	}
	ev := alert.Event{Rule: "web_config_invalid", Severity: "warning", Labels: map[string]string{"server": w.Kind}}
	switch {
	case w.ConfigOK && prev >= 2:
		ev.Resolve = true
	case w.ConfigOK:
		return
	case n >= 2:
		ev.Title = w.Kind + " configuration test fails"
		ev.Text = "`" + testCmd(w.Kind) + "` fails: " + w.ConfigError + ". The running server is unaffected, but " +
			"the next reload or reboot will fail and take every site down. Fix the file named above."
		ev.Fields = map[string]string{"Unit": w.Unit}
	default:
		return
	}
	m.d.Fire(ctx, ev)
	if !w.ConfigOK {
		slog.Warn("web server config test fails", "server", w.Kind, "err", w.ConfigError)
	}
}

func testCmd(kind string) string {
	if kind == "nginx" {
		return "nginx -t"
	}
	return "apachectl configtest"
}

// Collect reports web.config_ok and web.sites for the metric store (collector.Collector).
func (m *Manager) Collect(context.Context) ([]collector.Sample, error) {
	inv := m.Inventory()
	var out []collector.Sample
	for _, w := range inv.Servers {
		ok := 0.0
		if w.ConfigOK {
			ok = 1
		}
		if !w.TestedAt.IsZero() {
			out = append(out, collector.Sample{Metric: "web.config_ok", Labels: map[string]string{"server": w.Kind}, Value: ok})
		}
		on, off := 0.0, 0.0
		for _, s := range inv.Sites {
			if s.Kind != w.Kind {
				continue
			}
			if s.Enabled {
				on++
			} else {
				off++
			}
		}
		out = append(out,
			collector.Sample{Metric: "web.sites", Labels: map[string]string{"server": w.Kind, "state": "enabled"}, Value: on},
			collector.Sample{Metric: "web.sites", Labels: map[string]string{"server": w.Kind, "state": "disabled"}, Value: off})
	}
	return out, nil
}
