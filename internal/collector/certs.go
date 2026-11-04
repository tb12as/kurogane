package collector

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/tb12as/kurogane/internal/certs"
	"github.com/tb12as/kurogane/internal/config"
	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/hostfs"
)

// certCollector rescans certificates on its own slow loop (hourly by default) and reports the cached
// result every tick, recomputing days left so the series stay continuous for the store and the alerts.
type certCollector struct {
	r     certs.Reader
	opts  certs.Options
	every time.Duration

	scanMu sync.Mutex // one scan at a time (loop and API rescans)
	mu     sync.Mutex
	list   []certs.Cert
	at     time.Time
}

type hostReader struct{}

func (hostReader) ReadFile(p string) ([]byte, error) { return hostfs.Read(p) }

func newCerts(cfg config.Certs, ex executor.Executor) *certCollector {
	var r certs.Reader = hostReader{}
	if ex != nil {
		r = ex // the privileged parent reads root-only certbot directories
	}
	every := cfg.Interval
	if every <= 0 {
		every = time.Hour
	}
	return &certCollector{r: r, every: every, opts: certs.Options{Paths: cfg.Paths, Ports: cfg.ProbePorts,
		Now: func() time.Time { return now() }}}
}

func (c *certCollector) loop(ctx context.Context) {
	t := time.NewTimer(5 * time.Second) // let the agent and the web server settle first
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c.rescan(ctx)
		t.Reset(c.every)
	}
}

func (c *certCollector) rescan(ctx context.Context) ([]certs.Cert, time.Time) {
	c.scanMu.Lock()
	defer c.scanMu.Unlock()
	list := certs.Scan(ctx, c.r, c.opts)
	at := now()
	c.mu.Lock()
	c.list, c.at = list, at
	c.mu.Unlock()
	return c.current(at)
}

// current returns a copy of the last scan with DaysLeft as of t.
func (c *certCollector) current(t time.Time) ([]certs.Cert, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := slices.Clone(c.list)
	for i := range out {
		if out[i].Error == "" {
			out[i].DaysLeft = certs.Days(out[i].NotAfter, t)
		}
	}
	return out, c.at
}

func (c *certCollector) Collect(context.Context) ([]Sample, error) {
	list, _ := c.current(now())
	var out []Sample
	for _, x := range list {
		if x.Error != "" {
			continue
		}
		l := map[string]string{"name": x.Name}
		out = addL(out, "cert.days_left", l, x.DaysLeft)
		out = addL(out, "cert.stale_served", l, b2f(x.Stale))
	}
	return out, nil
}

// CertsEnabled reports whether certificate monitoring runs on this agent.
func (m *Manager) CertsEnabled() bool { return m.certs != nil }

// Certs returns the latest certificate scan and when it ran (zero before the first scan).
func (m *Manager) Certs() ([]certs.Cert, time.Time) {
	if m.certs == nil {
		return nil, time.Time{}
	}
	return m.certs.current(now())
}

// RescanCerts scans certificates now, for checking a renewal without waiting for the next scheduled scan.
func (m *Manager) RescanCerts(ctx context.Context) ([]certs.Cert, time.Time) {
	if m.certs == nil {
		return nil, time.Time{}
	}
	return m.certs.rescan(ctx)
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
