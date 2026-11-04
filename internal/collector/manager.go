package collector

import (
	"context"
	"log/slog"
	"slices"
	"sync/atomic"
	"time"

	"github.com/tb12as/serverman/internal/certs"
	"github.com/tb12as/serverman/internal/config"
	"github.com/tb12as/serverman/internal/executor"
)

type named struct {
	name string
	c    Collector
}

// Manager runs every collector each interval and keeps the latest Snapshot.
type Manager struct {
	// StoreSize, when set (e.g. to store.Store.Size), is reported as agent.store_bytes.
	StoreSize func() int64

	interval time.Duration
	cpu      *cpuCollector
	mem      *memCollector
	disk     *diskCollector
	conn     *connCollector
	proc     *procCollector
	sys      *sysCollector
	svc      *svcCollector
	certs    *certCollector // nil when collector.certs.enabled is off
	cols     []named

	latest atomic.Pointer[Snapshot]
	errAt  map[string]time.Time
	nprev  int
}

func NewManager(cfg config.Collector, ex executor.Executor) *Manager {
	m := &Manager{interval: cfg.Interval, cpu: newCPU(), mem: &memCollector{}, disk: newDisk(), conn: newConn(),
		proc: newProc(), sys: newSys(ex), svc: newSvc(ex, cfg.WatchServices), errAt: map[string]time.Time{}}
	if m.interval <= 0 {
		m.interval = 10 * time.Second
	}
	m.cols = []named{{"cpu", m.cpu}, {"mem", m.mem}, {"disk", m.disk}, {"net", newNet()}, {"conn", m.conn},
		{"proc", m.proc}, {"system", m.sys}, {"services", m.svc}, {"self", &selfCollector{}}}
	if cfg.NginxLog != "" {
		m.cols = append(m.cols, named{"nginx", &nginxCollector{path: cfg.NginxLog}})
	}
	if cfg.Certs.Enabled {
		m.certs = newCerts(cfg.Certs, ex)
		m.cols = append(m.cols, named{"certs", m.certs})
	}
	return m
}

// AddCollector registers an extra collector (e.g. the web site inventory); call before Run.
func (m *Manager) AddCollector(name string, c Collector) {
	m.cols = append(m.cols, named{name, c})
}

// Watch adds systemd units to the service watch (service.active / service_down); call before Run.
func (m *Manager) Watch(units ...string) {
	for _, u := range units {
		if !slices.Contains(m.svc.units, u) {
			m.svc.units = append(m.svc.units, u)
		}
	}
}

// Latest returns the most recent snapshot, or nil before the first full tick.
func (m *Manager) Latest() *Snapshot { return m.latest.Load() }

// Run collects until ctx is done, calling sink with every snapshot. A priming pass runs first
// so rates are available on the first published snapshot one second later.
func (m *Manager) Run(ctx context.Context, sink func(*Snapshot)) {
	go m.sys.loop(ctx)
	if m.certs != nil {
		go m.certs.loop(ctx)
	}
	m.collect(ctx, 0)
	sched := time.Now().Add(time.Second)
	t := time.NewTimer(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		delay := max(0, time.Since(sched))
		s := m.collect(ctx, delay)
		m.latest.Store(s)
		if sink != nil {
			sink(s)
		}
		sched = sched.Add(m.interval)
		if n := time.Now(); !sched.After(n) {
			sched = n.Add(m.interval) // skip missed ticks instead of bursting
		}
		t.Reset(time.Until(sched))
	}
}

func (m *Manager) collect(ctx context.Context, delay time.Duration) *Snapshot {
	start := now()
	all := make([]Sample, 0, m.nprev+8)
	for _, c := range m.cols {
		s, err := c.c.Collect(ctx)
		if err != nil {
			m.logErr(c.name, err)
		}
		all = append(all, s...)
	}
	lag := delay + now().Sub(start)
	all = add(all, "agent.collect_lag_ms", float64(lag)/float64(time.Millisecond))
	if m.StoreSize != nil {
		all = add(all, "agent.store_bytes", float64(m.StoreSize()))
	}
	m.nprev = len(all)
	ts := start.UnixMilli()
	for i := range all {
		all[i].TS = ts
	}
	sys := m.sys.snapshot()
	sys.CPUs, sys.MemTotal = m.cpu.cores, m.mem.total
	cs, _ := m.Certs()
	if cs == nil {
		cs = []certs.Cert{}
	}
	return &Snapshot{TS: start, Samples: all, System: sys, TopCPU: m.proc.topCPU, TopMem: m.proc.topMem,
		Conns: m.conn.info, Services: m.svc.state, Mounts: m.disk.mounts, Certs: cs, Lag: lag}
}

// logErr logs a failing collector at most once a minute so one broken source cannot flood logs.
func (m *Manager) logErr(name string, err error) {
	if t, ok := m.errAt[name]; ok && now().Sub(t) < time.Minute {
		return
	}
	m.errAt[name] = now()
	slog.Warn("collector failed", "collector", name, "err", err)
}
