package collector

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tb12as/kurogane/internal/certs"
	"github.com/tb12as/kurogane/internal/config"
	"github.com/tb12as/kurogane/internal/executor"
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
	certs    *certCollector  // nil when collector.certs.enabled is off
	redis    *redisCollector // nil when collector.redis.enabled is false
	nginx    *nginxCollector // nil when collector.nginx_log is empty
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
		m.nginx = &nginxCollector{path: cfg.NginxLog}
		m.cols = append(m.cols, named{"nginx", m.nginx})
	}
	if cfg.Redis.Mode() != "off" {
		m.redis = newRedis(cfg.Redis, ex, m.interval)
		m.cols = append(m.cols, named{"redis", m.redis})
		m.Watch(m.redis.units()...) // service_down covers redis-server without editing watch_services
	}
	if cfg.Certs.Enabled {
		m.certs = newCerts(cfg.Certs, ex)
		m.cols = append(m.cols, named{"certs", m.certs})
	}
	return m
}

// Redis returns the latest per-instance Redis detail (empty when none is monitored).
func (m *Manager) Redis() []RedisInstance {
	if m.redis == nil {
		return []RedisInstance{}
	}
	if st := m.redis.current(); st != nil {
		return st
	}
	return []RedisInstance{}
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
	// helper loops stop with ctx; Run returns only after they have, so nothing polls after shutdown
	var wg sync.WaitGroup
	defer wg.Wait()
	bg := func(f func(context.Context)) {
		wg.Add(1)
		go func() { defer wg.Done(); f(ctx) }()
	}
	bg(m.sys.loop)
	if m.certs != nil {
		bg(m.certs.loop)
	}
	if m.redis != nil {
		bg(m.redis.loop)
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
	conns := m.conn.info
	if m.nginx != nil {
		conns.TopHTTPClients, conns.TopHTTPFlows = m.nginx.top, m.nginx.topFlows
	}
	return &Snapshot{TS: start, Samples: all, System: sys, TopCPU: m.proc.topCPU, TopMem: m.proc.topMem,
		Conns: conns, Services: m.svc.state, Mounts: m.disk.mounts, Certs: cs, Redis: m.Redis(), Lag: lag}
}

// logErr logs a failing collector at most once a minute so one broken source cannot flood logs.
func (m *Manager) logErr(name string, err error) {
	if t, ok := m.errAt[name]; ok && now().Sub(t) < time.Minute {
		return
	}
	m.errAt[name] = now()
	slog.Warn("collector failed", "collector", name, "err", err)
}
