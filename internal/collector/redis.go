package collector

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tb12as/kurogane/internal/config"
	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/hostfs"
	"github.com/tb12as/kurogane/internal/redisinfo"
)

// Redis instance states.
const (
	RedisUp         = "up"
	RedisDown       = "down"              // not reachable, or INFO failed: redis.up 0 and redis_down alerts
	RedisAuthFailed = "auth_failed"       // the password we had was rejected: redis.up 0 as well
	RedisNeedsCreds = "needs_credentials" // wants a password we do not have: shown in the UI, no samples, no alert
)

// RedisInstance is the per-instance detail kept in the snapshot.
type RedisInstance struct {
	Name            string    `json:"name"`
	Addr            string    `json:"addr"`
	ConfigFile      string    `json:"config_file,omitempty"`
	Status          string    `json:"status"`
	Error           string    `json:"error,omitempty"`
	Hint            string    `json:"hint,omitempty"`
	Version         string    `json:"version,omitempty"`
	Mode            string    `json:"mode,omitempty"`
	Role            string    `json:"role,omitempty"`
	UptimeS         float64   `json:"uptime_s,omitempty"`
	StartedAt       time.Time `json:"started_at,omitzero"`
	PingMs          float64   `json:"ping_ms,omitempty"`
	MemoryUsed      float64   `json:"memory_used"`
	MemoryRSS       float64   `json:"memory_rss"`
	MaxMemory       float64   `json:"maxmemory"`
	MaxMemoryPolicy string    `json:"maxmemory_policy,omitempty"`
	Clients         float64   `json:"clients"`
	MaxClients      float64   `json:"maxclients"`
	OpsPS           float64   `json:"ops_ps"`
	HitRatio        *float64  `json:"hit_ratio,omitempty"` // nil when there were no lookups
	EvictedKeys     float64   `json:"evicted_keys"`
	// totals since start
	TotalConns       float64               `json:"total_connections"`
	RejectedConns    float64               `json:"rejected_connections"`
	TotalCommands    float64               `json:"total_commands"`
	NetInBytes       float64               `json:"net_input_bytes"`
	NetOutBytes      float64               `json:"net_output_bytes"`
	ExpiredKeys      float64               `json:"expired_keys"`
	KeyspaceHits     float64               `json:"keyspace_hits"`
	KeyspaceMiss     float64               `json:"keyspace_misses"`
	RDBStatus        string                `json:"rdb_status,omitempty"`
	LastSave         time.Time             `json:"last_save,omitzero"`
	ChangesSinceSave float64               `json:"changes_since_save"`
	AOFEnabled       bool                  `json:"aof_enabled"`
	AOFStatus        string                `json:"aof_status,omitempty"`
	Replicas         int                   `json:"replicas"`
	MasterLink       string                `json:"master_link,omitempty"` // replicas: up | down
	Keyspace         []redisinfo.DB        `json:"keyspace"`
	SlowLog          []redisinfo.SlowEntry `json:"slowlog"`
}

// redisTarget is a resolved instance to poll.
type redisTarget struct {
	name     string
	file     string
	target   redisinfo.Target
	hasPass  bool
	unit     string
	explicit bool
}

type redisPrev struct {
	t                                         time.Time
	uptime                                    float64
	cmds, hits, misses, evicted, expired, rej float64
	netIn, netOut                             float64
	ok                                        bool
}

// redisCollector polls on its own loop (one INFO per instance per interval) so a slow or hung Redis can never
// delay the other collectors; Collect returns the latest result.
type redisCollector struct {
	ex       executor.Executor
	cfg      config.Redis
	interval time.Duration

	mu      sync.Mutex
	targets []redisTarget
	found   time.Time
	conns   map[string]*redisinfo.Conn
	prev    map[string]redisPrev
	samples []Sample
	state   []RedisInstance
	slowAt  map[string]time.Time
}

// Redis config files: Debian (/etc/redis/redis.conf, plus redis-<name>.conf for redis-server@<name>) and RHEL.
var redisConfs = []string{"/etc/redis/redis.conf", "/etc/redis.conf"}

// RedisDefaultAddr is polled when no config is usable (a var so tests can point it at a fake).
var RedisDefaultAddr = "127.0.0.1:6379"

func newRedis(cfg config.Redis, ex executor.Executor, interval time.Duration) *redisCollector {
	c := &redisCollector{ex: ex, cfg: cfg, interval: interval, conns: map[string]*redisinfo.Conn{},
		prev: map[string]redisPrev{}, slowAt: map[string]time.Time{}}
	c.detect(context.Background())
	return c
}

// units returns the systemd units of the detected instances (for the service watch).
func (c *redisCollector) units() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, t := range c.targets {
		if t.unit != "" && !slices.Contains(out, t.unit) {
			out = append(out, t.unit)
		}
	}
	return out
}

// detect resolves the instances to poll: configured ones, else every redis.conf whose unit is enabled or whose
// port answers (auto), else the default port (always with enabled: true, when it answers with auto).
func (c *redisCollector) detect(ctx context.Context) {
	var ts []redisTarget
	if len(c.cfg.Instances) > 0 {
		for i, in := range c.cfg.Instances {
			name := in.Name
			if name == "" {
				name = "redis"
				if i > 0 {
					name += "-" + strconv.Itoa(i+1)
				}
			}
			t := redisinfo.Target{Addr: in.Addr, Username: in.Username, TLS: in.TLS}
			if in.PasswordFile != "" {
				if b, err := c.ex.ReadFile(in.PasswordFile); err == nil {
					t.Password = strings.TrimSpace(string(b))
				} else {
					slog.Warn("redis password_file unreadable", "instance", name, "err", err)
				}
			}
			ts = append(ts, redisTarget{name: name, target: t, hasPass: t.Password != "", explicit: true})
		}
	} else {
		for _, f := range RedisConfFiles(ctx, c.ex) {
			rc, err := redisinfo.ParseConfig(c.ex, f)
			if err != nil {
				continue
			}
			t := rc.Target()
			if t.Addr == "" {
				continue
			}
			t.Password = rc.RequirePass
			name, unit := redisNames(f)
			rt := redisTarget{name: name, file: f, target: t, hasPass: t.Password != "", unit: unit}
			if c.cfg.Mode() == "on" || c.enabled(ctx, unit) || c.answers(ctx, t) {
				ts = append(ts, rt)
			}
		}
		// no usable config (none, or unreadable to a non-root agent): the default port, if auto finds it answering
		def := redisinfo.Target{Addr: RedisDefaultAddr}
		if len(ts) == 0 && (c.cfg.Mode() == "on" || c.answers(ctx, def)) {
			ts = append(ts, redisTarget{name: "redis", target: def})
		}
	}
	c.mu.Lock()
	c.targets, c.found = ts, now()
	c.mu.Unlock()
}

// RedisConfFiles lists the Redis config files on this host (also used by the REDIS-* hardening checks).
// /etc/redis is usually 0750 redis:redis, so the privsep worker falls back to the root executor.
func RedisConfFiles(ctx context.Context, ex executor.Executor) []string {
	out := []string{}
	for _, f := range redisConfs {
		if confExists(ex, f) {
			out = append(out, f)
		}
	}

	es, err := os.ReadDir(hostfs.P("/etc/redis")) // sorted
	for _, e := range es {
		if n := e.Name(); strings.HasPrefix(n, "redis-") && strings.HasSuffix(n, ".conf") {
			out = append(out, "/etc/redis/"+n)
		}
	}
	if !errors.Is(err, fs.ErrPermission) {
		return out
	}

	// unlistable dir: find instance configs through their redis-server@<name> units instead
	b, _ := ex.Run(ctx, "systemctl", "list-units", "--all", "--plain", "--no-legend", "redis-server@*")
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		inst, ok := strings.CutPrefix(strings.TrimSuffix(f[0], ".service"), "redis-server@")
		if !ok || inst == "" {
			continue
		}
		if p := "/etc/redis/redis-" + inst + ".conf"; !slices.Contains(out, p) && confExists(ex, p) {
			out = append(out, p)
		}
	}
	return out
}

// confExists stats f directly and asks the executor only when access is denied (a plain miss is not
// sent over, so the root side does not log a failed read for every absent path).
func confExists(ex executor.Executor, f string) bool {
	_, err := os.Stat(hostfs.P(f))
	if err == nil {
		return true
	}
	if !errors.Is(err, fs.ErrPermission) {
		return false
	}
	_, err = ex.ReadFile(f)
	return err == nil
}

// redisNames maps a config file to an instance name and its systemd unit.
func redisNames(file string) (name, unit string) {
	base := strings.TrimSuffix(path.Base(file), ".conf")
	if inst, ok := strings.CutPrefix(base, "redis-"); ok {
		return base, "redis-server@" + inst
	}
	if hostfs.DetectDistro().Family == "rhel" {
		return "redis", "redis"
	}
	return "redis", "redis-server"
}

func (c *redisCollector) enabled(ctx context.Context, unit string) bool {
	if unit == "" {
		return false
	}
	_, err := c.ex.Run(ctx, "systemctl", "is-enabled", "--quiet", unit)
	return err == nil
}

func (c *redisCollector) answers(ctx context.Context, t redisinfo.Target) bool {
	t.Timeout = 500 * time.Millisecond
	conn, err := redisinfo.Dial(ctx, t)
	if conn != nil {
		conn.Close()
	}
	return err == nil || errors.Is(err, redisinfo.ErrNoAuth) || errors.Is(err, redisinfo.ErrAuth)
}

func (c *redisCollector) loop(ctx context.Context) {
	t := time.NewTicker(c.interval)
	defer t.Stop()
	defer c.closeAll()
	for {
		c.poll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (c *redisCollector) closeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, conn := range c.conns {
		conn.Close()
		delete(c.conns, k)
	}
}

// RedisRedetect is how often instances are looked for again (Redis installed or removed later).
var RedisRedetect = time.Hour

// poll queries every instance once and stores samples and detail.
func (c *redisCollector) poll(ctx context.Context) {
	c.mu.Lock()
	stale := now().Sub(c.found) >= RedisRedetect
	c.mu.Unlock()
	if stale {
		c.detect(ctx)
	}
	c.mu.Lock()
	targets := slices.Clone(c.targets)
	c.mu.Unlock()
	var samples []Sample
	var state []RedisInstance
	for _, t := range targets {
		s, st := c.one(ctx, t)
		samples = append(samples, s...)
		state = append(state, st)
	}
	c.mu.Lock()
	c.samples, c.state = samples, state
	c.mu.Unlock()
}

func (c *redisCollector) conn(ctx context.Context, t redisTarget) (*redisinfo.Conn, error) {
	c.mu.Lock()
	conn := c.conns[t.name]
	c.mu.Unlock()
	if conn != nil {
		return conn, nil
	}
	conn, err := redisinfo.Dial(ctx, t.target)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.conns[t.name] = conn
	c.mu.Unlock()
	return conn, nil
}

func (c *redisCollector) drop(name string) {
	c.mu.Lock()
	if conn := c.conns[name]; conn != nil {
		conn.Close()
		delete(c.conns, name)
	}
	c.mu.Unlock()
}

// one polls one instance; a broken connection is retried once with a fresh dial.
func (c *redisCollector) one(ctx context.Context, t redisTarget) ([]Sample, RedisInstance) {
	st := RedisInstance{Name: t.name, Addr: t.target.Addr, ConfigFile: t.file, Keyspace: []redisinfo.DB{},
		SlowLog: []redisinfo.SlowEntry{}}
	l := map[string]string{"instance": t.name}
	var info redisinfo.Info
	var ping time.Duration
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		var conn *redisinfo.Conn
		if conn, err = c.conn(ctx, t); err != nil {
			break
		}
		if ping, err = conn.Ping(); err == nil {
			if info, err = conn.Info(); err == nil {
				c.slowlog(conn, &st)
				break
			}
		}
		c.drop(t.name)
	}
	switch {
	case errors.Is(err, redisinfo.ErrNoAuth) && !t.hasPass:
		st.Status = RedisNeedsCreds
		st.Hint = "This Redis requires a password. Set collector.redis.instances[].password_file, or create a " +
			"read-only user: ACL SETUSER kurogane on >PASSWORD -@all +ping +info +slowlog|get"
		return nil, st
	case errors.Is(err, redisinfo.ErrAuth), errors.Is(err, redisinfo.ErrNoAuth):
		st.Status, st.Error = RedisAuthFailed, err.Error()
		st.Hint = "Check the password (password_file or requirepass) and the ACL user."
		return []Sample{{Metric: "redis.up", Labels: l, Value: 0}}, st
	case err != nil:
		st.Status, st.Error = RedisDown, err.Error()
		if strings.HasPrefix(t.target.Addr, "unix:") && strings.Contains(err.Error(), "permission denied") {
			st.Hint = "The agent cannot open the socket: add the kurogane user to the redis group, or let " +
				"Redis listen on 127.0.0.1."
		}
		return []Sample{{Metric: "redis.up", Labels: l, Value: 0}}, st
	}
	st.Status = RedisUp
	st.PingMs = float64(ping.Microseconds()) / 1000
	return c.metrics(t.name, l, info, &st), st
}

// SlowLogEvery is how often the slow log is fetched (it changes slowly).
var SlowLogEvery = time.Minute

func (c *redisCollector) slowlog(conn *redisinfo.Conn, st *RedisInstance) {
	c.mu.Lock()
	due := now().Sub(c.slowAt[st.Name]) >= SlowLogEvery
	var last []redisinfo.SlowEntry
	for _, s := range c.state {
		if s.Name == st.Name {
			last = s.SlowLog
		}
	}
	c.mu.Unlock()
	if !due {
		st.SlowLog = last
		return
	}
	if sl, err := conn.SlowLog(10); err == nil {
		st.SlowLog = sl
	} else {
		st.SlowLog = last // e.g. an ACL user without +slowlog|get: keep going without it
	}
	if st.SlowLog == nil {
		st.SlowLog = []redisinfo.SlowEntry{}
	}
	c.mu.Lock()
	c.slowAt[st.Name] = now()
	c.mu.Unlock()
}

func b2fl(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// metrics turns INFO into samples and detail; rates come from counter deltas and are skipped after a restart.
func (c *redisCollector) metrics(name string, l map[string]string, in redisinfo.Info, st *RedisInstance) []Sample {
	t := now()
	st.Version, st.Mode, st.Role = in["redis_version"], in["redis_mode"], in["role"]
	st.UptimeS = in.Num("uptime_in_seconds")
	if st.UptimeS > 0 {
		st.StartedAt = t.Add(-time.Duration(st.UptimeS) * time.Second).UTC().Truncate(time.Second)
	}
	st.TotalConns, st.RejectedConns = in.Num("total_connections_received"), in.Num("rejected_connections")
	st.TotalCommands, st.ExpiredKeys = in.Num("total_commands_processed"), in.Num("expired_keys")
	st.NetInBytes, st.NetOutBytes = in.Num("total_net_input_bytes"), in.Num("total_net_output_bytes")
	st.KeyspaceHits, st.KeyspaceMiss = in.Num("keyspace_hits"), in.Num("keyspace_misses")
	st.MemoryUsed, st.MemoryRSS, st.MaxMemory = in.Num("used_memory"), in.Num("used_memory_rss"), in.Num("maxmemory")
	st.MaxMemoryPolicy = in["maxmemory_policy"]
	st.Clients, st.MaxClients = in.Num("connected_clients"), in.Num("maxclients")
	st.EvictedKeys = in.Num("evicted_keys")
	st.RDBStatus, st.AOFStatus = in["rdb_last_bgsave_status"], in["aof_last_write_status"]
	st.ChangesSinceSave = in.Num("rdb_changes_since_last_save")
	if ts := in.Num("rdb_last_save_time"); ts > 0 {
		st.LastSave = time.Unix(int64(ts), 0).UTC()
	}
	st.AOFEnabled = in["aof_enabled"] == "1"
	st.Replicas = int(in.Num("connected_slaves"))
	st.MasterLink = in["master_link_status"]
	if ks := in.Keyspace(); ks != nil {
		st.Keyspace = ks
	}

	var out []Sample
	add := func(m string, v float64) { out = append(out, Sample{Metric: m, Labels: l, Value: v}) }
	add("redis.up", 1)
	add("redis.ping_ms", st.PingMs)
	add("redis.uptime_s", st.UptimeS)
	add("redis.memory_used_bytes", st.MemoryUsed)
	add("redis.memory_rss_bytes", st.MemoryRSS)
	add("redis.maxmemory_bytes", st.MaxMemory)
	if st.MaxMemory > 0 {
		add("redis.memory_used_pct", pct(st.MemoryUsed, st.MaxMemory))
	}
	add("redis.fragmentation_ratio", in.Num("mem_fragmentation_ratio"))
	add("redis.clients", st.Clients)
	add("redis.blocked_clients", in.Num("blocked_clients"))
	if st.MaxClients > 0 {
		add("redis.clients_pct", pct(st.Clients, st.MaxClients))
	}
	add("redis.rdb_ok", b2fl(st.RDBStatus == "" || st.RDBStatus == "ok"))
	add("redis.rdb_changes_since_save", st.ChangesSinceSave)
	if !st.LastSave.IsZero() {
		add("redis.rdb_last_save_age_s", t.Sub(st.LastSave).Seconds())
	}
	if st.AOFEnabled {
		add("redis.aof_ok", b2fl(st.AOFStatus == "ok" && in["aof_last_bgrewrite_status"] != "err"))
	}
	switch st.Role {
	case "master":
		add("redis.replicas", float64(st.Replicas))
	case "slave":
		add("redis.replica_link_up", b2fl(st.MasterLink == "up"))
		if v, ok := in.Float("master_last_io_seconds_ago"); ok && v >= 0 {
			add("redis.replica_last_io_s", v)
		}
	}
	var keys float64
	for _, d := range st.Keyspace {
		keys += float64(d.Keys)
		out = append(out, Sample{Metric: "redis.keys", Labels: map[string]string{"instance": name, "db": d.Name},
			Value: float64(d.Keys)})
	}
	add("redis.keys_total", keys)

	cur := redisPrev{t: t, uptime: st.UptimeS, cmds: in.Num("total_commands_processed"), hits: in.Num("keyspace_hits"),
		misses: in.Num("keyspace_misses"), evicted: st.EvictedKeys, expired: in.Num("expired_keys"),
		rej: in.Num("rejected_connections"), netIn: in.Num("total_net_input_bytes"),
		netOut: in.Num("total_net_output_bytes"), ok: true}
	c.mu.Lock()
	p := c.prev[name]
	c.prev[name] = cur
	c.mu.Unlock()
	dt := t.Sub(p.t).Seconds()
	if !p.ok || dt <= 0 || cur.uptime < p.uptime || cur.cmds < p.cmds {
		return out // first poll or a restart: counters started again, no rates this time
	}
	r := func(a, b float64) float64 { return max(a-b, 0) / dt }
	st.OpsPS = r(cur.cmds, p.cmds)
	add("redis.ops_ps", st.OpsPS)
	add("redis.evicted_keys_ps", r(cur.evicted, p.evicted))
	add("redis.expired_keys_ps", r(cur.expired, p.expired))
	add("redis.rejected_connections_ps", r(cur.rej, p.rej))
	add("redis.net_in_bps", r(cur.netIn, p.netIn))
	add("redis.net_out_bps", r(cur.netOut, p.netOut))
	if h, m := cur.hits-p.hits, cur.misses-p.misses; h+m > 0 {
		v := pct(h, h+m)
		st.HitRatio = &v
		add("redis.hit_ratio", v)
	}
	return out
}

func (c *redisCollector) Collect(context.Context) ([]Sample, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.samples), nil
}

// current returns the latest per-instance detail.
func (c *redisCollector) current() []RedisInstance {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.state)
}
