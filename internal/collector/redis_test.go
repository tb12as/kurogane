package collector

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tb12as/serverman/internal/config"
	"github.com/tb12as/serverman/internal/executor"
	"github.com/tb12as/serverman/internal/hostfs"
)

// fakeRedis answers PING, AUTH, INFO (from fields) and SLOWLOG GET.
type fakeRedis struct {
	addr   string
	mu     sync.Mutex
	fields map[string]string
	pass   string // "" = no auth required
	conns  int
}

func newFakeRedis(t *testing.T, pass string) *fakeRedis {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	f := &fakeRedis{addr: l.Addr().String(), pass: pass, fields: map[string]string{
		"redis_version": "7.2.4", "redis_mode": "standalone", "role": "master", "uptime_in_seconds": "100",
		"used_memory": "50000000", "used_memory_rss": "60000000", "maxmemory": "100000000",
		"maxmemory_policy": "allkeys-lru", "mem_fragmentation_ratio": "1.2", "connected_clients": "8",
		"blocked_clients": "0", "maxclients": "10", "rdb_last_bgsave_status": "ok", "rdb_last_save_time": "1699999000",
		"rdb_changes_since_last_save": "5", "aof_enabled": "0", "connected_slaves": "1",
		"total_commands_processed": "1000", "keyspace_hits": "90", "keyspace_misses": "10", "evicted_keys": "0",
		"expired_keys": "0", "rejected_connections": "0", "total_net_input_bytes": "0", "total_net_output_bytes": "0",
		"db0": "keys=100,expires=10,avg_ttl=0", "db3": "keys=5,expires=0,avg_ttl=0"}}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.conns++
			f.mu.Unlock()
			go f.handle(c)
		}
	}()
	return f
}

func (f *fakeRedis) set(kv ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := 0; i < len(kv); i += 2 {
		f.fields[kv[i]] = kv[i+1]
	}
}

func (f *fakeRedis) handle(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	authed := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		n, _ := strconv.Atoi(strings.TrimSpace(line[1:]))
		var args []string
		for i := 0; i < n; i++ {
			r.ReadString('\n')
			v, _ := r.ReadString('\n')
			args = append(args, strings.TrimRight(v, "\r\n"))
		}
		f.mu.Lock()
		pass := f.pass
		var keys []string
		for k := range f.fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var info strings.Builder
		for _, k := range keys {
			info.WriteString(k + ":" + f.fields[k] + "\r\n")
		}
		f.mu.Unlock()
		var out string
		switch {
		case args[0] == "AUTH":
			if args[len(args)-1] == pass {
				authed, out = true, "+OK\r\n"
			} else {
				out = "-WRONGPASS invalid username-password pair\r\n"
			}
		case pass != "" && !authed:
			out = "-NOAUTH Authentication required.\r\n"
		case args[0] == "PING":
			out = "+PONG\r\n"
		case args[0] == "INFO":
			out = fmt.Sprintf("$%d\r\n%s\r\n", info.Len(), info.String())
		case args[0] == "SLOWLOG":
			out = "*1\r\n*4\r\n:1\r\n:1699999999\r\n:15000\r\n*2\r\n$3\r\nget\r\n$6\r\nsecret\r\n"
		default:
			out = "-ERR unknown\r\n"
		}
		if _, err := io.WriteString(c, out); err != nil {
			return
		}
	}
}

func samplesMap(ss []Sample) map[string]float64 {
	m := map[string]float64{}
	for _, s := range ss {
		m[s.Key()] = s.Value
	}
	return m
}

func redisRoot(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	old := hostfs.Root
	hostfs.Root = dir
	t.Cleanup(func() { hostfs.Root = old })
	for p, c := range files {
		full := filepath.Join(dir, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		os.WriteFile(full, []byte(c), 0o640)
	}
	return dir
}

func TestRedisMetricsAndRates(t *testing.T) {
	adv := clock(t)
	redisRoot(t, map[string]string{"etc/serverkeeper/redis.pass": "s3cret\n"})
	f := newFakeRedis(t, "s3cret")
	c := newRedis(config.Redis{Enabled: "auto", Instances: []config.RedisInstance{{Name: "cache", Addr: f.addr,
		PasswordFile: "/etc/serverkeeper/redis.pass"}}}, executor.NewFake(), 10*time.Second)
	c.poll(ctx)
	first := samplesMap(c.samples)
	for k, want := range map[string]float64{`redis.up{instance="cache"}`: 1, `redis.memory_used_pct{instance="cache"}`: 50,
		`redis.clients_pct{instance="cache"}`: 80, `redis.keys{db="db0",instance="cache"}`: 100,
		`redis.keys_total{instance="cache"}`: 105, `redis.replicas{instance="cache"}`: 1, `redis.rdb_ok{instance="cache"}`: 1} {
		if first[k] != want {
			t.Errorf("%s = %v, want %v", k, first[k], want)
		}
	}
	if _, ok := first[`redis.ops_ps{instance="cache"}`]; ok {
		t.Fatal("rates on the first poll")
	}
	if _, ok := first[`redis.aof_ok{instance="cache"}`]; ok {
		t.Fatal("aof_ok without AOF")
	}
	st := c.current()[0]
	if st.Status != RedisUp || st.Version != "7.2.4" || st.MaxMemoryPolicy != "allkeys-lru" || len(st.Keyspace) != 2 ||
		len(st.SlowLog) != 1 || st.SlowLog[0].Command != "GET" || st.HitRatio != nil {
		t.Fatalf("state = %+v", st)
	}

	adv(10 * time.Second)
	f.set("total_commands_processed", "2000", "keyspace_hits", "170", "keyspace_misses", "30", "evicted_keys", "50",
		"uptime_in_seconds", "110", "rdb_last_bgsave_status", "err", "aof_enabled", "1", "aof_last_write_status", "ok")
	c.poll(ctx)
	second := samplesMap(c.samples)
	for k, want := range map[string]float64{`redis.ops_ps{instance="cache"}`: 100, `redis.hit_ratio{instance="cache"}`: 80,
		`redis.evicted_keys_ps{instance="cache"}`: 5, `redis.rdb_ok{instance="cache"}`: 0, `redis.aof_ok{instance="cache"}`: 1} {
		if second[k] != want {
			t.Errorf("%s = %v, want %v", k, second[k], want)
		}
	}
	if st := c.current()[0]; st.HitRatio == nil || *st.HitRatio != 80 || st.OpsPS != 100 {
		t.Fatalf("state = %+v", st)
	}
	f.mu.Lock()
	conns := f.conns
	f.mu.Unlock()
	if conns != 1 {
		t.Fatalf("%d connections: the connection must be reused", conns)
	}

	// a restart (uptime went down) gives no rates for one poll
	adv(10 * time.Second)
	f.set("uptime_in_seconds", "5", "total_commands_processed", "10")
	c.poll(ctx)
	if _, ok := samplesMap(c.samples)[`redis.ops_ps{instance="cache"}`]; ok {
		t.Fatal("rate across a restart")
	}
	if got, _ := c.Collect(ctx); len(got) != len(c.samples) {
		t.Fatal("Collect")
	}
}

func TestRedisStates(t *testing.T) {
	clock(t)
	redisRoot(t, map[string]string{"etc/serverkeeper/wrong.pass": "nope"})
	locked := newFakeRedis(t, "s3cret")
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := l.Addr().String()
	l.Close()
	c := newRedis(config.Redis{Instances: []config.RedisInstance{
		{Name: "nopass", Addr: locked.addr},
		{Name: "wrong", Addr: locked.addr, PasswordFile: "/etc/serverkeeper/wrong.pass"},
		{Name: "dead", Addr: dead},
		{Name: "sock", Addr: "unix:/nonexistent/redis.sock"},
	}}, executor.NewFake(), time.Second)
	c.poll(ctx)
	by := map[string]RedisInstance{}
	for _, s := range c.current() {
		by[s.Name] = s
	}
	if s := by["nopass"]; s.Status != RedisNeedsCreds || !strings.Contains(s.Hint, "ACL SETUSER") {
		t.Errorf("nopass = %+v", s)
	}
	if s := by["wrong"]; s.Status != RedisAuthFailed {
		t.Errorf("wrong = %+v", s)
	}
	if s := by["dead"]; s.Status != RedisDown || s.Error == "" {
		t.Errorf("dead = %+v", s)
	}
	got := samplesMap(c.samples)
	if _, ok := got[`redis.up{instance="nopass"}`]; ok {
		t.Error("needs-credentials instance produced samples (it would alert)")
	}
	if got[`redis.up{instance="wrong"}`] != 0 || got[`redis.up{instance="dead"}`] != 0 || len(got) != 3 {
		t.Errorf("samples = %v", got)
	}
}

func TestRedisDetection(t *testing.T) {
	clock(t)
	f := newFakeRedis(t, "")
	_, port, _ := net.SplitHostPort(f.addr)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	_, deadPort, _ := net.SplitHostPort(l.Addr().String())
	l.Close()
	redisRoot(t, map[string]string{
		"etc/os-release":              "ID=ubuntu\n",
		"etc/redis/redis.conf":        "bind 127.0.0.1\nport " + port + "\n",
		"etc/redis/redis-cache.conf":  "port " + deadPort + "\nrequirepass pw\n",
		"etc/redis/redis-queue.conf":  "port " + deadPort + "\n",
		"etc/redis/redis-nosock.conf": "port 0\n",
	})
	ex := executor.NewFake()
	ex.Errors["systemctl is-enabled --quiet redis-server"] = errors.New("disabled") // but its port answers
	ex.Errors["systemctl is-enabled --quiet redis-server@queue"] = errors.New("disabled")
	c := newRedis(config.Redis{Enabled: "auto"}, ex, time.Second)
	var names []string
	for _, x := range c.targets {
		names = append(names, x.name+"|"+x.unit+"|"+strconv.FormatBool(x.hasPass))
	}
	if strings.Join(names, ",") != "redis|redis-server|false,redis-cache|redis-server@cache|true" {
		t.Fatalf("targets = %v", names)
	}
	if u := c.units(); strings.Join(u, ",") != "redis-server,redis-server@cache" {
		t.Fatalf("units = %v", u)
	}

	// enabled: true without any config file falls back to the default port
	redisRoot(t, nil)
	on := newRedis(config.Redis{Enabled: "true"}, executor.NewFake(), time.Second)
	if len(on.targets) != 1 || on.targets[0].target.Addr != "127.0.0.1:6379" {
		t.Fatalf("on = %+v", on.targets)
	}
	// auto with nothing installed: no targets, no samples, nothing logged as down
	auto := newRedis(config.Redis{}, executor.NewFake(), time.Second)
	auto.poll(ctx)
	if len(auto.targets) != 0 || len(auto.samples) != 0 || len(auto.current()) != 0 {
		t.Fatalf("auto = %+v", auto)
	}
	// RHEL names its unit redis
	redisRoot(t, map[string]string{"etc/os-release": "ID=\"rocky\"\nID_LIKE=\"rhel\"\n", "etc/redis/redis.conf": "port 1\n"})
	if n, u := redisNames("/etc/redis/redis.conf"); n != "redis" || u != "redis" {
		t.Fatalf("rhel = %s %s", n, u)
	}
}

func TestManagerRedis(t *testing.T) {
	clock(t)
	root(t, "t1")
	f := newFakeRedis(t, "")
	m := NewManager(config.Collector{Interval: time.Second, Redis: config.Redis{Enabled: "auto",
		Instances: []config.RedisInstance{{Addr: f.addr}}}}, executor.NewFake())
	m.redis.poll(ctx)
	s := m.collect(ctx, 0)
	get(t, s.Samples, `redis.up{instance="redis"}`)
	if len(s.Redis) != 1 || s.Redis[0].Status != RedisUp {
		t.Fatalf("snapshot redis = %+v", s.Redis)
	}
	off := NewManager(config.Collector{Interval: time.Second, Redis: config.Redis{Enabled: "false"}}, executor.NewFake())
	if off.redis != nil || len(off.Redis()) != 0 {
		t.Fatal("redis monitored while disabled")
	}
}
