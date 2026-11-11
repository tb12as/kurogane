package collector

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tb12as/kurogane/internal/config"
	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/hostfs"
)

var ctx = context.Background()

// root points hostfs at testdata/<name>.
func root(t *testing.T, name string) {
	t.Helper()
	old := hostfs.Root
	abs, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	hostfs.Root = abs
	t.Cleanup(func() { hostfs.Root = old })
}

// clock freezes now() and returns a function advancing it.
func clock(t *testing.T) func(time.Duration) {
	cur := time.Unix(1_700_000_000, 0)
	now = func() time.Time { return cur }
	t.Cleanup(func() { now = time.Now })
	return func(d time.Duration) { cur = cur.Add(d) }
}

// twoTicks collects at t1, then 10s later at t2.
func twoTicks(t *testing.T, c Collector) (first, second []Sample) {
	t.Helper()
	adv := clock(t)
	root(t, "t1")
	first, err := c.Collect(ctx)
	if err != nil {
		t.Fatalf("t1: %v", err)
	}
	adv(10 * time.Second)
	root(t, "t2")
	second, err = c.Collect(ctx)
	if err != nil {
		t.Fatalf("t2: %v", err)
	}
	return first, second
}

func get(t *testing.T, s []Sample, key string) float64 {
	t.Helper()
	for _, x := range s {
		if x.Key() == key {
			return x.Value
		}
	}
	t.Fatalf("missing %s in %v", key, keys(s))
	return 0
}

func has(s []Sample, key string) bool {
	for _, x := range s {
		if x.Key() == key {
			return true
		}
	}
	return false
}

func keys(s []Sample) []string {
	out := make([]string, len(s))
	for i, x := range s {
		out[i] = x.Key()
	}
	return out
}

func near(t *testing.T, s []Sample, key string, want float64) {
	t.Helper()
	if got := get(t, s, key); math.Abs(got-want) > 1e-6 {
		t.Errorf("%s = %v, want %v", key, got, want)
	}
}

func TestCPU(t *testing.T) {
	c := newCPU()
	a, b := twoTicks(t, c)
	if has(a, "cpu.total_pct") {
		t.Error("first tick must not report cpu percentages")
	}
	near(t, a, "load.1", 0.5)
	near(t, a, "load.15", 0.3)
	near(t, b, "cpu.total_pct", 50)
	near(t, b, "cpu.user_pct", 30)
	near(t, b, "cpu.system_pct", 15)
	near(t, b, "cpu.iowait_pct", 5)
	near(t, b, "cpu.steal_pct", 5)
	near(t, b, `cpu.core_pct{core="0"}`, 55)
	near(t, b, `cpu.core_pct{core="1"}`, 45)
	if c.cores != 2 {
		t.Errorf("cores = %d", c.cores)
	}
}

func TestMem(t *testing.T) {
	c := &memCollector{}
	a, b := twoTicks(t, c)
	near(t, a, "mem.total_bytes", 1000000*1024)
	near(t, a, "mem.used_pct", 60)
	near(t, a, "mem.available_pct", 40)
	near(t, a, "mem.cached_bytes", 200000*1024)
	near(t, a, "mem.buffers_bytes", 50000*1024)
	near(t, a, "swap.used_pct", 25)
	near(t, a, "swap.used_bytes", 50000*1024)
	near(t, a, "mem.oom_kills", 3)
	near(t, a, "mem.oom_kills_delta", 0)
	near(t, b, "mem.oom_kills", 5)
	near(t, b, "mem.oom_kills_delta", 2)
	if c.total != 1000000*1024 {
		t.Errorf("total = %d", c.total)
	}
}

func TestDisk(t *testing.T) {
	statfs = func(p string, st *syscall.Statfs_t) error {
		switch {
		case strings.HasSuffix(p, "/srv/my data"):
			*st = syscall.Statfs_t{Bsize: 4096, Blocks: 100, Bfree: 50, Bavail: 50}
		case strings.HasSuffix(p, "t1") || strings.HasSuffix(p, "t2"):
			*st = syscall.Statfs_t{Bsize: 4096, Blocks: 1000, Bfree: 400, Bavail: 300, Files: 100, Ffree: 25}
		default:
			return errors.New("unexpected statfs " + p)
		}
		return nil
	}
	t.Cleanup(func() { statfs = syscall.Statfs })
	c := newDisk()
	a, b := twoTicks(t, c)

	near(t, a, `disk.used_pct{mount="/"}`, 600.0/900*100)
	near(t, a, `disk.used_bytes{mount="/"}`, 600*4096)
	near(t, a, `disk.total_bytes{mount="/"}`, 1000*4096)
	near(t, a, `disk.free_bytes{mount="/"}`, 300*4096)
	near(t, a, `disk.inodes_used_pct{mount="/"}`, 75)
	near(t, a, `disk.used_pct{mount="/srv/my data"}`, 50)
	if has(a, `disk.used_pct{mount="/mnt/bind"}`) || has(a, `disk.used_pct{mount="/proc"}`) {
		t.Error("bind/pseudo mounts must be skipped")
	}
	if len(c.mounts) != 2 || c.mounts[1].Path != "/srv/my data" || c.mounts[0].FSType != "ext4" {
		t.Errorf("mounts = %+v", c.mounts)
	}
	if has(a, `diskio.read_bps{dev="sda"}`) {
		t.Error("first tick must not report io rates")
	}
	near(t, b, `diskio.read_bps{dev="sda"}`, 20480*512/10.0)
	near(t, b, `diskio.write_bps{dev="sda"}`, 20480*512/10.0)
	near(t, b, `diskio.read_iops{dev="sda"}`, 10)
	near(t, b, `diskio.write_iops{dev="sda"}`, 30)
	near(t, b, `diskio.await_ms{dev="sda"}`, 2)
	near(t, b, `diskio.util_pct{dev="sda"}`, 20)
	for _, d := range []string{"sda1", "loop0", "sdb"} {
		k := `diskio.read_bps{dev="` + d + `"}`
		if has(b, k) {
			t.Errorf("%s must be skipped", k)
		}
	}
}

func TestNet(t *testing.T) {
	c := newNet()
	a, b := twoTicks(t, c)
	if len(a) != 0 {
		t.Errorf("first tick: %v", keys(a))
	}
	near(t, b, `net.rx_bps{iface="eth0"}`, 10000)
	near(t, b, `net.tx_bps{iface="eth0"}`, 20000)
	near(t, b, `net.rx_pps{iface="eth0"}`, 100)
	near(t, b, `net.tx_pps{iface="eth0"}`, 200)
	near(t, b, `net.rx_errors_ps{iface="eth0"}`, 1)
	near(t, b, `net.tx_errors_ps{iface="eth0"}`, 0)
	near(t, b, `net.rx_drops_ps{iface="eth0"}`, 0)
	near(t, b, `net.tx_drops_ps{iface="eth0"}`, 1)
	near(t, b, `net.rx_bps{iface="lo"}`, 1000)
	near(t, b, "net.rx_bps_total", 10000) // lo and veth excluded
	near(t, b, "net.tx_bps_total", 20000)
	near(t, b, "net.rx_pps_total", 100)
	near(t, b, "net.tx_pps_total", 200)
	near(t, b, "net.new_conns_ps", 20)
	near(t, b, "net.udp_pps", 200)
	if has(b, `net.rx_bps{iface="veth1a2b"}`) {
		t.Error("veth must be skipped")
	}
}

func TestConnProc(t *testing.T) {
	clock(t)
	root(t, "t1")
	c := newConn()
	s, err := c.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	near(t, s, "net.tcp.established", 10)
	near(t, s, "net.tcp.syn_recv", 1)
	near(t, s, "net.tcp.time_wait", 1)
	near(t, s, "net.tcp.listen", 4)
	near(t, s, "net.tcp.total", 12)
	near(t, s, "net.tcp.syn_sent", 0)
	near(t, s, "net.conns_per_ip_max", 4)
	near(t, s, "net.conns_per_subnet_max", 5)
	near(t, s, "net.listening_ports", 3)

	in := c.info
	if !in.SynCookies || in.States["ESTABLISHED"] != 10 || in.States["LISTEN"] != 4 {
		t.Errorf("info = %+v", in)
	}
	if in.TopIPs[0] != (IPCount{"203.0.113.5", 4}) || in.TopIPs[1] != (IPCount{"198.51.100.7", 2}) {
		t.Errorf("top ips = %v", in.TopIPs)
	}
	if in.TopSubnets[0] != (IPCount{"203.0.113.0/24", 5}) || in.TopSubnets[1] != (IPCount{"198.51.100.0/24", 3}) {
		t.Errorf("top subnets = %v", in.TopSubnets)
	}
	for _, x := range in.TopIPs {
		if strings.HasPrefix(x.IP, "127.") {
			t.Errorf("loopback in top ips: %v", in.TopIPs)
		}
	}
	want := []PortCount{{80, 7}, {22, 2}, {5432, 1}}
	if len(in.TopPorts) != 3 || in.TopPorts[0] != want[0] || in.TopPorts[1] != want[1] || in.TopPorts[2] != want[2] {
		t.Errorf("top ports = %v", in.TopPorts)
	}
	l := map[string]string{}
	for _, x := range in.Listening {
		l[x.Proto+" "+x.Addr+":"+strconv.Itoa(x.Port)] = x.Process
	}
	if len(in.Listening) != 3 || l["tcp 0.0.0.0:80"] != "nginx" || l["tcp6 :::22"] != "sshd" {
		t.Errorf("listening = %+v", in.Listening)
	}
	if _, ok := l["tcp 127.0.0.1:5432"]; !ok {
		t.Errorf("listening = %+v", in.Listening)
	}

	// second tick reuses maps and must not double count
	s, _ = c.Collect(ctx)
	near(t, s, "net.tcp.established", 10)
}

func TestHexAddr(t *testing.T) {
	ip, port, ok := hexAddr([]byte("0100007F:0035"), false)
	if !ok || port != 53 || !isV4(&ip) || ip[12] != 127 || ip[15] != 1 {
		t.Errorf("v4 = %v %d %v", ip, port, ok)
	}
	if _, _, ok := hexAddr([]byte("zz"), false); ok {
		t.Error("bad addr accepted")
	}
	if _, _, ok := hexAddr([]byte("0100007F:0035"), true); ok {
		t.Error("v4 accepted as v6")
	}
	ip, _, _ = hexAddr([]byte("00000000000000000000000001000000:0016"), true)
	if !isLocal(&ip) {
		t.Error("::1 must be local")
	}
}

func TestConnNetlinkLive(t *testing.T) {
	if hostfs.Root != "/" {
		t.Skip("netlink needs the real root")
	}
	c := newConn()
	if _, err := c.Collect(ctx); err != nil {
		t.Fatal(err)
	}
	if c.noNetlink {
		t.Skip("sock_diag not available here")
	}
}

func TestProc(t *testing.T) {
	c := newProc()
	a, b := twoTicks(t, c)
	near(t, a, "proc.total", 5)
	near(t, a, "proc.running", 1)
	near(t, a, "proc.zombies", 1)
	near(t, a, "proc.threads", 8)
	near(t, b, "proc.total", 5)

	if len(c.topCPU) != 5 || c.topCPU[0].PID != 100 {
		t.Fatalf("top cpu = %+v", c.topCPU)
	}
	p := c.topCPU[0]
	if math.Abs(p.CPU-50) > 1e-9 || p.Name != "nginx: worker" || p.User != "www-data" || p.Cmd != "nginx: worker process" {
		t.Errorf("nginx = %+v", p)
	}
	if c.topCPU[1].PID != 200 || math.Abs(c.topCPU[1].CPU-2) > 1e-9 || c.topCPU[1].Cmd != "/usr/sbin/sshd -D" ||
		c.topCPU[1].User != "root" {
		t.Errorf("sshd = %+v", c.topCPU[1])
	}
	for _, x := range c.topCPU {
		if x.PID == 400 && (x.CPU != 0 || x.Name != "a) b" || x.User != "1234") {
			t.Errorf("reused pid must not report cpu: %+v", x)
		}
		if x.PID == 1 && x.Cmd != "[systemd]" {
			t.Errorf("no cmdline: %+v", x)
		}
	}
	if c.topMem[0].PID != 400 || c.topMem[1].PID != 200 || c.topMem[0].RSS != 3000*c.page {
		t.Errorf("top mem = %+v", c.topMem)
	}
}

func TestSystem(t *testing.T) {
	clock(t)
	root(t, "t1")
	ex := executor.NewFake()
	ex.Outputs["apt list --upgradable"] = "Listing...\n" +
		"openssl/noble-updates,noble-security 3.0.13-0ubuntu3.4 amd64 [upgradable from: 3.0.13-0ubuntu3.1]\n" +
		"curl/noble-updates 8.5.0-2ubuntu10.5 amd64 [upgradable from: 8.5.0-2ubuntu10.4]\n" +
		"libssl3t64/noble-security 3.0.13-0ubuntu3.4 amd64 [upgradable from: 3.0.13-0ubuntu3.1]\n"
	s := newSys(ex)
	a, err := s.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	near(t, a, "sys.uptime_s", 3600.5)
	near(t, a, "sys.reboot_required", 0)
	if has(a, "sys.pending_updates") {
		t.Error("updates must not be reported before the first check")
	}
	s.checkUpdates(ctx)
	root(t, "t2")
	b, _ := s.Collect(ctx)
	near(t, b, "sys.reboot_required", 1)
	near(t, b, "sys.pending_updates", 3)
	near(t, b, "sys.security_updates", 2)
	in := s.snapshot()
	if in.Hostname != "web-01" || in.Kernel != "6.8.0-45-generic" || in.OS != "Ubuntu 24.04.1 LTS" || !in.RebootRequired {
		t.Errorf("info = %+v", in)
	}
	if want := now().Add(-3610500 * time.Millisecond).Truncate(time.Second); !in.BootTime.Equal(want) {
		t.Errorf("boot = %v want %v", in.BootTime, want)
	}
	s.checkReboot(ctx) // ubuntu: no needs-restarting call
	if ex.Called("needs-restarting") {
		t.Error("needs-restarting on debian")
	}
}

func TestCountDnf(t *testing.T) {
	out := []byte("\nkernel.x86_64    5.14.0-427.el9    baseos\nopenssl.x86_64   1:3.0.7-27.el9    baseos\n" +
		"Obsoleting Packages\ngrub2.x86_64  1:2.06  baseos\n")
	if n := countDnf(out); n != 2 {
		t.Errorf("dnf = %d", n)
	}
	sec := []byte("RHSA-2024:1234 Important/Sec. openssl-1:3.0.7-27.el9.x86_64\n" +
		"RHSA-2024:2345 Low/Sec. curl-7.76.1-29.el9.x86_64\n")
	if n := countDnf(sec); n != 2 {
		t.Errorf("dnf security = %d", n)
	}
}

func TestServices(t *testing.T) {
	ex := executor.NewFake()
	k := "systemctl show -p ActiveState,SubState -- nginx mysql"
	ex.Outputs[k] = "ActiveState=active\nSubState=running\n\nActiveState=failed\nSubState=failed\n"
	c := newSvc(ex, []string{"nginx", "mysql"})
	s, err := c.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	near(t, s, `service.active{unit="nginx"}`, 1)
	near(t, s, `service.active{unit="mysql"}`, 0)
	if c.state[1] != (ServiceState{"mysql", "failed", "failed"}) {
		t.Errorf("state = %+v", c.state)
	}
	ex.Outputs[k] = "ActiveState=inactive\nSubState=dead\n\nActiveState=active\nSubState=running\n"
	s, _ = c.Collect(ctx)
	near(t, s, `service.active{unit="nginx"}`, 0)
	if c.prev["mysql"] != "active/running" {
		t.Errorf("prev = %v", c.prev)
	}
	if s, _ := newSvc(ex, nil).Collect(ctx); s != nil {
		t.Error("no units must not shell out")
	}
	ex.Errors[k] = errors.New("boom")
	if _, err := c.Collect(ctx); err == nil {
		t.Error("want error")
	}
}

func TestNginx(t *testing.T) {
	adv := clock(t)
	dir := t.TempDir()
	old := hostfs.Root
	hostfs.Root = dir
	t.Cleanup(func() { hostfs.Root = old })
	fixture, err := os.ReadFile("testdata/nginx/access.log")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "access.log")
	os.WriteFile(p, []byte("old line \"GET /\" 500 1\n"), 0o644)
	c := &nginxCollector{path: "/access.log"}
	if s, err := c.Collect(ctx); err != nil || s != nil {
		t.Fatalf("first: %v %v", s, err) // starts at end, no rates
	}

	// append fixture plus a partial line
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.Write(fixture)
	f.Write([]byte(`1.2.3.4 - - [x] "GET / HTTP/1.1" 50`))
	f.Close()
	adv(10 * time.Second)
	s, err := c.Collect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	near(t, s, "http.rps", 0.5)
	near(t, s, "http.4xx_ps", 0.1)
	near(t, s, "http.5xx_ps", 0.2)
	if len(c.top) != 2 || c.top[0].Count != 2 || c.top[1].Count != 2 {
		t.Errorf("top http clients = %v", c.top)
	}

	// finish the partial line
	f, _ = os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.Write([]byte("3 0 \"-\" \"-\"\n"))
	f.Close()
	adv(10 * time.Second)
	s, _ = c.Collect(ctx)
	near(t, s, "http.rps", 0.1)
	near(t, s, "http.5xx_ps", 0.1)

	// copytruncate rotation: file shrinks, read from the start
	os.WriteFile(p, []byte("a \"GET / HTTP/1.1\" 404 1\n"), 0o644)
	adv(10 * time.Second)
	s, _ = c.Collect(ctx)
	near(t, s, "http.4xx_ps", 0.1)

	// rename rotation: new inode
	os.Rename(p, p+".1")
	os.WriteFile(p, []byte("a \"GET / HTTP/1.1\" 200 1\nb \"GET / HTTP/1.1\" 200 1\n"), 0o644)
	adv(10 * time.Second)
	s, _ = c.Collect(ctx)
	near(t, s, "http.rps", 0.2)
	near(t, s, "http.4xx_ps", 0)
}

func TestStatus(t *testing.T) {
	for in, want := range map[string]int{
		`1.1.1.1 - - [t] "GET / HTTP/1.1" 200 1 "-" "-"`:       200,
		`x "GET /a\x22b HTTP/1.1" 503 0`:                       503,
		`no quotes 500`:                                        0,
		`203.0.113.5 - - [t] "GET /a HTTP/1.1" 304 - "-" "ua"`: 304, // apache logs "-" for zero bytes
		`x "unterminated 500`:                                  0,
		`x "GET /" 5`:                                          0,
	} {
		if got := status([]byte(in)); got != want {
			t.Errorf("status(%q) = %d want %d", in, got, want)
		}
	}
}

// CF-Connecting-IP is trusted only when $remote_addr is a Cloudflare edge
func TestClientIP(t *testing.T) {
	for in, want := range map[string]string{
		`104.16.0.1 - - [t] "GET / HTTP/1.1" 200 1 "-" "ua" "198.51.100.9"`:         "198.51.100.9",
		`2606:4700::1 - - [t] "GET / HTTP/1.1" 200 1 "-" "ua" "2001:db8::5"` + "\r": "2001:db8::5",
		`104.16.0.1 - - [t] "GET / HTTP/1.1" 200 1 "-" "ua" "-"`:                    "104.16.0.1",
		`104.16.0.1 - - [t] "GET / HTTP/1.1" 200 1 "-" "curl/8.0"`:                  "104.16.0.1",
		`203.0.113.5 - - [t] "GET / HTTP/1.1" 200 1 "-" "ua" "1.1.1.1"`:             "203.0.113.5",
		`garbage line`: "",
		// apache: LogFormat "... \"%{CF-Connecting-IP}i\"", the plain combined format and vhost_combined
		`162.158.1.1 - - [11/Nov/2026:10:00:00 +0700] "GET /a HTTP/1.1" 200 - "-" "ua" "198.51.100.9"`: "198.51.100.9",
		`203.0.113.5 - frank [11/Nov/2026:10:00:00 +0700] "GET /a HTTP/1.1" 304 - "-" "Mozilla/5.0"`:   "203.0.113.5",
		`shop.example.org:443 203.0.113.5 - - [t] "GET / HTTP/1.1" 200 1 "-" "ua"`:                     "",
	} {
		a, ok := clientIP([]byte(in))
		got := ""
		if ok {
			got = a.String()
		}
		if got != want {
			t.Errorf("clientIP(%q) = %q want %q", in, got, want)
		}
	}
	for ip, want := range map[string]bool{"173.245.48.1": true, "2a06:98c0::1": true, "::ffff:162.158.1.1": true,
		"203.0.113.5": false, "bogus": false} {
		if IsCloudflare(ip) != want {
			t.Errorf("IsCloudflare(%s) != %v", ip, want)
		}
	}
}

func TestSelf(t *testing.T) {
	c := &selfCollector{}
	a, _ := c.Collect(ctx)
	if has(a, "agent.cpu_pct") || get(t, a, "agent.rss_bytes") <= 0 || get(t, a, "agent.goroutines") < 1 {
		t.Errorf("self = %v", a)
	}
	time.Sleep(5 * time.Millisecond)
	b, _ := c.Collect(ctx)
	if v := get(t, b, "agent.cpu_pct"); v < 0 {
		t.Errorf("cpu = %v", v)
	}
}

func TestManager(t *testing.T) {
	statfs = func(p string, st *syscall.Statfs_t) error {
		*st = syscall.Statfs_t{Bsize: 4096, Blocks: 1000, Bfree: 400, Bavail: 300, Files: 10, Ffree: 5}
		return nil
	}
	t.Cleanup(func() { statfs = syscall.Statfs })
	adv := clock(t)
	root(t, "t1")
	ex := executor.NewFake()
	ex.Outputs["systemctl show -p ActiveState,SubState -- nginx"] = "ActiveState=active\nSubState=running\n"
	cfg := config.Collector{Interval: 10 * time.Second, WatchServices: []string{"nginx"}, NginxLog: "/nope.log"}
	m := NewManager(cfg, ex)
	m.StoreSize = func() int64 { return 4096 }
	if m.Latest() != nil {
		t.Fatal("latest before run")
	}
	m.collect(ctx, 0)
	adv(10 * time.Second)
	root(t, "t2")
	s := m.collect(ctx, 5*time.Millisecond)

	for _, k := range []string{"cpu.total_pct", "mem.used_pct", `disk.used_pct{mount="/"}`, `diskio.util_pct{dev="sda"}`,
		`net.rx_bps{iface="eth0"}`, "net.tcp.total", "proc.total", "sys.uptime_s", `service.active{unit="nginx"}`,
		"agent.rss_bytes", "agent.collect_lag_ms", "agent.store_bytes"} {
		get(t, s.Samples, k)
	}
	for _, x := range s.Samples {
		if x.TS != s.TS.UnixMilli() {
			t.Fatalf("ts not set on %s", x.Key())
		}
	}
	if s.Lag < 5*time.Millisecond || s.System.CPUs != 2 || s.System.MemTotal != 1000000*1024 ||
		s.System.Hostname != "web-01" || len(s.TopCPU) == 0 || len(s.TopMem) == 0 || len(s.Mounts) == 0 ||
		len(s.Services) != 1 || s.Conns.States == nil {
		t.Errorf("snapshot = %+v", s)
	}
	if v, ok := s.Value("cpu.total_pct", nil); !ok || v != 50 {
		t.Errorf("cpu = %v", v)
	}
	// nginx log missing: logged once a minute, others unaffected
	if _, ok := m.errAt["nginx"]; !ok {
		t.Error("nginx error not recorded")
	}
	at := m.errAt["nginx"]
	adv(10 * time.Second)
	m.collect(ctx, 0)
	if !m.errAt["nginx"].Equal(at) {
		t.Error("error logged again within a minute")
	}
}

func TestManagerRun(t *testing.T) {
	statfs = func(p string, st *syscall.Statfs_t) error { return errors.New("no") }
	t.Cleanup(func() { statfs = syscall.Statfs })
	root(t, "t1")
	m := NewManager(config.Collector{Interval: time.Second}, executor.NewFake())
	c, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	var got *Snapshot
	m.Run(c, func(s *Snapshot) { got = s })
	if got == nil || m.Latest() != got {
		t.Fatal("no snapshot published")
	}
}

func TestHelpers(t *testing.T) {
	if hexu([]byte("1aF")) != 0x1af || atou([]byte("12x")) != 12 || rate(5, 10, 1) != 0 || pct(1, 0) != 0 {
		t.Error("helpers")
	}
	if unescapeMount(`/a\040b\011c`) != "/a b\tc" || unescapeMount("/x") != "/x" {
		t.Error("unescape")
	}
	if f := fields([]byte("  a\tb  c\n"), nil); len(f) != 3 || string(f[2]) != "c" {
		t.Errorf("fields = %q", f)
	}
}
