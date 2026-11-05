package alert

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// MetricDef describes one metric a rule can use: what it measures, where it comes from, its unit, labels and the
// values the UI offers. It is the single source of truth behind GET /alerts/metrics, the rule builder and the
// readable rule summaries.
type MetricDef struct {
	Name        string            `json:"name"`
	Group       string            `json:"group"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Unit        string            `json:"unit"` // pct bytes bytes_ps count per_s ms s h days ratio bool
	Labels      []string          `json:"labels,omitempty"`
	Presets     []float64         `json:"presets"`
	Min         *float64          `json:"min,omitempty"`
	Max         *float64          `json:"max,omitempty"`
	States      map[string]string `json:"states,omitempty"` // bool metrics: "1" and "0" in words
	DefaultOp   string            `json:"default_op"`
	Computed    bool              `json:"computed,omitempty"` // derived by the alert engine, not stored as history
}

func fp(v float64) *float64 { return &v }

func def(name, group, title, unit, desc string) MetricDef {
	d := MetricDef{Name: name, Group: group, Title: title, Unit: unit, Description: desc, DefaultOp: ">", Min: fp(0)}
	switch unit {
	case "pct":
		d.Presets, d.Max = []float64{50, 70, 80, 85, 90, 95, 99}, fp(100)
	case "bool":
		d.Presets, d.Max, d.States = []float64{0, 1}, fp(1), map[string]string{"1": "up", "0": "down"}
		d.DefaultOp = "=="
	case "bytes":
		d.Presets = []float64{100 << 20, 500 << 20, 1 << 30, 2 << 30, 5 << 30, 10 << 30}
	case "bytes_ps":
		d.Presets = []float64{1 << 20, 10 << 20, 50 << 20, 100 << 20, 500 << 20}
	case "per_s":
		d.Presets = []float64{0, 1, 10, 100, 1000}
	case "count":
		d.Presets = []float64{0, 1, 10, 100, 1000}
	case "ms":
		d.Presets = []float64{10, 50, 100, 250, 500, 1000}
	case "s":
		d.Presets = []float64{60, 300, 900, 3600, 86400}
	case "h":
		d.Presets = []float64{6, 12, 24, 48, 72}
	case "days":
		d.Presets = []float64{3, 7, 14, 30}
	case "ratio":
		d.Presets = []float64{1.5, 2, 3, 5, 10}
	}
	return d
}

func (d MetricDef) l(labels ...string) MetricDef { d.Labels = labels; return d }
func (d MetricDef) p(p ...float64) MetricDef     { d.Presets = p; return d }
func (d MetricDef) below() MetricDef             { d.DefaultOp = "<"; return d }
func (d MetricDef) computed() MetricDef          { d.Computed = true; return d }
func (d MetricDef) states(one, zero string) MetricDef {
	d.States = map[string]string{"1": one, "0": zero}
	return d
}

const (
	srcStat    = "Read from /proc/stat every collection interval (10 s by default)."
	srcMem     = "Read from /proc/meminfo every collection interval."
	srcStatfs  = "Measured with statfs on each mounted filesystem every collection interval."
	srcDisks   = "Read from /proc/diskstats every collection interval."
	srcNet     = "Read from /proc/net/dev for every non-loopback interface."
	srcConns   = "Counted from the kernel's TCP socket table (netlink sock_diag, /proc/net/tcp as fallback)."
	srcProc    = "Counted from /proc/[pid] every collection interval."
	srcEngine  = "Computed by the alert engine from recent history; not stored as a chart series."
	srcRedis   = "From Redis INFO, polled on each monitored instance (collector.redis)."
	srcCerts   = "From the hourly TLS certificate scan (collector.certs), recomputed every tick."
	srcSelf    = "Measured on the Kurogane agent process itself."
	srcSystemd = "From systemctl show for each watched unit (collector.watch_services and detected web/Redis units)."
)

var catalog = []MetricDef{
	// CPU
	def("cpu.total_pct", "CPU", "CPU usage, all cores", "pct", "Share of CPU time spent busy across all cores. "+srcStat),
	def("cpu.user_pct", "CPU", "CPU time in user space", "pct", "Share of CPU time running application code. "+srcStat),
	def("cpu.system_pct", "CPU", "CPU time in the kernel", "pct", "Share of CPU time spent in the kernel. "+srcStat),
	def("cpu.iowait_pct", "CPU", "CPU waiting for disk I/O", "pct", "Share of CPU time idle while waiting for disk I/O; high values mean slow or saturated disks. "+srcStat).p(10, 20, 30, 50),
	def("cpu.steal_pct", "CPU", "CPU stolen by the hypervisor", "pct", "Share of time a virtual CPU waited for the host; high values mean a noisy neighbour or an oversold VPS. "+srcStat).p(5, 10, 20, 30),
	def("cpu.core_pct", "CPU", "CPU usage per core", "pct", "Busy share of each core separately. "+srcStat).l("core"),
	def("load.1", "CPU", "Load average, 1 minute", "count", "Runnable plus waiting processes averaged over 1 minute, from /proc/loadavg. Compare with the number of CPUs.").p(1, 2, 4, 8, 16),
	def("load.5", "CPU", "Load average, 5 minutes", "count", "Runnable plus waiting processes averaged over 5 minutes, from /proc/loadavg.").p(1, 2, 4, 8, 16),
	def("load.15", "CPU", "Load average, 15 minutes", "count", "Runnable plus waiting processes averaged over 15 minutes, from /proc/loadavg.").p(1, 2, 4, 8, 16),

	// Memory
	def("mem.used_pct", "Memory", "Memory used", "pct", "RAM in use, excluding reclaimable cache. "+srcMem),
	def("mem.available_pct", "Memory", "Memory available", "pct", "RAM the kernel can hand out without swapping (MemAvailable). Low values come before the OOM killer. "+srcMem).below().p(5, 10, 15, 20, 30),
	def("mem.available_bytes", "Memory", "Memory available (bytes)", "bytes", "MemAvailable in bytes. "+srcMem).below(),
	def("mem.used_bytes", "Memory", "Memory used (bytes)", "bytes", "RAM in use in bytes. "+srcMem),
	def("mem.total_bytes", "Memory", "Memory installed", "bytes", "Total RAM. "+srcMem),
	def("mem.cached_bytes", "Memory", "Page cache", "bytes", "File cache the kernel can reclaim. "+srcMem),
	def("mem.buffers_bytes", "Memory", "Buffers", "bytes", "Kernel buffers. "+srcMem),
	def("swap.used_pct", "Memory", "Swap used", "pct", "Share of swap space in use. "+srcMem).p(10, 25, 50, 75, 90),
	def("swap.used_bytes", "Memory", "Swap used (bytes)", "bytes", "Swap in use in bytes. "+srcMem),
	def("swap.total_bytes", "Memory", "Swap size", "bytes", "Total swap. "+srcMem),
	def("mem.oom_kills", "Memory", "OOM kills since boot", "count", "Processes killed by the out-of-memory killer since boot, from /proc/vmstat."),
	def("mem.oom_kills_delta", "Memory", "New OOM kills", "count", "Processes killed by the OOM killer since the previous sample, from /proc/vmstat.").p(0, 1, 5),

	// Disk
	def("disk.used_pct", "Disk", "Disk space used", "pct", "Share of each filesystem in use. "+srcStatfs).l("mount"),
	def("disk.free_bytes", "Disk", "Disk space free", "bytes", "Free space on each filesystem. "+srcStatfs).l("mount").below(),
	def("disk.used_bytes", "Disk", "Disk space used (bytes)", "bytes", "Used space on each filesystem. "+srcStatfs).l("mount"),
	def("disk.total_bytes", "Disk", "Disk size", "bytes", "Size of each filesystem. "+srcStatfs).l("mount"),
	def("disk.inodes_used_pct", "Disk", "Inodes used", "pct", "Share of inodes (file slots) in use; a full inode table stops new files even with free space. "+srcStatfs).l("mount"),
	def("disk.projected_full_h", "Disk", "Hours until disk full", "h", "Projected time until the filesystem fills at the recent growth rate. "+srcEngine).l("mount").below().computed(),

	// Disk I/O
	def("diskio.util_pct", "Disk I/O", "Disk busy time", "pct", "Share of time each block device was busy. "+srcDisks).l("dev"),
	def("diskio.await_ms", "Disk I/O", "Disk I/O wait", "ms", "Average time an I/O request took on each device. "+srcDisks).l("dev").p(10, 20, 50, 100, 250),
	def("diskio.read_bps", "Disk I/O", "Disk reads", "bytes_ps", "Bytes read per second on each device. "+srcDisks).l("dev"),
	def("diskio.write_bps", "Disk I/O", "Disk writes", "bytes_ps", "Bytes written per second on each device. "+srcDisks).l("dev"),
	def("diskio.read_iops", "Disk I/O", "Disk read operations", "per_s", "Read operations per second on each device. "+srcDisks).l("dev"),
	def("diskio.write_iops", "Disk I/O", "Disk write operations", "per_s", "Write operations per second on each device. "+srcDisks).l("dev"),

	// Network
	def("net.rx_bps_total", "Network", "Inbound traffic, all interfaces", "bytes_ps", "Bytes received per second over all non-loopback interfaces. "+srcNet),
	def("net.tx_bps_total", "Network", "Outbound traffic, all interfaces", "bytes_ps", "Bytes sent per second over all non-loopback interfaces. "+srcNet),
	def("net.rx_bps", "Network", "Inbound traffic per interface", "bytes_ps", "Bytes received per second on each interface. "+srcNet).l("iface"),
	def("net.tx_bps", "Network", "Outbound traffic per interface", "bytes_ps", "Bytes sent per second on each interface. "+srcNet).l("iface"),
	def("net.rx_pps", "Network", "Packets in per interface", "per_s", "Packets received per second on each interface. "+srcNet).l("iface"),
	def("net.tx_pps", "Network", "Packets out per interface", "per_s", "Packets sent per second on each interface. "+srcNet).l("iface"),
	def("net.rx_pps_total", "Network", "Packets in, all interfaces", "per_s", "Packets received per second over all interfaces. "+srcNet).p(1000, 10000, 50000, 100000),
	def("net.tx_pps_total", "Network", "Packets out, all interfaces", "per_s", "Packets sent per second over all interfaces. "+srcNet).p(1000, 10000, 50000, 100000),
	def("net.rx_errors_ps", "Network", "Receive errors", "per_s", "Receive errors per second on each interface. "+srcNet).l("iface"),
	def("net.tx_errors_ps", "Network", "Transmit errors", "per_s", "Transmit errors per second on each interface. "+srcNet).l("iface"),
	def("net.rx_drops_ps", "Network", "Dropped incoming packets", "per_s", "Incoming packets dropped per second on each interface. "+srcNet).l("iface"),
	def("net.tx_drops_ps", "Network", "Dropped outgoing packets", "per_s", "Outgoing packets dropped per second on each interface. "+srcNet).l("iface"),
	def("net.udp_pps", "Network", "UDP packets in", "per_s", "UDP datagrams received per second, from /proc/net/snmp.").p(1000, 10000, 50000, 100000),
	def("net.rx_baseline_ratio", "Network", "Inbound traffic vs usual", "ratio", "Inbound traffic divided by the usual level for this hour of the week (learned over 7 days). "+srcEngine).computed(),
	def("net.tx_baseline_ratio", "Network", "Outbound traffic vs usual", "ratio", "Outbound traffic divided by the usual level for this hour of the week (learned over 7 days). "+srcEngine).computed(),

	// Connections
	def("net.tcp.established", "Connections", "Open TCP connections", "count", "Established TCP connections. "+srcConns).p(100, 500, 1000, 5000, 10000),
	def("net.tcp.syn_recv", "Connections", "Half-open TCP connections (SYN_RECV)", "count", "Connections waiting for the client's final ACK; a flood of these is a SYN attack. "+srcConns).p(100, 250, 500, 1000, 5000),
	def("net.tcp.syn_sent", "Connections", "Outgoing connection attempts (SYN_SENT)", "count", "Connections this host is trying to open. "+srcConns).p(10, 50, 100, 500),
	def("net.tcp.time_wait", "Connections", "TCP connections in TIME_WAIT", "count", "Recently closed connections. "+srcConns).p(1000, 5000, 10000, 30000),
	def("net.tcp.close_wait", "Connections", "TCP connections in CLOSE_WAIT", "count", "Connections the peer closed but the local app did not; growth means an app is leaking sockets. "+srcConns).p(10, 50, 100, 500),
	def("net.tcp.fin_wait", "Connections", "TCP connections in FIN_WAIT", "count", "Connections closing. "+srcConns).p(100, 500, 1000),
	def("net.tcp.listen", "Connections", "Listening TCP sockets", "count", "Sockets in LISTEN state. "+srcConns),
	def("net.tcp.total", "Connections", "All TCP sockets", "count", "TCP sockets in any state. "+srcConns).p(1000, 5000, 10000, 50000),
	def("net.new_conns_ps", "Connections", "New connections per second", "per_s", "TCP connections opened per second (active and passive), from /proc/net/snmp.").p(50, 100, 500, 1000, 5000),
	def("net.new_conns_ratio", "Connections", "New connections vs usual", "ratio", "New connections per second divided by the usual level for this hour of the week. "+srcEngine).computed(),
	def("net.conns_per_ip_max", "Connections", "Most connections from one IP", "count", "Connections from the busiest single remote address. "+srcConns).p(50, 100, 200, 500),
	def("net.conns_per_subnet_max", "Connections", "Most connections from one /24", "count", "Connections from the busiest /24 subnet. "+srcConns).p(100, 200, 500, 1000),
	def("net.listening_ports", "Connections", "Listening ports", "count", "Distinct listening TCP/UDP ports. "+srcConns),
	def("net.anomaly", "Connections", "Traffic pattern", "bool", "1 when traffic or new connections are far above the learned baseline for this hour. "+srcEngine).states("anomalous", "normal").computed(),

	// Processes
	def("proc.total", "Processes", "Processes", "count", "Running processes. "+srcProc).p(200, 500, 1000, 2000),
	def("proc.running", "Processes", "Runnable processes", "count", "Processes running or ready to run. "+srcProc).p(4, 8, 16, 32),
	def("proc.zombies", "Processes", "Zombie processes", "count", "Exited processes their parent has not reaped; a growing number points to a buggy parent. "+srcProc).p(1, 5, 10, 50),
	def("proc.threads", "Processes", "Threads", "count", "Threads across all processes. "+srcProc).p(1000, 5000, 10000, 30000),

	// System
	def("sys.uptime_s", "System", "Uptime", "s", "Seconds since boot, from /proc/uptime. Below a few minutes means a reboot.").below().p(300, 600, 3600),
	def("sys.reboot_required", "System", "Reboot", "bool", "1 when installed updates need a reboot (/run/reboot-required or needs-restarting).").states("required", "not required"),
	def("sys.security_updates", "System", "Pending security updates", "count", "Security updates not installed yet, from apt or dnf, checked every few hours.").p(0, 1, 5, 10),
	def("sys.pending_updates", "System", "Pending updates", "count", "All updates not installed yet, from apt or dnf.").p(0, 10, 50, 100),

	// Services
	def("service.active", "Services", "Service", "bool", "1 when the systemd unit is active. "+srcSystemd).l("unit").states("running", "not running"),
	def("http.rps", "Services", "HTTP requests per second", "per_s", "Requests per second from the nginx access log tail (collector.nginx_log).").p(10, 100, 500, 1000),
	def("http.4xx_ps", "Services", "HTTP 4xx per second", "per_s", "Client error responses per second from the nginx access log tail.").p(1, 10, 50, 100),
	def("http.5xx_ps", "Services", "HTTP 5xx per second", "per_s", "Server error responses per second from the nginx access log tail.").p(0, 1, 5, 10),

	// Web servers
	def("web.config_ok", "Web servers", "Web server config test", "bool", "1 when nginx -t / apachectl configtest passes, tested every 15 minutes and after each site change.").l("server").states("passes", "fails"),
	def("web.sites", "Web servers", "Web sites", "count", "Sites per web server and state (enabled or disabled), from the parsed nginx/Apache configuration.").l("server", "state"),

	// TLS certificates
	def("cert.days_left", "TLS certificates", "Days until certificate expiry", "days", "Days until each certificate expires, negative once expired. "+srcCerts).l("name").below(),
	def("cert.stale_served", "TLS certificates", "Served certificate", "bool", "1 when a local port still serves an older certificate than the file on disk (renewed but not reloaded). "+srcCerts).l("name").states("stale", "current"),

	// Redis
	def("redis.up", "Redis", "Redis", "bool", "1 when the instance answers PING with Kurogane's credentials, 0 when it is down or rejects them. "+srcRedis).l("instance"),
	def("redis.ping_ms", "Redis", "Redis PING time", "ms", "Round trip of a PING measured by the agent. "+srcRedis).l("instance").p(5, 10, 50, 100, 250),
	def("redis.memory_used_pct", "Redis", "Redis memory used (of maxmemory)", "pct", "used_memory as a share of maxmemory; only reported when maxmemory is set. "+srcRedis).l("instance"),
	def("redis.memory_used_bytes", "Redis", "Redis memory used", "bytes", "used_memory. "+srcRedis).l("instance"),
	def("redis.memory_rss_bytes", "Redis", "Redis resident memory", "bytes", "used_memory_rss, as seen by the OS. "+srcRedis).l("instance"),
	def("redis.maxmemory_bytes", "Redis", "Redis maxmemory", "bytes", "The configured maxmemory, 0 when unlimited. "+srcRedis).l("instance"),
	def("redis.fragmentation_ratio", "Redis", "Redis memory fragmentation", "ratio", "mem_fragmentation_ratio: RSS divided by used memory. "+srcRedis).l("instance").p(1.5, 2, 3),
	def("redis.clients", "Redis", "Redis clients", "count", "connected_clients. "+srcRedis).l("instance").p(100, 500, 1000, 5000),
	def("redis.clients_pct", "Redis", "Redis clients (of maxclients)", "pct", "connected_clients as a share of maxclients. "+srcRedis).l("instance"),
	def("redis.blocked_clients", "Redis", "Redis blocked clients", "count", "Clients waiting on a blocking command (BLPOP and similar). "+srcRedis).l("instance").p(1, 10, 100),
	def("redis.ops_ps", "Redis", "Redis operations per second", "per_s", "Commands processed per second. "+srcRedis).l("instance").p(1000, 10000, 50000, 100000),
	def("redis.hit_ratio", "Redis", "Redis hit ratio", "pct", "Keyspace hits as a share of lookups over the last interval. "+srcRedis).l("instance").below().p(50, 70, 80, 90, 95),
	def("redis.evicted_keys_ps", "Redis", "Redis evictions per second", "per_s", "Keys evicted per second to stay under maxmemory. "+srcRedis).l("instance").p(0, 1, 10, 100),
	def("redis.expired_keys_ps", "Redis", "Redis expirations per second", "per_s", "Keys expired per second. "+srcRedis).l("instance"),
	def("redis.rejected_connections_ps", "Redis", "Redis rejected connections", "per_s", "Connections refused per second because maxclients was reached. "+srcRedis).l("instance").p(0, 1, 10),
	def("redis.net_in_bps", "Redis", "Redis network in", "bytes_ps", "Bytes received per second. "+srcRedis).l("instance"),
	def("redis.net_out_bps", "Redis", "Redis network out", "bytes_ps", "Bytes sent per second. "+srcRedis).l("instance"),
	def("redis.keys", "Redis", "Redis keys per database", "count", "Keys in each database. "+srcRedis).l("instance", "db").p(1000, 100000, 1000000, 10000000),
	def("redis.keys_total", "Redis", "Redis keys", "count", "Keys over all databases. "+srcRedis).l("instance").p(1000, 100000, 1000000, 10000000),
	def("redis.rdb_ok", "Redis", "Redis last save", "bool", "0 when the last RDB snapshot failed: changes would be lost on a restart. "+srcRedis).l("instance").states("ok", "failing"),
	def("redis.aof_ok", "Redis", "Redis AOF writes", "bool", "0 when AOF writes or rewrites fail; only reported with appendonly on. "+srcRedis).l("instance").states("ok", "failing"),
	def("redis.rdb_changes_since_save", "Redis", "Redis unsaved changes", "count", "Writes since the last successful RDB save. "+srcRedis).l("instance").p(1000, 10000, 100000, 1000000),
	def("redis.rdb_last_save_age_s", "Redis", "Seconds since Redis last saved", "s", "Time since the last successful RDB save. "+srcRedis).l("instance").p(3600, 21600, 86400, 172800),
	def("redis.uptime_s", "Redis", "Redis uptime", "s", "Seconds since the instance started. "+srcRedis).l("instance").below(),
	def("redis.replicas", "Redis", "Redis replicas connected", "count", "Replicas connected to a primary. "+srcRedis).l("instance").below().p(1, 2, 3),
	def("redis.replica_link_up", "Redis", "Redis replica link", "bool", "On a replica: 1 when its link to the primary is up. "+srcRedis).l("instance"),
	def("redis.replica_last_io_s", "Redis", "Seconds since the primary was heard", "s", "On a replica: time since the last message from the primary. "+srcRedis).l("instance").p(10, 30, 60, 300),

	// Agent
	def("agent.cpu_pct", "Agent", "Agent CPU usage", "pct", "CPU used by the Kurogane agent. "+srcSelf).p(1, 2, 5, 10, 25),
	def("agent.rss_bytes", "Agent", "Agent memory", "bytes", "Resident memory of the Kurogane agent. "+srcSelf).p(50<<20, 100<<20, 200<<20, 500<<20),
	def("agent.collect_lag_ms", "Agent", "Collection lag", "ms", "How late the last collection finished; growth means the host is overloaded. "+srcSelf).p(100, 500, 1000, 5000),
	def("agent.goroutines", "Agent", "Agent goroutines", "count", "Goroutines in the agent process. "+srcSelf).p(100, 500, 1000),
	def("agent.store_bytes", "Agent", "Metric store size", "bytes", "Size of the local metric history (agent.db). "+srcSelf).p(100<<20, 500<<20, 1<<30, 2<<30),
}

var catalogIdx = func() map[string]MetricDef {
	m := make(map[string]MetricDef, len(catalog))
	for _, d := range catalog {
		m[d.Name] = d
	}
	return m
}()

// Catalog returns every metric a rule can use, in display order.
func Catalog() []MetricDef {
	out := make([]MetricDef, len(catalog))
	copy(out, catalog)
	return out
}

// LookupMetric returns the definition of name.
func LookupMetric(name string) (MetricDef, bool) {
	d, ok := catalogIdx[name]
	return d, ok
}

// ---- conditions and summaries ----

// Condition is one comparison of a rule expression.
type Condition struct {
	Metric string            `json:"metric"`
	Labels map[string]string `json:"labels,omitempty"`
	Op     string            `json:"op"`
	Value  float64           `json:"value"`
}

// Conditions is a rule expression that is a flat list of comparisons joined by one operator.
type Conditions struct {
	Join  string      `json:"join"` // and | or
	Items []Condition `json:"items"`
}

// FlatConditions returns the comparisons of expr when they are joined by a single kind of operator (any
// grouping), or nil for mixed and/or. Unparseable expressions return the parse error.
func FlatConditions(expr string) (*Conditions, error) {
	n, err := parse(expr)
	if err != nil {
		return nil, err
	}
	var items []Condition
	joins := map[bool]bool{}
	var walk func(n node)
	walk = func(n node) {
		switch x := n.(type) {
		case *cmp:
			items = append(items, Condition{Metric: x.metric, Labels: x.labels, Op: x.op, Value: x.val})
		case *bin:
			joins[x.and] = true
			walk(x.l)
			walk(x.r)
		}
	}
	walk(n)
	if len(joins) > 1 {
		return nil, nil
	}
	c := &Conditions{Join: "and", Items: items}
	if joins[false] {
		c.Join = "or"
	}
	return c, nil
}

var opWords = map[string]string{">": "above", ">=": "at or above", "<": "below", "<=": "at or below", "==": "equal to",
	"!=": "not equal to"}

// FormatValue renders v in the metric's unit ("90 %", "1.0 GB", "14 days").
func FormatValue(d MetricDef, v float64) string {
	n := strconv.FormatFloat(v, 'f', -1, 64)
	switch d.Unit {
	case "pct":
		return n + " %"
	case "bytes":
		return bytesH(v)
	case "bytes_ps":
		return bytesH(v) + "/s"
	case "per_s":
		return n + "/s"
	case "ms":
		return n + " ms"
	case "s":
		return n + " s"
	case "h":
		return n + " h"
	case "days":
		if v == 1 {
			return "1 day"
		}
		return n + " days"
	case "ratio":
		return n + "×"
	}
	return n
}

// boolState names the state a bool comparison selects, or "" when it is not a plain is-up / is-down test.
func boolState(d MetricDef, op string, v float64) string {
	one, zero := d.States["1"], d.States["0"]
	switch {
	case (op == "==" && v == 1) || (op == "!=" && v == 0) || (op == ">" && v == 0) || (op == ">=" && v == 1):
		return one
	case (op == "==" && v == 0) || (op == "!=" && v == 1) || (op == "<" && v == 1) || (op == "<=" && v == 0):
		return zero
	}
	return ""
}

// Describe renders one condition as words: "Disk space used (mount /) above 85 %".
func Describe(c Condition) string {
	d, ok := LookupMetric(c.Metric)
	title := c.Metric
	if ok {
		title = d.Title
	}
	if len(c.Labels) > 0 {
		var ks []string
		for k := range c.Labels {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		var parts []string
		for _, k := range ks {
			parts = append(parts, k+" "+c.Labels[k])
		}
		title += " (" + strings.Join(parts, ", ") + ")"
	}
	if ok && d.Unit == "bool" {
		if s := boolState(d, c.Op, c.Value); s != "" {
			return title + " is " + s
		}
	}
	val := strconv.FormatFloat(c.Value, 'f', -1, 64)
	if ok {
		val = FormatValue(d, c.Value)
	}
	return title + " " + opWords[c.Op] + " " + val
}

// Summary renders a rule expression as a sentence, falling back to the expression itself.
func Summary(expr string) string {
	c, err := FlatConditions(expr)
	if err != nil || c == nil {
		return expr
	}
	parts := make([]string, len(c.Items))
	for i, x := range c.Items {
		parts[i] = Describe(x)
	}
	return strings.Join(parts, " "+c.Join+" ")
}

// CheckMetrics rejects metrics that are not in the catalog and label keys a metric does not have. The API applies
// it to rules created or edited there; rules from config.yaml are only parsed, so an upgrade never drops them.
func CheckMetrics(expr string) error {
	n, err := parse(expr)
	if err != nil {
		return err
	}
	var bad error
	var walk func(n node)
	walk = func(n node) {
		if bad != nil {
			return
		}
		switch x := n.(type) {
		case *cmp:
			d, ok := LookupMetric(x.metric)
			if !ok {
				bad = fmt.Errorf("unknown metric %q%s: see GET /alerts/metrics for the list", x.metric, suggest(x.metric))
				return
			}
			for k := range x.labels {
				if !containsStr(d.Labels, k) {
					want := "it has no labels"
					if len(d.Labels) > 0 {
						want = "use " + strings.Join(d.Labels, " or ")
					}
					bad = fmt.Errorf("metric %s has no label %q: %s", x.metric, k, want)
					return
				}
			}
		case *bin:
			walk(x.l)
			walk(x.r)
		}
	}
	walk(n)
	return bad
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// suggest returns ", did you mean X?" for the closest catalog name, if one is close enough.
func suggest(name string) string {
	best, bestD := "", 1<<30
	for _, d := range catalog {
		if strings.HasPrefix(d.Name, name+"_") || strings.HasPrefix(d.Name, name+".") {
			return ", did you mean " + d.Name + "?" // a truncated name: cpu.total -> cpu.total_pct
		}
		if dd := editDistance(name, d.Name); dd < bestD {
			best, bestD = d.Name, dd
		}
	}
	if bestD <= max(3, len(name)/3) {
		return ", did you mean " + best + "?"
	}
	return ""
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}
