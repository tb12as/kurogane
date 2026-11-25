package alert

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/tb12as/kurogane/internal/collector"
	"github.com/tb12as/kurogane/internal/db"
	"github.com/tb12as/kurogane/internal/notify"
	"github.com/tb12as/kurogane/internal/store"
)

// builtin is a PRD §8.1 default rule; tmpl's %g takes the (overridable) threshold.
type builtin struct {
	id, name, tmpl, sev string
	def                 float64
	dur                 time.Duration
}

func (b builtin) rule(th map[string]float64) db.AlertRule {
	r := db.AlertRule{ID: b.id, Name: b.name, Severity: b.sev, For: b.dur, Enabled: true, Builtin: true}
	if b.tmpl == "" {
		return r
	}
	v := b.def
	if x, ok := th[b.id]; ok {
		v = x
	}
	r.Expr = strings.ReplaceAll(b.tmpl, "%g", fmt.Sprintf("%g", v))
	return r
}

var builtins = []builtin{
	{"high_cpu", "High CPU", "cpu.total_pct > %g", "warning", 90, 5 * time.Minute},
	{"mem_available_low", "RAM almost full", "mem.available_pct < %g or swap.used_pct > 50", "warning", 10, 5 * time.Minute},
	{"oom_kill", "OOM kill", "mem.oom_kills_delta > %g", "critical", 0, 0},
	{"disk_full", "Disk almost full", "disk.used_pct > %g", "warning", 85, 0},
	{"disk_full_projected", "Disk projected full", "disk.projected_full_h < %g", "warning", 24, 0},
	{"high_iowait", "High I/O wait", "cpu.iowait_pct > %g", "warning", 30, 5 * time.Minute},
	{"high_traffic", "High traffic", "net.rx_baseline_ratio > %g or net.tx_baseline_ratio > %g", "warning", 3, 3 * time.Minute},
	{"ddos", "Possible DDoS / SYN flood", "net.tcp.syn_recv > %g or net.new_conns_ratio > 10 or net.conns_per_ip_max > 200 or net.anomaly > 0",
		"critical", 500, 0},
	// sliding last-minute counts from the access log tail (collector.nginx_log)
	{"http_ip_path_burst", "One client hammering a URL", "http.ip_path_max_1m > %g", "warning", 30, 0},
	{"http_path_burst", "URL request burst", "http.path_max_1m > %g", "warning", 300, 0},
	{"service_down", "Service down", "service.active < 1", "critical", 0, 0},
	{"updates_pending", "Reboot required / security updates pending", "sys.security_updates > 0 or sys.reboot_required > 0",
		"info", 0, 0},
	{"cert_expiring", "TLS certificate expiring", "cert.days_left < %g", "warning", 14, 0},
	// renew-then-reload can take a few minutes; an hour means the reload was really missed
	{"cert_stale_served", "Renewed TLS certificate not served", "cert.stale_served > %g", "warning", 0, time.Hour},
	{"redis_down", "Redis down", "redis.up < %g", "critical", 1, time.Minute},
	{"redis_persistence_failing", "Redis cannot save to disk", "redis.rdb_ok < 1 or redis.aof_ok < 1", "critical", 0, 0},
	{"redis_memory_high", "Redis memory almost full", "redis.memory_used_pct > %g", "warning", 90, 5 * time.Minute},
	{"redis_evicting", "Redis is evicting keys", "redis.evicted_keys_ps > %g", "warning", 0, 5 * time.Minute},
	{"redis_clients_high", "Redis connections almost full", "redis.clients_pct > %g or redis.rejected_connections_ps > 0",
		"warning", 80, 0},
	{"redis_replication_broken", "Redis replica disconnected", "redis.replica_link_up < 1", "critical", 0, 2 * time.Minute},
	{"redis_slow", "Redis slow to answer", "redis.ping_ms > %g", "warning", 50, 5 * time.Minute},
	// fired by other packages through Engine.Fire
	{"ssh_bruteforce", "SSH brute force", "", "warning", 0, 0},
	{"ssh_login", "New SSH login", "", "info", 0, 0},
	{"ssh_config_changed", "SSH config changed", "", "info", 0, 0},
	{"ssh_rolled_back", "SSH config rolled back", "", "critical", 0, 0},
	{"hardening_drift", "Hardening drift", "", "warning", 0, 0},
	{"agent_offline", "Agent offline", "", "critical", 0, 0},
	{"web_config_invalid", "Web server configuration test fails", "", "warning", 0, 0},
	{"site_change_rolled_back", "Web site change rolled back", "", "critical", 0, 0},
}

// critExpr escalates warning rules to critical (RAM < 5%, disk > 95%).
var critExpr = map[string]string{
	"mem_available_low": "mem.available_pct < 5",
	"disk_full":         "disk.used_pct > 95",
	"cert_expiring":     "cert.days_left < 3",
}

// onceRules send a firing message only; the next sample resolves them silently.
var onceRules = map[string]bool{"oom_kill": true}

var repeatOverride = map[string]time.Duration{"updates_pending": 24 * time.Hour, "cert_expiring": 24 * time.Hour,
	"cert_stale_served": 24 * time.Hour}

var titles = map[string]string{}

func init() {
	for _, b := range builtins {
		titles[b.id] = b.name
	}
}

// synthetic derives metrics the rules need: baseline ratios, anomaly flag, disk projection (AL-5, §8.1).
func (e *Engine) synthetic(s *collector.Snapshot, now time.Time) []collector.Sample {
	ts := now.UnixMilli()
	var out []collector.Sample
	add := func(m string, l map[string]string, v float64) {
		out = append(out, collector.Sample{Metric: m, Labels: l, TS: ts, Value: v})
	}
	add("net.rx_baseline_ratio", nil, e.ratio(s, "net.rx_bps_total", now))
	add("net.tx_baseline_ratio", nil, e.ratio(s, "net.tx_bps_total", now))
	add("net.new_conns_ratio", nil, e.ratio(s, "net.new_conns_ps", now))
	anom := 0.0
	for m := range floors {
		if x, ok := s.Value(m, nil); ok {
			if _, bad := e.anomalous(m, x, now); bad {
				anom = 1
			}
		}
	}
	add("net.anomaly", nil, anom)
	if now.Sub(e.projAt) >= time.Hour && e.d.Store != nil {
		e.projAt = now
		e.proj = projectDisks(e.d.Store, now)
	}
	for mount, h := range e.proj {
		add("disk.projected_full_h", map[string]string{"mount": mount}, h)
	}
	return out
}

// ratio is value / expected for the same hour-of-week once 7 days are learned; before that the absolute
// floor stands in as the static threshold. Below the floor the ratio is 0 so idle servers never alert.
func (e *Engine) ratio(s *collector.Snapshot, m string, now time.Time) float64 {
	x, ok := s.Value(m, nil)
	if !ok || x < floors[m] {
		return 0
	}
	b := e.base[m]
	if b == nil || !b.ready(now) {
		return x / floors[m]
	}
	mean, _ := b.expect(now)
	return x / math.Max(mean, floors[m]/10)
}

// projectDisks fits a line to the last 6 h of disk.used_pct per mount and returns hours until 100%.
func projectDisks(st *store.Store, now time.Time) map[string]float64 {
	res, err := st.Query(store.Query{Names: []string{"disk.used_pct"}, From: now.Add(-6 * time.Hour), To: now,
		Step: 10 * time.Minute}, 0)
	out := map[string]float64{}
	if err != nil {
		return out
	}
	for _, sr := range res {
		if len(sr.Points) < 6 {
			continue
		}
		var sx, sy, sxx, sxy float64
		n := float64(len(sr.Points))
		for _, p := range sr.Points {
			x := p[0] / 3.6e6 // hours
			sx, sy, sxx, sxy = sx+x, sy+p[1], sxx+x*x, sxy+x*p[1]
		}
		slope := (n*sxy - sx*sy) / (n*sxx - sx*sx)
		last := sr.Points[len(sr.Points)-1][1]
		if slope <= 0 || math.IsNaN(slope) {
			continue
		}
		out[sr.Labels["mount"]] = (100 - last) / slope
	}
	return out
}

// describe builds the human message, matching the PRD §8.3 example.
func describe(r *rule, in inst, s *collector.Snapshot, held time.Duration) (string, string, []notify.Field) {
	title := r.Name
	if title == "" {
		title = r.ID
	}
	l := in.labels
	var text string
	var fields []notify.Field
	switch r.ID {
	case "high_cpu":
		text = fmt.Sprintf("CPU %s for %s", pct(in.v), durH(held))
		fields = append(fields, notify.Field{Name: "Top processes", Value: topCPU(s)})
	case "mem_available_low":
		avail, _ := s.Value("mem.available_bytes", nil)
		total, _ := s.Value("mem.total_bytes", nil)
		ap, _ := s.Value("mem.available_pct", nil)
		sw, _ := s.Value("swap.used_pct", nil)
		text = fmt.Sprintf("Available memory %s (%s of %s) for %s, swap %s used", pct(ap), bytesH(avail), bytesH(total),
			durH(held), pct(sw))
		fields = append(fields, notify.Field{Name: "Top processes", Value: topMem(s)})
	case "oom_kill":
		text = fmt.Sprintf("%.0f process(es) killed by the OOM killer", in.v)
		fields = append(fields, notify.Field{Name: "Top processes", Value: topMem(s)})
	case "disk_full":
		free, _ := s.Value("disk.free_bytes", map[string]string{"mount": l["mount"]})
		text = fmt.Sprintf("Mount %s is %s full (%s free)", l["mount"], pct(in.v), bytesH(free))
	case "disk_full_projected":
		text = fmt.Sprintf("Mount %s projected full in %.1f h at the current growth rate", l["mount"], in.v)
	case "high_iowait":
		text = fmt.Sprintf("I/O wait %s for %s", pct(in.v), durH(held))
	case "high_traffic":
		rx, _ := s.Value("net.rx_bps_total", nil)
		tx, _ := s.Value("net.tx_bps_total", nil)
		text = fmt.Sprintf("Traffic rx %s/s, tx %s/s (%.1fx the usual level for this hour)", bytesH(rx), bytesH(tx), in.v)
	case "ddos":
		text, fields = ddosText(s)
	case "http_ip_path_burst", "http_path_burst":
		text, fields = burstText(r.ID, in.v, s)
	case "service_down":
		sub := ""
		for _, sv := range s.Services {
			if sv.Unit == l["unit"] {
				sub = sv.Active + "/" + sv.Sub
			}
		}
		text = fmt.Sprintf("Watched unit %s is not active (%s)", l["unit"], sub)
	case "updates_pending":
		text = fmt.Sprintf("%d security updates pending, reboot required: %v", s.System.SecurityUpdates, s.System.RebootRequired)
	case "redis_down", "redis_persistence_failing", "redis_memory_high", "redis_evicting", "redis_clients_high",
		"redis_replication_broken", "redis_slow":
		text = redisText(r.ID, l["instance"], s, in.v)
	case "cert_expiring", "cert_stale_served":
		text, fields = certText(r.ID, l["name"], s)
	default:
		text = fmt.Sprintf("%s (value %.4g) for %s", r.Expr, in.v, durH(held))
		if len(l) > 0 {
			text += " · " + collector.SeriesKey("", l)
		}
	}
	return title, text, fields
}

// redisText describes a Redis alert with the instance's own numbers and the usual fix.
func redisText(id, name string, s *collector.Snapshot, v float64) string {
	var in collector.RedisInstance
	for _, x := range s.Redis {
		if x.Name == name {
			in = x
		}
	}
	who := "Redis " + name
	if in.Addr != "" {
		who += " (" + in.Addr + ")"
	}
	switch id {
	case "redis_down":
		if in.Status == collector.RedisAuthFailed {
			return who + " rejects Kurogane's credentials: check password_file or requirepass and the ACL user."
		}
		msg := who + " does not answer"
		if in.Error != "" {
			msg += ": " + in.Error
		}
		return msg + ". Check `systemctl status redis-server` and the Redis log."
	case "redis_persistence_failing":
		what := "the last RDB save failed"
		if in.RDBStatus == "ok" {
			what = "AOF writes are failing"
		}
		return fmt.Sprintf("%s: %s, %.0f changes are not on disk and would be lost on a restart. Usually a full "+
			"disk, wrong permissions on Redis's dir, or a failed fork (vm.overcommit_memory).", who, what, in.ChangesSinceSave)
	case "redis_memory_high":
		return fmt.Sprintf("%s uses %s of maxmemory %s (%s). Policy %s: when full, Redis evicts keys or rejects "+
			"writes.", who, pct(v), bytesH(in.MaxMemory), bytesH(in.MemoryUsed), in.MaxMemoryPolicy)
	case "redis_evicting":
		return fmt.Sprintf("%s is evicting %.1f keys/s to stay under maxmemory %s (policy %s). Fine for a pure "+
			"cache; data loss for anything else: raise maxmemory or find what grew.", who, v, bytesH(in.MaxMemory),
			in.MaxMemoryPolicy)
	case "redis_clients_high":
		return fmt.Sprintf("%s has %.0f of %.0f client connections; new connections are refused when it is full. "+
			"Look for a connection leak or raise maxclients.", who, in.Clients, in.MaxClients)
	case "redis_replication_broken":
		return who + " lost its link to the primary: reads may be stale. Check the network and the primary's log."
	case "redis_slow":
		return fmt.Sprintf("%s takes %.0f ms to answer PING: look for slow commands (KEYS, big SMEMBERS) in its "+
			"slow log, swapping, or a busy CPU.", who, v)
	}
	return who
}

// certText names the certificate, its expiry and what to do about it.
func certText(id, name string, s *collector.Snapshot) (string, []notify.Field) {
	for _, c := range s.Certs {
		if c.Name != name {
			continue
		}
		var fields []notify.Field
		if c.Path != "" {
			fields = append(fields, notify.Field{Name: "File", Value: c.Path})
		}
		if c.ServedPort != 0 {
			fields = append(fields, notify.Field{Name: "Served on", Value: fmt.Sprintf("127.0.0.1:%d", c.ServedPort)})
		}
		if id == "cert_stale_served" {
			return fmt.Sprintf("%s was renewed on disk (valid until %s) but the server still sends the old "+
				"certificate, valid until %s. Reload the web server (for nginx: systemctl reload nginx).", name,
				c.NotAfter.Format(time.DateOnly), c.ServedNotAfter.Format(time.DateOnly)), fields
		}
		when := fmt.Sprintf("expires in %.1f days", c.DaysLeft)
		if c.DaysLeft < 0 {
			when = fmt.Sprintf("expired %.1f days ago", -c.DaysLeft)
		}
		hint := "Renew it and reload the server using it."
		if c.Origin == "letsencrypt" {
			hint = "Automatic renewal is failing: run `certbot renew --dry-run` to see why."
		}
		return fmt.Sprintf("Certificate %s %s (%s, issuer %s). %s", name, when,
			c.NotAfter.Format(time.DateOnly), c.Issuer, hint), fields
	}
	return "Certificate " + name + " is expiring", nil
}

// ddosText lists top sources/subnets/ports and SYN cookie status (§8.2).
func ddosText(s *collector.Snapshot) (string, []notify.Field) {
	syn, _ := s.Value("net.tcp.syn_recv", nil)
	nc, _ := s.Value("net.new_conns_ps", nil)
	text := fmt.Sprintf("SYN_RECV %.0f, new connections %.0f/s, max %.0f conns from one IP. Host-level detection only: "+
		"volumetric attacks need upstream mitigation (provider or CDN).", syn, nc, firstOr(s, "net.conns_per_ip_max"))
	var ips, nets, ports, http []string
	for i, x := range s.Conns.TopIPs {
		if i >= 10 {
			break
		}
		cf := ""
		if collector.IsCloudflare(x.IP) {
			cf = ", Cloudflare"
		}
		ips = append(ips, fmt.Sprintf("%s (%d%s)", x.IP, x.Count, cf))
	}
	if len(s.Conns.TopIPs) > 0 && collector.IsCloudflare(s.Conns.TopIPs[0].IP) {
		text += " Traffic arrives through Cloudflare: block offenders there (WAF, rate limiting), not on this host."
	}
	for _, x := range s.Conns.TopHTTPClients {
		http = append(http, fmt.Sprintf("%s (%d req)", x.IP, x.Count))
	}
	for i, x := range s.Conns.TopSubnets {
		if i < 10 {
			nets = append(nets, fmt.Sprintf("%s (%d)", x.IP, x.Count))
		}
	}
	for i, x := range s.Conns.TopPorts {
		if i < 10 {
			ports = append(ports, fmt.Sprintf("%d (%d)", x.Port, x.Count))
		}
	}
	cookies := "off"
	if s.Conns.SynCookies {
		cookies = "on"
	}
	return text, []notify.Field{{Name: "Top source IPs", Value: join(ips)}, {Name: "Top subnets", Value: join(nets)},
		{Name: "Top destination ports", Value: join(ports)}, {Name: "SYN cookies", Value: cookies},
		{Name: "Top HTTP clients (real IP)", Value: join(http)},
		{Name: "Top TCP flows (source -> port)", Value: flows(s.Conns.TopFlows, "")},
		{Name: "Top HTTP requests (client -> request)", Value: flows(s.Conns.TopHTTPFlows, " req")}}
}

// burstText names the client/request behind an http burst rule from the snapshot's last-minute estimates.
func burstText(id string, v float64, s *collector.Snapshot) (string, []notify.Field) {
	fs, ps := s.Conns.BurstHTTPFlows, s.Conns.BurstHTTPPaths
	if id == "http_ip_path_burst" {
		if len(fs) == 0 {
			return fmt.Sprintf("One client requested the same URL %.0f times in the last minute", v), nil
		}
		return fmt.Sprintf("%s requested %s %d times in the last minute", fs[0].IP, fs[0].Dest, fs[0].Count),
			[]notify.Field{{Name: "Top clients -> request (last minute)", Value: flows(fs, " req")}}
	}
	if len(ps) == 0 {
		return fmt.Sprintf("One URL was requested %.0f times in the last minute", v), nil
	}
	p := ps[0]
	reqs := make([]string, 0, len(ps))
	for _, x := range ps {
		reqs = append(reqs, fmt.Sprintf("%s (%d req, %d IPs)", x.Path, x.Count, x.IPs))
	}
	var clients []collector.Flow
	for _, f := range fs {
		if f.Dest == p.Path {
			clients = append(clients, f)
		}
	}
	return fmt.Sprintf("%s requested %d times in the last minute by %d client IPs", p.Path, p.Count, p.IPs),
		[]notify.Field{{Name: "Top requests (last minute)", Value: join(reqs)},
			{Name: "Top clients for this request", Value: flows(clients, " req")}}
}

func flows(fs []collector.Flow, unit string) string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		cf := ""
		if f.Cloudflare {
			cf = ", Cloudflare"
		}
		out = append(out, fmt.Sprintf("%s -> %s (%d%s%s)", f.IP, f.Dest, f.Count, unit, cf))
	}
	return join(out)
}

func firstOr(s *collector.Snapshot, m string) float64 {
	v, _ := s.Value(m, nil)
	return v
}

func join(s []string) string {
	if len(s) == 0 {
		return "-"
	}
	return strings.Join(s, ", ")
}

func topMem(s *collector.Snapshot) string {
	ps := append([]collector.Proc{}, s.TopMem...)
	sort.Slice(ps, func(i, j int) bool { return ps[i].RSS > ps[j].RSS })
	var out []string
	for i, p := range ps {
		if i == 3 {
			break
		}
		out = append(out, p.Name+" "+bytesH(float64(p.RSS)))
	}
	return join(out)
}

func topCPU(s *collector.Snapshot) string {
	var out []string
	for i, p := range s.TopCPU {
		if i == 3 {
			break
		}
		out = append(out, fmt.Sprintf("%s %.0f%%", p.Name, p.CPU))
	}
	return join(out)
}
