package alert

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/tb12as/serverman/internal/collector"
	"github.com/tb12as/serverman/internal/db"
	"github.com/tb12as/serverman/internal/notify"
	"github.com/tb12as/serverman/internal/store"
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
	{"service_down", "Service down", "service.active < 1", "critical", 0, 0},
	{"updates_pending", "Reboot required / security updates pending", "sys.security_updates > 0 or sys.reboot_required > 0",
		"info", 0, 0},
	// fired by other packages through Engine.Fire
	{"ssh_bruteforce", "SSH brute force", "", "warning", 0, 0},
	{"ssh_login", "New SSH login", "", "info", 0, 0},
	{"ssh_config_changed", "SSH config changed", "", "info", 0, 0},
	{"ssh_rolled_back", "SSH config rolled back", "", "critical", 0, 0},
	{"hardening_drift", "Hardening drift", "", "warning", 0, 0},
	{"agent_offline", "Agent offline", "", "critical", 0, 0},
}

// critExpr escalates warning rules to critical (RAM < 5%, disk > 95%).
var critExpr = map[string]string{
	"mem_available_low": "mem.available_pct < 5",
	"disk_full":         "disk.used_pct > 95",
}

// onceRules send a firing message only; the next sample resolves them silently.
var onceRules = map[string]bool{"oom_kill": true}

var repeatOverride = map[string]time.Duration{"updates_pending": 24 * time.Hour}

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
	default:
		text = fmt.Sprintf("%s (value %.4g) for %s", r.Expr, in.v, durH(held))
		if len(l) > 0 {
			text += " · " + collector.SeriesKey("", l)
		}
	}
	return title, text, fields
}

// ddosText lists top sources/subnets/ports and SYN cookie status (§8.2).
func ddosText(s *collector.Snapshot) (string, []notify.Field) {
	syn, _ := s.Value("net.tcp.syn_recv", nil)
	nc, _ := s.Value("net.new_conns_ps", nil)
	text := fmt.Sprintf("SYN_RECV %.0f, new connections %.0f/s, max %.0f conns from one IP. Host-level detection only: "+
		"volumetric attacks need upstream mitigation (provider or CDN).", syn, nc, firstOr(s, "net.conns_per_ip_max"))
	var ips, nets, ports []string
	for i, x := range s.Conns.TopIPs {
		if i < 10 {
			ips = append(ips, fmt.Sprintf("%s (%d)", x.IP, x.Count))
		}
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
		{Name: "Top destination ports", Value: join(ports)}, {Name: "SYN cookies", Value: cookies}}
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
