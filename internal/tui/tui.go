// Package tui is the `kurogane top` live dashboard (PM-3): a thin client over /metrics/current, /status and
// /ssh/sessions that shows what the web Overview and server page show.
package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/tb12as/kurogane/internal/certs"
	"github.com/tb12as/kurogane/internal/collector"
	"github.com/tb12as/kurogane/internal/db"
	"github.com/tb12as/kurogane/internal/sshmgr"
)

// Status is the part of GET /status the dashboard shows.
type Status struct {
	ServerName string `json:"server_name"`
	Version    string `json:"version"`
	Hardening  *struct {
		Score     float64   `json:"score"`
		Grade     string    `json:"grade"`
		ScannedAt time.Time `json:"scanned_at"`
	} `json:"hardening"`
	Alerts []db.AlertEvent `json:"active_alerts"`
}

// Data is one refresh. Snap is required; Status and Sessions are optional and their fetch errors go to Warn.
type Data struct {
	Snap     *collector.Snapshot
	Status   *Status
	Sessions []sshmgr.Session
	Warn     []string
}

// Fetch returns the agent's latest data; an error means the snapshot itself is unavailable.
type Fetch func() (*Data, error)

const poll = 2 * time.Second

// Run starts the dashboard and blocks until the user quits.
func Run(fetch Fetch) error {
	_, err := tea.NewProgram(newModel(fetch), tea.WithAltScreen()).Run()
	return err
}

type dataMsg struct {
	d   *Data
	err error
}

type tickMsg struct{}

type model struct {
	fetch  Fetch
	d      *Data
	err    error
	byMem  bool
	width  int
	height int // 0 until the first WindowSizeMsg: render everything
	off    int // first body line shown
}

func newModel(f Fetch) model { return model{fetch: f, width: 100} }

func (m model) load() tea.Cmd {
	return func() tea.Msg {
		d, err := m.fetch()
		return dataMsg{d, err}
	}
}

func (m model) Init() tea.Cmd { return m.load() }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "s", "tab":
			m.byMem = !m.byMem
		case "c":
			m.byMem = false
		case "m":
			m.byMem = true
		case "down", "j":
			m.scroll(1)
		case "up", "k":
			m.scroll(-1)
		case "pgdown", " ", "f":
			m.scroll(m.page())
		case "pgup", "b":
			m.scroll(-m.page())
		case "home", "g":
			m.off = 0
		case "end", "G":
			m.scroll(1 << 20)
		}
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.scroll(0)
	case dataMsg:
		m.err = msg.err
		if msg.d != nil && msg.d.Snap != nil {
			m.d = msg.d
		}
		m.scroll(0)
		return m, tea.Tick(poll, func(time.Time) tea.Msg { return tickMsg{} })
	case tickMsg:
		return m, m.load()
	}
	return m, nil
}

// page is the number of body lines that fit above the footer.
func (m model) page() int { return max(1, m.height-1) }

// scroll moves the view by d lines, clamped to the rendered body.
func (m *model) scroll(d int) {
	n := strings.Count(m.body(), "\n")
	m.off = min(max(m.off+d, 0), max(0, n-m.page()))
}

var (
	title = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	head  = lipgloss.NewStyle().Bold(true)
	dim   = lipgloss.NewStyle().Faint(true)
	red   = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	ok    = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	warn  = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
)

// series indexes a snapshot's samples by metric name.
type series map[string][]collector.Sample

func index(s *collector.Snapshot) series {
	out := series{}
	for _, x := range s.Samples {
		out[x.Metric] = append(out[x.Metric], x)
	}
	return out
}

func (s series) v(metric string) float64 {
	if x := s[metric]; len(x) > 0 {
		return x[0].Value
	}
	return 0
}

// by returns label value -> sample value for a labelled metric.
func (s series) by(metric, label string) map[string]float64 {
	out := map[string]float64{}
	for _, x := range s[metric] {
		out[x.Labels[label]] = x.Value
	}
	return out
}

func keys(m map[string]float64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (m model) View() string {
	if m.d == nil {
		if m.err != nil {
			return red.Render("error: "+m.err.Error()) + "\n\n" + dim.Render("retrying every 2s · q quit") + "\n"
		}
		return "connecting to agent...\n"
	}
	foot := dim.Render("q quit · s sort by cpu/memory · ↑↓ pgup pgdn home end scroll")
	body := m.body()
	if m.height <= 0 {
		return body + "\n" + foot + "\n"
	}
	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	end := min(len(lines), m.off+m.page())
	if m.off > 0 || end < len(lines) {
		foot += dim.Render(fmt.Sprintf(" · lines %d-%d of %d", m.off+1, end, len(lines)))
	}
	return strings.Join(lines[min(m.off, end):end], "\n") + "\n" + foot
}

// body renders every section; View clips it to the terminal height.
func (m model) body() string {
	if m.d == nil {
		return ""
	}
	s, ix := m.d.Snap, index(m.d.Snap)
	w := max(m.width, 60)
	bw := max(10, w-56)
	var b strings.Builder

	m.header(&b, s)
	m.alerts(&b)

	section(&b, w, "CPU", "")
	fmt.Fprintf(&b, "total %s %5.1f%%  usr %.0f sys %.0f iow %.0f steal %.0f\n", bar(ix.v("cpu.total_pct"), bw),
		ix.v("cpu.total_pct"), ix.v("cpu.user_pct"), ix.v("cpu.system_pct"), ix.v("cpu.iowait_pct"),
		ix.v("cpu.steal_pct"))
	fmt.Fprintf(&b, "load  %.2f %.2f %.2f  (%d cpus)\n", ix.v("load.1"), ix.v("load.5"), ix.v("load.15"), s.System.CPUs)
	b.WriteString(cores(ix.by("cpu.core_pct", "core"), w))

	section(&b, w, "Memory", "")
	fmt.Fprintf(&b, "mem   %s %5.1f%%  %s / %s  %s free\n", bar(ix.v("mem.used_pct"), bw), ix.v("mem.used_pct"),
		bytes(ix.v("mem.used_bytes")), bytes(ix.v("mem.total_bytes")), bytes(ix.v("mem.available_bytes")))
	fmt.Fprintf(&b, "swap  %s %5.1f%%  %s / %s\n", bar(ix.v("swap.used_pct"), bw), ix.v("swap.used_pct"),
		bytes(ix.v("swap.used_bytes")), bytes(ix.v("swap.total_bytes")))

	section(&b, w, "Disk", "")
	for _, mt := range s.Mounts {
		fmt.Fprintf(&b, "%-14s %s %5.1f%%  %s / %s\n", trunc(mt.Path, 14), bar(mt.UsedPct, bw-9), mt.UsedPct,
			bytes(float64(mt.Used)), bytes(float64(mt.Total)))
	}
	rd, wr := ix.by("diskio.read_bps", "dev"), ix.by("diskio.write_bps", "dev")
	if len(rd) > 0 {
		ri, wi := ix.by("diskio.read_iops", "dev"), ix.by("diskio.write_iops", "dev")
		aw, ut := ix.by("diskio.await_ms", "dev"), ix.by("diskio.util_pct", "dev")
		b.WriteString(dim.Render(fmt.Sprintf("%-10s %10s %10s %8s %8s %7s %6s", "dev", "read/s", "write/s",
			"r iops", "w iops", "await", "util")) + "\n")
		for _, d := range keys(rd) {
			fmt.Fprintf(&b, "%-10s %10s %10s %8.0f %8.0f %5.1fms %5.1f%%\n", trunc(d, 10), bytes(rd[d]), bytes(wr[d]),
				ri[d], wi[d], aw[d], ut[d])
		}
	}

	section(&b, w, "Network", "")
	fmt.Fprintf(&b, "total in %s/s  out %s/s\n", bytes(ix.v("net.rx_bps_total")), bytes(ix.v("net.tx_bps_total")))
	rx, tx := ix.by("net.rx_bps", "iface"), ix.by("net.tx_bps", "iface")
	rp, tp := ix.by("net.rx_pps", "iface"), ix.by("net.tx_pps", "iface")
	b.WriteString(dim.Render(fmt.Sprintf("%-12s %10s %10s %9s %9s", "iface", "rx/s", "tx/s", "rx pps", "tx pps")) + "\n")
	for _, i := range keys(rx) {
		fmt.Fprintf(&b, "%-12s %10s %10s %9.0f %9.0f\n", trunc(i, 12), bytes(rx[i]), bytes(tx[i]), rp[i], tp[i])
	}
	fmt.Fprintf(&b, "tcp   estab %.0f  syn_recv %.0f  time_wait %.0f  close_wait %.0f  listen %.0f  new/s %.1f\n",
		ix.v("net.tcp.established"), ix.v("net.tcp.syn_recv"), ix.v("net.tcp.time_wait"), ix.v("net.tcp.close_wait"),
		ix.v("net.tcp.listen"), ix.v("net.new_conns_ps"))
	if ips := s.Conns.TopIPs; len(ips) > 0 {
		var t []string
		for _, x := range ips[:min(len(ips), 5)] {
			t = append(t, fmt.Sprintf("%s (%d)", x.IP, x.Count))
		}
		b.WriteString("top ips  " + strings.Join(t, "  ") + "\n")
	}
	if ips := s.Conns.TopHTTPClients; len(ips) > 0 {
		var t []string
		for _, x := range ips[:min(len(ips), 5)] {
			t = append(t, fmt.Sprintf("%s (%d)", x.IP, x.Count))
		}
		b.WriteString("http ips " + strings.Join(t, "  ") + "\n")
	}

	procs, by := s.TopCPU, "CPU"
	if m.byMem {
		procs, by = s.TopMem, "memory"
	}
	section(&b, w, "Processes", fmt.Sprintf("by %s · %.0f total, %.0f zombies", by, ix.v("proc.total"),
		ix.v("proc.zombies")))
	b.WriteString(dim.Render(fmt.Sprintf("%7s %-10s %6s %9s %s %s", "PID", "USER", "CPU%", "RSS", "S", "COMMAND")) + "\n")
	cw := max(10, w-40)
	for _, p := range procs {
		fmt.Fprintf(&b, "%7d %-10s %6.1f %9s %s %s\n", p.PID, trunc(p.User, 10), p.CPU, bytes(float64(p.RSS)), p.State,
			trunc(p.Cmd, cw))
	}

	services(&b, s.Services, w)
	certList(&b, s.Certs, w)
	redis(&b, s.Redis, w)
	m.sessions(&b, w)
	return b.String()
}

func (m model) header(b *strings.Builder, s *collector.Snapshot) {
	sys, st := s.System, m.d.Status
	name, ver := sys.Hostname, ""
	if st != nil {
		if st.ServerName != "" && st.ServerName != name {
			name = st.ServerName + " (" + name + ")"
		}
		ver = " · kurogane " + st.Version
	}
	fmt.Fprintf(b, "%s  %s · kernel %s · %s · up %s · %d cpus · %s RAM%s · %s\n", title.Render(name), sys.OS,
		sys.Kernel, sys.Arch, dur(sys.Uptime), sys.CPUs, bytes(float64(sys.MemTotal)), ver,
		s.TS.Local().Format("15:04:05"))
	if sys.RebootRequired || sys.SecurityUpdates > 0 || sys.PendingUpdates > 0 {
		b.WriteString(warn.Render(fmt.Sprintf("%d security / %d pending updates · reboot required: %v",
			sys.SecurityUpdates, sys.PendingUpdates, sys.RebootRequired)) + "\n")
	}
	if m.err != nil {
		b.WriteString(red.Render("stale: "+m.err.Error()) + "\n")
	}
	for _, x := range m.d.Warn {
		b.WriteString(warn.Render(x) + "\n")
	}
}

// alerts mirrors the Overview cards: active alerts first, then the hardening grade.
func (m model) alerts(b *strings.Builder) {
	st := m.d.Status
	if st == nil {
		return
	}
	const show = 8
	section(b, max(m.width, 60), "Alerts", fmt.Sprintf("%d active", len(st.Alerts)))
	if len(st.Alerts) == 0 {
		b.WriteString(dim.Render("No active alerts.") + "\n")
	}
	for i, a := range st.Alerts {
		if i == show {
			b.WriteString(dim.Render(fmt.Sprintf("+%d more: krgn alert events", len(st.Alerts)-show)) + "\n")
			break
		}
		txt := a.Summary
		if txt == "" {
			txt = a.RuleID
		}
		state := ""
		// every active alert fires; only show the state when it differs
		if a.State != "firing" {
			state = " " + dim.Render("("+a.State+")")
		}
		fmt.Fprintf(b, "%s %s%s %s\n", sev(a.Severity), txt, state, dim.Render(ago(a.StartedAt)))
	}

	h := st.Hardening
	section(b, max(m.width, 60), "Hardening", "")
	if h == nil {
		b.WriteString(dim.Render("No scan yet: run `krgn harden scan`.") + "\n")
		return
	}
	g := ok
	switch h.Grade {
	case "C":
		g = warn
	case "D":
		g = red
	}
	fmt.Fprintf(b, "grade %s %.0f / 100 %s\n", g.Bold(true).Render(h.Grade), h.Score, dim.Render("scanned "+ago(h.ScannedAt)))
}

// section starts a block with a full-width rule and its heading; sub is an optional faint note.
func section(b *strings.Builder, w int, name, sub string) {
	b.WriteString(dim.Render(strings.Repeat("─", w)) + "\n" + head.Render(name))
	if sub != "" {
		b.WriteString(" " + dim.Render(sub))
	}
	b.WriteString("\n")
}

func sev(s string) string {
	l := fmt.Sprintf("%-8s", s)
	switch s {
	case "critical":
		return red.Render(l)
	case "warning":
		return warn.Render(l)
	}
	return dim.Render(l)
}

func services(b *strings.Builder, ss []collector.ServiceState, w int) {
	section(b, w, "Services", "")
	if len(ss) == 0 {
		b.WriteString(dim.Render("No watched services. Add units to collector.watch_services.") + "\n")
		return
	}
	for _, x := range ss {
		st := red
		switch x.Active {
		case "active":
			st = ok
		case "activating", "reloading", "deactivating":
			st = warn
		}
		fmt.Fprintf(b, "%-32s %s %s\n", trunc(x.Unit, 32), st.Render(fmt.Sprintf("%-10s", x.Active)), dim.Render(x.Sub))
	}
}

// certList shows certificates soonest expiry first, unreadable files last, like the server page.
func certList(b *strings.Builder, cs []certs.Cert, w int) {
	if len(cs) == 0 {
		return
	}
	cs = append([]certs.Cert(nil), cs...)
	sort.SliceStable(cs, func(i, j int) bool {
		if (cs[i].Error != "") != (cs[j].Error != "") {
			return cs[j].Error != ""
		}
		if cs[i].DaysLeft != cs[j].DaysLeft {
			return cs[i].DaysLeft < cs[j].DaysLeft
		}
		return cs[i].Name < cs[j].Name
	})
	section(b, w, "TLS certificates", "")
	nw := max(16, w-62)
	b.WriteString(dim.Render(fmt.Sprintf("%-*s %10s %-10s %-24s %6s", nw, "NAME", "EXPIRES", "DATE", "ISSUER",
		"SERVED")) + "\n")
	for _, c := range cs {
		if c.Error != "" {
			fmt.Fprintf(b, "%-*s %s\n", nw, trunc(c.Name, nw), red.Render(trunc(c.Error, max(10, w-nw-1))))
			continue
		}
		left := fmt.Sprintf("%10s", days(c.DaysLeft))
		switch {
		case c.DaysLeft < 3:
			left = red.Render(left)
		case c.DaysLeft < 14:
			left = warn.Render(left)
		}
		port := "-"
		if c.ServedPort > 0 {
			port = fmt.Sprintf(":%d", c.ServedPort)
		}
		fmt.Fprintf(b, "%-*s %s %-10s %-24s %6s\n", nw, trunc(c.Name, nw), left, c.NotAfter.Local().Format("2006-01-02"),
			trunc(c.Issuer, 24), port)
		var n []string
		if c.Stale {
			n = append(n, fmt.Sprintf("port %d serves an older copy (until %s): reload the web server", c.ServedPort,
				c.ServedNotAfter.Local().Format("2006-01-02")))
		}
		if wk := c.Weak(); wk != "" {
			n = append(n, wk)
		}
		if len(n) > 0 {
			b.WriteString("  " + warn.Render(trunc(strings.Join(n, " · "), max(10, w-2))) + "\n")
		}
	}
}

func days(d float64) string {
	if d < 0 {
		return fmt.Sprintf("expired %.0fd", -d)
	}
	return fmt.Sprintf("%.0fd", d)
}

func redis(b *strings.Builder, rs []collector.RedisInstance, w int) {
	if len(rs) == 0 {
		return
	}
	section(b, w, "Redis", "")
	b.WriteString(dim.Render(fmt.Sprintf("%-14s %-8s %-8s %-12s %-20s %8s %6s %8s %s", "INSTANCE", "STATUS",
		"VERSION", "ROLE", "MEMORY", "OPS/S", "HITS", "CLIENTS", "LAST SAVE")) + "\n")
	for _, r := range rs {
		if r.Status != collector.RedisUp {
			st := red
			if r.Status == collector.RedisNeedsCreds {
				st = warn
			}
			note := r.Addr
			if r.Error != "" {
				note += ": " + r.Error
			}
			if r.Hint != "" {
				note += ". " + r.Hint
			}
			fmt.Fprintf(b, "%-14s %s %s\n", trunc(r.Name, 14), st.Render(strings.ReplaceAll(r.Status, "_", " ")),
				dim.Render(trunc(note, max(10, w-34))))
			continue
		}
		mem := bytes(r.MemoryUsed)
		if r.MaxMemory > 0 {
			mem += fmt.Sprintf(" / %s %.0f%%", bytes(r.MaxMemory), 100*r.MemoryUsed/r.MaxMemory)
		}
		hits := "-"
		if r.HitRatio != nil {
			hits = fmt.Sprintf("%.1f%%", *r.HitRatio)
		}
		role := r.Role
		if r.Role == "master" && r.Replicas > 0 {
			role = fmt.Sprintf("master +%d", r.Replicas)
		}
		if r.Role == "slave" {
			role = "replica " + r.MasterLink
		}
		save := "never"
		if !r.LastSave.IsZero() {
			save = ago(r.LastSave)
		}
		if r.RDBStatus != "" && r.RDBStatus != "ok" {
			save = red.Render(save + " FAILED")
		}
		fmt.Fprintf(b, "%-14s %s %-8s %-12s %-20s %8.0f %6s %8.0f %s\n", trunc(r.Name, 14), ok.Render(fmt.Sprintf("%-8s",
			r.Status)), trunc(r.Version, 8), trunc(role, 12), trunc(mem, 20), r.OpsPS, hits, r.Clients, save)
	}
}

func (m model) sessions(b *strings.Builder, w int) {
	if m.d.Status == nil && m.d.Sessions == nil {
		return
	}
	section(b, w, "SSH sessions", "")
	if len(m.d.Sessions) == 0 {
		b.WriteString(dim.Render("No open SSH sessions.") + "\n")
		return
	}
	b.WriteString(dim.Render(fmt.Sprintf("%7s %-12s %-8s %-16s %s", "PID", "USER", "TTY", "STARTED", "FROM")) + "\n")
	for _, x := range m.d.Sessions {
		fmt.Fprintf(b, "%7d %-12s %-8s %-16s %s\n", x.PID, trunc(x.User, 12), trunc(x.TTY, 8),
			x.Started.Local().Format("2006-01-02 15:04"), trunc(x.From, max(10, w-48)))
	}
}

// cores lays out per-core bars in as many columns as fit.
func cores(c map[string]float64, w int) string {
	if len(c) == 0 {
		return ""
	}
	ids := keys(c)
	sort.Slice(ids, func(i, j int) bool {
		if len(ids[i]) != len(ids[j]) {
			return len(ids[i]) < len(ids[j])
		}
		return ids[i] < ids[j]
	})
	const cell = 26
	cols := max(1, w/cell)
	var b strings.Builder
	for i, id := range ids {
		fmt.Fprintf(&b, "%3s %s %5.1f%% ", id, bar(c[id], 12), c[id])
		if (i+1)%cols == 0 || i == len(ids)-1 {
			b.WriteString("\n")
		}
	}
	return b.String()
}

func bar(p float64, w int) string {
	p = min(max(p, 0), 100)
	n := int(p / 100 * float64(w))
	st := ok
	if p >= 90 {
		st = red
	} else if p >= 70 {
		st = warn
	}
	return "[" + st.Render(strings.Repeat("|", n)) + strings.Repeat(" ", w-n) + "]"
}

func bytes(v float64) string {
	const u = "KMGTPE"
	if v < 1024 {
		return fmt.Sprintf("%.0fB", v)
	}
	i := -1
	for v >= 1024 && i < len(u)-1 {
		v /= 1024
		i++
	}
	return fmt.Sprintf("%.1f%c", v, u[i])
}

func dur(s float64) string {
	d := time.Duration(s) * time.Second
	if d >= 24*time.Hour {
		return fmt.Sprintf("%dd%dh", d/(24*time.Hour), d%(24*time.Hour)/time.Hour)
	}
	if d < time.Minute {
		return d.Truncate(time.Second).String()
	}
	return strings.TrimSuffix(d.Truncate(time.Minute).String(), "0s")
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := time.Since(t)
	if d < time.Minute {
		return "just now"
	}
	return dur(d.Seconds()) + " ago"
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "~"
}
