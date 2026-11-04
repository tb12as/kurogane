// Package tui is the `serverkeeper top` live dashboard (PM-3): a thin client over GET /metrics/current.
package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/tb12as/kurogane/internal/collector"
)

// Fetch returns the agent's latest snapshot.
type Fetch func() (*collector.Snapshot, error)

const poll = 2 * time.Second

// Run starts the dashboard and blocks until the user quits.
func Run(fetch Fetch) error {
	_, err := tea.NewProgram(newModel(fetch), tea.WithAltScreen()).Run()
	return err
}

type snapMsg struct {
	s   *collector.Snapshot
	err error
}

type tickMsg struct{}

type model struct {
	fetch Fetch
	snap  *collector.Snapshot
	err   error
	byMem bool
	width int
}

func newModel(f Fetch) model { return model{fetch: f, width: 100} }

func (m model) load() tea.Cmd {
	return func() tea.Msg {
		s, err := m.fetch()
		return snapMsg{s, err}
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
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case snapMsg:
		m.err = msg.err
		if msg.s != nil {
			m.snap = msg.s
		}
		return m, tea.Tick(poll, func(time.Time) tea.Msg { return tickMsg{} })
	case tickMsg:
		return m, m.load()
	}
	return m, nil
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
	if m.snap == nil {
		if m.err != nil {
			return red.Render("error: "+m.err.Error()) + "\n\n" + dim.Render("retrying every 2s · q quit") + "\n"
		}
		return "connecting to agent...\n"
	}
	s, ix := m.snap, index(m.snap)
	w := max(m.width, 60)
	var b strings.Builder

	sys := s.System
	fmt.Fprintf(&b, "%s  %s · kernel %s · up %s · %d cpus · %s\n", title.Render(sys.Hostname), sys.OS, sys.Kernel,
		dur(sys.Uptime), sys.CPUs, s.TS.Local().Format("15:04:05"))
	if sys.RebootRequired || sys.SecurityUpdates > 0 {
		b.WriteString(warn.Render(fmt.Sprintf("%d security / %d pending updates · reboot required: %v",
			sys.SecurityUpdates, sys.PendingUpdates, sys.RebootRequired)) + "\n")
	}
	if m.err != nil {
		b.WriteString(red.Render("stale: "+m.err.Error()) + "\n")
	}

	bw := max(10, w-56)
	b.WriteString("\n" + head.Render("CPU") + "\n")
	fmt.Fprintf(&b, "total %s %5.1f%%  usr %.0f sys %.0f iow %.0f steal %.0f\n", bar(ix.v("cpu.total_pct"), bw),
		ix.v("cpu.total_pct"), ix.v("cpu.user_pct"), ix.v("cpu.system_pct"), ix.v("cpu.iowait_pct"),
		ix.v("cpu.steal_pct"))
	fmt.Fprintf(&b, "load  %.2f %.2f %.2f\n", ix.v("load.1"), ix.v("load.5"), ix.v("load.15"))
	b.WriteString(cores(ix.by("cpu.core_pct", "core"), w))

	b.WriteString("\n" + head.Render("Memory") + "\n")
	fmt.Fprintf(&b, "mem   %s %5.1f%%  %s / %s\n", bar(ix.v("mem.used_pct"), bw), ix.v("mem.used_pct"),
		bytes(ix.v("mem.used_bytes")), bytes(ix.v("mem.total_bytes")))
	fmt.Fprintf(&b, "swap  %s %5.1f%%  %s / %s\n", bar(ix.v("swap.used_pct"), bw), ix.v("swap.used_pct"),
		bytes(ix.v("swap.used_bytes")), bytes(ix.v("swap.total_bytes")))

	b.WriteString("\n" + head.Render("Disk") + "\n")
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

	b.WriteString("\n" + head.Render("Network") + "\n")
	rx, tx := ix.by("net.rx_bps", "iface"), ix.by("net.tx_bps", "iface")
	rp, tp := ix.by("net.rx_pps", "iface"), ix.by("net.tx_pps", "iface")
	b.WriteString(dim.Render(fmt.Sprintf("%-12s %10s %10s %9s %9s", "iface", "rx/s", "tx/s", "rx pps", "tx pps")) + "\n")
	for _, i := range keys(rx) {
		fmt.Fprintf(&b, "%-12s %10s %10s %9.0f %9.0f\n", trunc(i, 12), bytes(rx[i]), bytes(tx[i]), rp[i], tp[i])
	}
	fmt.Fprintf(&b, "tcp   estab %.0f  syn_recv %.0f  time_wait %.0f  close_wait %.0f  listen %.0f  new/s %.1f",
		ix.v("net.tcp.established"), ix.v("net.tcp.syn_recv"), ix.v("net.tcp.time_wait"), ix.v("net.tcp.close_wait"),
		ix.v("net.tcp.listen"), ix.v("net.new_conns_ps"))
	if len(s.Conns.TopIPs) > 0 {
		fmt.Fprintf(&b, "  top ip %s (%d)", s.Conns.TopIPs[0].IP, s.Conns.TopIPs[0].Count)
	}
	b.WriteString("\n")

	procs, by := s.TopCPU, "CPU"
	if m.byMem {
		procs, by = s.TopMem, "memory"
	}
	fmt.Fprintf(&b, "\n%s %s\n", head.Render("Processes"), dim.Render(fmt.Sprintf("by %s · %.0f total, %.0f zombies",
		by, ix.v("proc.total"), ix.v("proc.zombies"))))
	b.WriteString(dim.Render(fmt.Sprintf("%7s %-10s %6s %9s %s %s", "PID", "USER", "CPU%", "RSS", "S", "COMMAND")) + "\n")
	cw := max(10, w-40)
	for _, p := range procs {
		fmt.Fprintf(&b, "%7d %-10s %6.1f %9s %s %s\n", p.PID, trunc(p.User, 10), p.CPU, bytes(float64(p.RSS)), p.State,
			trunc(p.Cmd, cw))
	}
	b.WriteString("\n" + dim.Render("q quit · s sort by cpu/memory") + "\n")
	return b.String()
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
	return d.Truncate(time.Minute).String()
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
