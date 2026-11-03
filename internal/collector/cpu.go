package collector

import (
	"bytes"
	"context"
	"strconv"

	"github.com/tb12as/serverman/internal/hostfs"
)

type cpuTimes struct{ user, nice, system, idle, iowait, irq, softirq, steal uint64 }

func (t cpuTimes) total() uint64 {
	return t.user + t.nice + t.system + t.idle + t.iowait + t.irq + t.softirq + t.steal
}

// cpuCollector reads /proc/stat and /proc/loadavg.
type cpuCollector struct {
	prev, cur []cpuTimes // [0] = all cpus, then one per core line
	ids       [][]byte   // core id per cur[i+1]
	cores     int
	lbl       *labels
	f         [][]byte
}

func newCPU() *cpuCollector { return &cpuCollector{lbl: newLabels("core")} }

func (c *cpuCollector) Collect(context.Context) ([]Sample, error) {
	b, err := hostfs.Read("/proc/stat")
	if err != nil {
		return nil, err
	}
	c.cur, c.ids = c.cur[:0], c.ids[:0]
	for l := range bytes.Lines(b) {
		if !bytes.HasPrefix(l, []byte("cpu")) {
			continue
		}
		c.f = fields(l, c.f)
		if len(c.f) < 9 {
			continue
		}
		f := c.f
		t := cpuTimes{atou(f[1]), atou(f[2]), atou(f[3]), atou(f[4]), atou(f[5]), atou(f[6]), atou(f[7]), atou(f[8])}
		if len(f[0]) > 3 {
			c.ids = append(c.ids, f[0][3:])
		}
		c.cur = append(c.cur, t)
	}
	c.cores = len(c.ids)

	out := make([]Sample, 0, 8+len(c.cur))
	if len(c.prev) == len(c.cur) && len(c.cur) > 0 {
		d := delta(c.cur[0], c.prev[0])
		tot := float64(d.total())
		if tot > 0 {
			out = add(out, "cpu.total_pct", pct(tot-float64(d.idle+d.iowait), tot))
			out = add(out, "cpu.user_pct", pct(float64(d.user+d.nice), tot))
			out = add(out, "cpu.system_pct", pct(float64(d.system+d.irq+d.softirq), tot))
			out = add(out, "cpu.iowait_pct", pct(float64(d.iowait), tot))
			out = add(out, "cpu.steal_pct", pct(float64(d.steal), tot))
		}
		for i := 1; i < len(c.cur); i++ {
			d := delta(c.cur[i], c.prev[i])
			if tot := float64(d.total()); tot > 0 {
				out = addL(out, "cpu.core_pct", c.lbl.get(c.ids[i-1]), pct(tot-float64(d.idle+d.iowait), tot))
			}
		}
	}
	c.prev, c.cur = c.cur, c.prev

	lb, err := hostfs.Read("/proc/loadavg")
	if err != nil {
		return out, err
	}
	c.f = fields(lb, c.f)
	for i, n := range []string{"load.1", "load.5", "load.15"} {
		if i < len(c.f) {
			v, _ := strconv.ParseFloat(string(c.f[i]), 64)
			out = add(out, n, v)
		}
	}
	return out, nil
}

func sub(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

func delta(a, b cpuTimes) cpuTimes {
	return cpuTimes{sub(a.user, b.user), sub(a.nice, b.nice), sub(a.system, b.system), sub(a.idle, b.idle),
		sub(a.iowait, b.iowait), sub(a.irq, b.irq), sub(a.softirq, b.softirq), sub(a.steal, b.steal)}
}
