package collector

import (
	"bytes"
	"context"

	"github.com/tb12as/serverman/internal/hostfs"
)

// memCollector reads /proc/meminfo and /proc/vmstat (oom_kill).
type memCollector struct {
	total   uint64
	oom     uint64
	oomSeen bool
	f       [][]byte
}

func (c *memCollector) Collect(context.Context) ([]Sample, error) {
	b, err := hostfs.Read("/proc/meminfo")
	if err != nil {
		return nil, err
	}
	var total, free, avail, buffers, cached, srecl, swapT, swapF uint64
	hasAvail := false
	for l := range bytes.Lines(b) {
		c.f = fields(l, c.f)
		if len(c.f) < 2 {
			continue
		}
		v := atou(c.f[1]) * 1024
		switch string(c.f[0]) {
		case "MemTotal:":
			total = v
		case "MemFree:":
			free = v
		case "MemAvailable:":
			avail, hasAvail = v, true
		case "Buffers:":
			buffers = v
		case "Cached:":
			cached = v
		case "SReclaimable:":
			srecl = v
		case "SwapTotal:":
			swapT = v
		case "SwapFree:":
			swapF = v
		}
	}
	if !hasAvail {
		avail = free + buffers + cached
	}
	c.total = total
	used := sub(total, avail)
	swapU := sub(swapT, swapF)
	out := make([]Sample, 0, 12)
	out = add(out, "mem.total_bytes", float64(total))
	out = add(out, "mem.used_bytes", float64(used))
	out = add(out, "mem.used_pct", pct(float64(used), float64(total)))
	out = add(out, "mem.available_bytes", float64(avail))
	out = add(out, "mem.available_pct", pct(float64(avail), float64(total)))
	out = add(out, "mem.cached_bytes", float64(cached+srecl))
	out = add(out, "mem.buffers_bytes", float64(buffers))
	out = add(out, "swap.total_bytes", float64(swapT))
	out = add(out, "swap.used_bytes", float64(swapU))
	out = add(out, "swap.used_pct", pct(float64(swapU), float64(swapT)))

	vb, err := hostfs.Read("/proc/vmstat")
	if err != nil {
		return out, err
	}
	i := bytes.Index(vb, []byte("\noom_kill "))
	if i < 0 {
		return out, nil
	}
	n := atou(vb[i+len("\noom_kill "):])
	d := 0.0
	if c.oomSeen && n > c.oom {
		d = float64(n - c.oom)
	}
	c.oom, c.oomSeen = n, true
	out = add(out, "mem.oom_kills", float64(n))
	out = add(out, "mem.oom_kills_delta", d)
	return out, nil
}
