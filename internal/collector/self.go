package collector

import (
	"context"
	"os"
	"runtime"
	"syscall"
	"time"
)

// selfCollector reports the agent's own CPU, RSS and goroutines (PM-8). It reads the real
// /proc/self, not hostfs, because it measures this process.
type selfCollector struct {
	prevCPU time.Duration
	prevT   time.Time
	buf     []byte
	f       [][]byte
}

func (c *selfCollector) Collect(context.Context) ([]Sample, error) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return nil, err
	}
	cpu := time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
	t := now()
	out := make([]Sample, 0, 3)
	if !c.prevT.IsZero() {
		if dt := t.Sub(c.prevT); dt > 0 {
			out = add(out, "agent.cpu_pct", float64(cpu-c.prevCPU)/float64(dt)*100)
		}
	}
	c.prevCPU, c.prevT = cpu, t
	if c.buf == nil {
		c.buf = make([]byte, 128)
	}
	if b, err := readInto("/proc/self/statm", c.buf); err == nil {
		if c.f = fields(b, c.f); len(c.f) > 1 {
			out = add(out, "agent.rss_bytes", float64(atou(c.f[1])*uint64(os.Getpagesize())))
		}
	}
	out = add(out, "agent.goroutines", float64(runtime.NumGoroutine()))
	return out, nil
}
