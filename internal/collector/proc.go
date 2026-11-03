package collector

import (
	"bytes"
	"context"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/serverkeeper/serverkeeper/internal/hostfs"
)

type pinfo struct {
	pid   int32
	ticks uint64
	rss   uint64
	cpu   float64
	state byte
	name  string
}

type pprev struct{ ticks, start uint64 }

// procCollector walks /proc/[pid]/stat for totals, zombies and the top 10 by CPU and RSS.
type procCollector struct {
	prev, cur map[int32]pprev
	prevT     time.Time
	list      []pinfo
	buf       []byte
	f         [][]byte
	page      uint64

	users   map[string]string // uid -> name
	usersAt time.Time

	topCPU, topMem []Proc
}

func newProc() *procCollector {
	return &procCollector{prev: map[int32]pprev{}, cur: map[int32]pprev{}, buf: make([]byte, 4096),
		page: uint64(os.Getpagesize())}
}

func (c *procCollector) Collect(context.Context) ([]Sample, error) {
	names, err := readDirNames(hostfs.P("/proc"))
	if err != nil {
		return nil, err
	}
	t := now()
	dt := t.Sub(c.prevT).Seconds()
	first := c.prevT.IsZero()
	c.prevT = t
	c.list = c.list[:0]
	clear(c.cur)
	var total, running, zombies, threads int
	for _, n := range names {
		if n[0] < '0' || n[0] > '9' {
			continue
		}
		b, err := readInto(hostfs.P("/proc/"+n+"/stat"), c.buf)
		if err != nil {
			continue // process exited
		}
		i := bytes.LastIndexByte(b, ')')
		j := bytes.IndexByte(b, '(')
		if i < 0 || j < 0 || j > i {
			continue
		}
		c.f = fields(b[i+1:], c.f)
		if len(c.f) < 22 {
			continue
		}
		pid := int32(atou(b))
		p := pinfo{pid: pid, state: c.f[0][0], ticks: atou(c.f[11]) + atou(c.f[12]), rss: atou(c.f[21]) * c.page,
			name: string(b[j+1 : i])}
		start := atou(c.f[19])
		if pr, ok := c.prev[pid]; ok && !first && pr.start == start && dt > 0 {
			p.cpu = float64(sub(p.ticks, pr.ticks)) / clkTck / dt * 100
		}
		c.cur[pid] = pprev{p.ticks, start}
		total++
		threads += int(atou(c.f[17]))
		switch p.state {
		case 'R':
			running++
		case 'Z':
			zombies++
		}
		c.list = append(c.list, p)
	}
	c.prev, c.cur = c.cur, c.prev

	slices.SortFunc(c.list, func(a, b pinfo) int {
		if a.cpu != b.cpu {
			if a.cpu > b.cpu {
				return -1
			}
			return 1
		}
		return int(b.rss>>20) - int(a.rss>>20)
	})
	c.topCPU = c.details(c.list[:min(10, len(c.list))])
	slices.SortFunc(c.list, func(a, b pinfo) int {
		if a.rss > b.rss {
			return -1
		}
		if a.rss < b.rss {
			return 1
		}
		return 0
	})
	c.topMem = c.details(c.list[:min(10, len(c.list))])

	out := make([]Sample, 0, 4)
	out = add(out, "proc.total", float64(total))
	out = add(out, "proc.running", float64(running))
	out = add(out, "proc.zombies", float64(zombies))
	out = add(out, "proc.threads", float64(threads))
	return out, nil
}

// details reads user and command line for the few processes that make the top lists.
func (c *procCollector) details(l []pinfo) []Proc {
	out := make([]Proc, len(l))
	for i, p := range l {
		dir := hostfs.P("/proc/" + strconv.Itoa(int(p.pid)))
		pr := Proc{PID: p.pid, Name: p.name, CPU: p.cpu, RSS: p.rss, State: string(p.state)}
		if b, err := readInto(dir+"/cmdline", c.buf); err == nil && len(b) > 0 {
			b = bytes.TrimRight(b, "\x00")
			for k := range b {
				if b[k] == 0 {
					b[k] = ' '
				}
			}
			pr.Cmd = string(b[:min(len(b), 256)])
		} else {
			pr.Cmd = "[" + p.name + "]"
		}
		if b, err := readInto(dir+"/status", c.buf); err == nil {
			if k := bytes.Index(b, []byte("\nUid:")); k >= 0 {
				c.f = fields(b[k+5:min(len(b), k+64)], c.f)
				if len(c.f) > 0 {
					pr.User = c.user(string(c.f[0]))
				}
			}
		}
		out[i] = pr
	}
	return out
}

func (c *procCollector) user(uid string) string {
	if n, ok := c.users[uid]; ok {
		return n
	}
	if now().Sub(c.usersAt) < time.Minute && c.users != nil {
		return uid
	}
	c.usersAt = now()
	c.users = map[string]string{}
	lines, _ := hostfs.Lines("/etc/passwd")
	for _, l := range lines {
		f := strings.SplitN(l, ":", 4)
		if len(f) == 4 {
			c.users[f[2]] = f[0]
		}
	}
	if n, ok := c.users[uid]; ok {
		return n
	}
	return uid
}
