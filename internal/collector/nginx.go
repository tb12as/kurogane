package collector

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"github.com/tb12as/kurogane/internal/hostfs"
)

// nginxCollector tails an access log by offset and counts requests and 4xx/5xx statuses.
// Rotation is detected by inode change (rename) or the file shrinking (copytruncate).
type nginxCollector struct {
	path  string
	ino   uint64
	off   int64
	prevT time.Time
	rem   []byte // partial last line
	buf   []byte
	ips   map[[16]byte]int32
	top   []IPCount // busiest client IPs of the last interval

	flows    map[string]*int32 // 16-byte IP + request; pointer values so a hit does not allocate
	kb       []byte
	topFlows []Flow
}

// maxFlows caps distinct client -> request pairs per interval so a random-path flood cannot grow memory.
const maxFlows = 10000

func (c *nginxCollector) Collect(context.Context) ([]Sample, error) {
	p := hostfs.P(c.path)
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	var ino uint64
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		ino = s.Ino
	}
	t := now()
	if c.prevT.IsZero() {
		// start at the end: history is not a rate
		c.ino, c.off, c.prevT = ino, st.Size(), t
		return nil, nil
	}
	dt := t.Sub(c.prevT).Seconds()
	if dt <= 0 {
		return nil, nil
	}
	c.prevT = t
	if ino != c.ino || st.Size() < c.off {
		c.ino, c.off, c.rem = ino, 0, c.rem[:0]
	}
	var n, n4, n5 int
	if c.ips == nil {
		c.ips, c.flows = map[[16]byte]int32{}, map[string]*int32{}
	}
	clear(c.ips)
	clear(c.flows)
	if st.Size() > c.off {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if _, err := f.Seek(c.off, io.SeekStart); err != nil {
			return nil, err
		}
		if c.buf == nil {
			c.buf = make([]byte, 64*1024)
		}
		for {
			k, err := f.Read(c.buf)
			if k > 0 {
				c.off += int64(k)
				data := c.buf[:k]
				for {
					i := bytes.IndexByte(data, '\n')
					if i < 0 {
						c.rem = append(c.rem, data...)
						break
					}
					line := data[:i]
					if len(c.rem) > 0 {
						line = append(c.rem, line...)
						c.rem = c.rem[:0]
					}
					n++
					if a, ok := clientIP(line); ok {
						c.count(a, line)
					}
					switch status(line) / 100 {
					case 4:
						n4++
					case 5:
						n5++
					}
					data = data[i+1:]
				}
			}
			if err != nil || k == 0 {
				break
			}
		}
		if len(c.rem) > 64*1024 {
			c.rem = c.rem[:0] // not a log line, do not grow forever
		}
	}
	c.top = topN(c.ips, 10, false)
	c.topFlows = c.topHTTP(10)
	out := make([]Sample, 0, 3)
	out = add(out, "http.rps", float64(n)/dt)
	out = add(out, "http.4xx_ps", float64(n4)/dt)
	out = add(out, "http.5xx_ps", float64(n5)/dt)
	return out, nil
}

// status extracts the code after the quoted request line in combined/common log format.
func status(l []byte) int {
	i := bytes.IndexByte(l, '"')
	if i < 0 {
		return 0
	}
	j := bytes.IndexByte(l[i+1:], '"')
	if j < 0 {
		return 0
	}
	s := l[i+j+2:]
	if len(s) < 4 || s[0] != ' ' {
		return 0
	}
	return int(atou(s[1:4]))
}

// clientIP returns $remote_addr, or the last quoted field ("$http_cf_connecting_ip") when $remote_addr is a
// Cloudflare edge: the header is trusted only from Cloudflare, so a spoofed one from anyone else is ignored.
func clientIP(l []byte) (netip.Addr, bool) {
	i := bytes.IndexByte(l, ' ')
	if i < 0 {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(string(l[:i]))
	if err != nil {
		return a, false
	}
	if !isCF(a) {
		return a, true
	}
	l = bytes.TrimRight(l, " \r")
	if len(l) < 2 || l[len(l)-1] != '"' {
		return a, true
	}
	j := bytes.LastIndexByte(l[:len(l)-1], '"')
	if r, err := netip.ParseAddr(string(l[j+1 : len(l)-1])); err == nil {
		return r, true
	}
	return a, true
}

// count adds one request from a to the per-IP and per-request totals.
func (c *nginxCollector) count(a netip.Addr, line []byte) {
	ip := a.As16()
	c.ips[ip]++
	req := request(line)
	if req == nil {
		return
	}
	c.kb = append(append(c.kb[:0], ip[:]...), req...)
	if p := c.flows[string(c.kb)]; p != nil {
		*p++
		return
	}
	// shortcut: pairs beyond maxFlows are not counted per request (per-IP totals stay exact), raise it if needed
	if len(c.flows) < maxFlows {
		n := int32(1)
		c.flows[string(c.kb)] = &n
	}
}

func (c *nginxCollector) topHTTP(n int) []Flow {
	top := topK(func(yield func(string, int32) bool) {
		for k, p := range c.flows {
			if !yield(k, *p) {
				return
			}
		}
	}, n)
	out := make([]Flow, len(top))
	for i, x := range top {
		out[i] = Flow{IP: net.IP(x.k[:16]).String(), Dest: x.k[16:], Count: int(x.v)}
	}
	return out
}

// request returns "METHOD /path" from the quoted request line, without the query string, capped at 100 bytes.
func request(l []byte) []byte {
	i := bytes.IndexByte(l, '"')
	if i < 0 {
		return nil
	}
	r := l[i+1:]
	j := bytes.IndexByte(r, '"')
	if j < 0 {
		return nil
	}
	m, rest, ok := bytes.Cut(r[:j], []byte{' '})
	if !ok || len(m) == 0 || len(rest) == 0 {
		return nil
	}
	p, _, _ := bytes.Cut(rest, []byte{' '})
	if k := bytes.IndexByte(p, '?'); k >= 0 {
		p = p[:k]
	}
	return r[:min(len(m)+1+len(p), 100)]
}
