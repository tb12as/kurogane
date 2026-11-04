package collector

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/tb12as/kurogane/internal/hostfs"
)

// netCollector reads /proc/net/dev (per interface) and /proc/net/snmp{,6} (new conns, udp packets).
type netCollector struct {
	prev   map[string]*ifStat
	prevT  time.Time
	lbl    *labels
	opens  uint64 // Tcp ActiveOpens+PassiveOpens
	udpIn  uint64 // Udp InDatagrams + Udp6InDatagrams
	snmpOK bool
	f, h   [][]byte
}

type ifStat struct {
	rxB, rxP, rxE, rxD, txB, txP, txE, txD uint64
	seen                                   bool
}

func newNet() *netCollector {
	return &netCollector{prev: map[string]*ifStat{}, lbl: newLabels("iface")}
}

func (c *netCollector) Collect(context.Context) ([]Sample, error) {
	t := now()
	dt := t.Sub(c.prevT).Seconds()
	first := c.prevT.IsZero()
	c.prevT = t
	out, err1 := c.dev(nil, dt, first)
	out, err2 := c.snmp(out, dt, first)
	return out, errors.Join(err1, err2)
}

func (c *netCollector) dev(out []Sample, dt float64, first bool) ([]Sample, error) {
	b, err := hostfs.Read("/proc/net/dev")
	if err != nil {
		return out, err
	}
	var rxB, txB, rxP, txP float64
	for l := range bytes.Lines(b) {
		i := bytes.IndexByte(l, ':')
		if i < 0 {
			continue
		}
		name := bytes.TrimSpace(l[:i])
		c.f = fields(l[i+1:], c.f)
		if len(c.f) < 16 {
			continue
		}
		f := c.f
		cur := ifStat{atou(f[0]), atou(f[1]), atou(f[2]), atou(f[3]), atou(f[8]), atou(f[9]), atou(f[10]), atou(f[11]), true}
		p := c.prev[string(name)]
		if p == nil {
			p = &ifStat{}
			c.prev[string(name)] = p
		}
		if !first && p.seen {
			// veth pairs mirror bridge traffic and churn with containers: skip to bound series count
			veth := bytes.HasPrefix(name, []byte("veth"))
			lb := c.lbl.get(name)
			r := [8]float64{rate(cur.rxB, p.rxB, dt), rate(cur.txB, p.txB, dt), rate(cur.rxP, p.rxP, dt),
				rate(cur.txP, p.txP, dt), rate(cur.rxE, p.rxE, dt), rate(cur.txE, p.txE, dt),
				rate(cur.rxD, p.rxD, dt), rate(cur.txD, p.txD, dt)}
			if !veth {
				out = addL(out, "net.rx_bps", lb, r[0])
				out = addL(out, "net.tx_bps", lb, r[1])
				out = addL(out, "net.rx_pps", lb, r[2])
				out = addL(out, "net.tx_pps", lb, r[3])
				out = addL(out, "net.rx_errors_ps", lb, r[4])
				out = addL(out, "net.tx_errors_ps", lb, r[5])
				out = addL(out, "net.rx_drops_ps", lb, r[6])
				out = addL(out, "net.tx_drops_ps", lb, r[7])
			}
			if !veth && string(name) != "lo" {
				rxB, txB, rxP, txP = rxB+r[0], txB+r[1], rxP+r[2], txP+r[3]
			}
		}
		*p = cur
	}
	if !first {
		out = add(out, "net.rx_bps_total", rxB)
		out = add(out, "net.tx_bps_total", txB)
		out = add(out, "net.rx_pps_total", rxP)
		out = add(out, "net.tx_pps_total", txP)
	}
	return out, nil
}

func (c *netCollector) snmp(out []Sample, dt float64, first bool) ([]Sample, error) {
	b, err := hostfs.Read("/proc/net/snmp")
	if err != nil {
		return out, err
	}
	var opens, udp uint64
	var hdr []byte
	for l := range bytes.Lines(b) {
		if !bytes.HasPrefix(l, []byte("Tcp:")) && !bytes.HasPrefix(l, []byte("Udp:")) {
			continue
		}
		if hdr == nil || !bytes.Equal(hdr[:4], l[:4]) {
			hdr = l
			continue
		}
		c.h, c.f = fields(hdr, c.h), fields(l, c.f)
		hdr = nil
		for i := 1; i < len(c.h) && i < len(c.f); i++ {
			switch string(c.h[i]) {
			case "ActiveOpens", "PassiveOpens":
				if l[0] == 'T' {
					opens += atou(c.f[i])
				}
			case "InDatagrams":
				if l[0] == 'U' {
					udp += atou(c.f[i])
				}
			}
		}
	}
	if b6, err := hostfs.Read("/proc/net/snmp6"); err == nil {
		if i := bytes.Index(b6, []byte("Udp6InDatagrams")); i >= 0 {
			c.f = fields(b6[i:min(len(b6), i+64)], c.f)
			if len(c.f) > 1 {
				udp += atou(c.f[1])
			}
		}
	}
	if !first && c.snmpOK {
		out = add(out, "net.new_conns_ps", rate(opens, c.opens, dt))
		out = add(out, "net.udp_pps", rate(udp, c.udpIn, dt))
	}
	c.opens, c.udpIn, c.snmpOK = opens, udp, true
	return out, nil
}
