package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"iter"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/tb12as/kurogane/internal/hostfs"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const (
	tcpEstablished = 1
	tcpSynSent     = 2
	tcpSynRecv     = 3
	tcpFinWait1    = 4
	tcpFinWait2    = 5
	tcpTimeWait    = 6
	tcpCloseWait   = 8
	tcpListen      = 10
	tcpNewSynRecv  = 12
)

var tcpStateNames = [...]string{"", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT",
	"CLOSE", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING", "SYN_RECV"}

type sock struct {
	state        uint8
	lip, rip     [16]byte // ipv4 stored v4-mapped
	lport, rport uint16
	inode        uint32
	v6           bool
}

type lkey struct {
	ip   [16]byte
	port uint16
	v6   bool
}

// connCollector counts TCP sockets via netlink sock_diag, falling back to /proc/net/tcp{,6}.
type connCollector struct {
	states  [13]int
	socks   []sock // non-listen sockets with a remote peer, classified once every listener is known
	ips     map[[16]byte]int32
	nets    map[[16]byte]int32
	peers   map[pkey][13]int32
	ports   []uint32 // per local port, non-listen sockets
	lidx    map[lkey]int
	listen  []Listener
	linodes []uint32
	allow   allowlist

	noNetlink bool
	names     map[uint32]string // socket inode -> process name
	scanAt    time.Time

	info ConnInfo
	f    [][]byte
}

func newConn(allow []string) *connCollector {
	return &connCollector{ips: map[[16]byte]int32{}, nets: map[[16]byte]int32{}, peers: map[pkey][13]int32{},
		ports: make([]uint32, 65536), lidx: map[lkey]int{}, names: map[uint32]string{}, allow: newAllowlist(allow)}
}

func (c *connCollector) Collect(ctx context.Context) ([]Sample, error) {
	c.resetCounts()
	var err error
	if c.noNetlink || (hostfs.Root != "/" && hostfs.Root != "") {
		err = c.procAll()
	} else if err = errors.Join(c.diag(unix.AF_INET), c.diag(unix.AF_INET6)); err != nil {
		slog.Debug("sock_diag unavailable, using /proc/net/tcp", "err", err)
		c.noNetlink = true
		c.resetCounts()
		err = c.procAll()
	}
	if err != nil {
		return nil, err
	}

	c.resolveNames()
	st := c.states
	syn := st[tcpSynRecv] + st[tcpNewSynRecv]
	total := 0
	states := map[string]int{}
	for i, n := range st {
		if n == 0 || i == 0 {
			continue
		}
		states[tcpStateNames[i]] += n
		if i != tcpListen {
			total += n
		}
	}
	ports := make([]PortCount, 0, len(c.listen))
	seenPort := map[uint16]bool{}
	for _, l := range c.listen {
		p := uint16(l.Port)
		if seenPort[p] {
			continue
		}
		seenPort[p] = true
		if n := c.ports[p]; n > 0 {
			ports = append(ports, PortCount{Port: l.Port, Count: int(n)})
		}
	}
	c.allow.refresh(ctx)
	c.classify(seenPort)
	tops := topN(c.ips, 10, false)
	subs := topN(c.nets, 10, true)
	sortTop(ports)
	if len(ports) > 10 {
		ports = ports[:10]
	}
	sc := hostfs.ReadString("/proc/sys/net/ipv4/tcp_syncookies")
	c.info = ConnInfo{States: states, TopIPs: tops, TopSubnets: subs, TopPorts: ports,
		TopFlows: topFlows(c.peers, 10), TopPeers: topPeers(c.peers, 10), Listening: append([]Listener(nil), c.listen...),
		SynCookies: sc != "" && sc != "0"}

	out := make([]Sample, 0, 12)
	out = add(out, "net.tcp.established", float64(st[tcpEstablished]))
	out = add(out, "net.tcp.syn_recv", float64(syn))
	out = add(out, "net.tcp.syn_sent", float64(st[tcpSynSent]))
	out = add(out, "net.tcp.time_wait", float64(st[tcpTimeWait]))
	out = add(out, "net.tcp.close_wait", float64(st[tcpCloseWait]))
	out = add(out, "net.tcp.fin_wait", float64(st[tcpFinWait1]+st[tcpFinWait2]))
	out = add(out, "net.tcp.listen", float64(st[tcpListen]))
	out = add(out, "net.tcp.total", float64(total))
	out = add(out, "net.conns_per_ip_max", float64(first(tops)))
	out = add(out, "net.conns_per_subnet_max", float64(first(subs)))
	out = add(out, "net.listening_ports", float64(len(seenPort)))
	return out, nil
}

func first(x []IPCount) int {
	if len(x) == 0 {
		return 0
	}
	return x[0].Count
}

func (c *connCollector) resetCounts() {
	c.states = [13]int{}
	c.socks = c.socks[:0]
	clear(c.ips)
	clear(c.nets)
	clear(c.peers)
	clear(c.ports)
	clear(c.lidx)
	c.listen, c.linodes = c.listen[:0], c.linodes[:0]
}

func (c *connCollector) add(s *sock) {
	if int(s.state) >= len(c.states) {
		return
	}
	c.states[s.state]++
	if s.state == tcpListen {
		k := lkey{s.lip, s.lport, s.v6}
		if _, ok := c.lidx[k]; ok {
			return // SO_REUSEPORT duplicates
		}
		proto := "tcp"
		if s.v6 {
			proto = "tcp6"
		}
		c.lidx[k] = len(c.listen)
		c.listen = append(c.listen, Listener{Proto: proto, Addr: net.IP(s.lip[:]).String(), Port: int(s.lport)})
		c.linodes = append(c.linodes, s.inode)
		return
	}
	c.ports[s.lport]++
	if !isLocal(&s.rip) {
		c.socks = append(c.socks, *s)
	}
}

// classify counts every socket per peer and direction. Only inbound ESTABLISHED and SYN_RECV sockets feed the
// per-IP and per-subnet totals behind the attack rules: outbound connections (to a database, an API) and closing
// states such as TIME_WAIT are normal traffic. A socket is inbound when its local port is listening.
func (c *connCollector) classify(listening map[uint16]bool) {
	for i := range c.socks {
		s := &c.socks[i]
		if c.allow.has(&s.rip) {
			continue
		}
		st := s.state
		if st == tcpNewSynRecv {
			st = tcpSynRecv
		}
		in := listening[s.lport]
		k := pkey{s.rip, s.rport, in}
		if in {
			k.port = s.lport
		}
		p := c.peers[k]
		p[st]++
		c.peers[k] = p
		if !in || (st != tcpEstablished && st != tcpSynRecv) {
			continue
		}
		c.ips[s.rip]++
		n := s.rip
		if isV4(&n) {
			n[15] = 0
		} else {
			clear(n[8:])
		}
		c.nets[n]++
	}
}

var v4prefix = [12]byte{10: 0xff, 11: 0xff}

func isV4(ip *[16]byte) bool { return [12]byte(ip[:12]) == v4prefix }

// isLocal reports unspecified and loopback addresses, which are not remote clients.
func isLocal(ip *[16]byte) bool {
	if isV4(ip) {
		return ip[12] == 127 || ip[12]|ip[13]|ip[14]|ip[15] == 0
	}
	var z [15]byte
	return [15]byte(ip[:15]) == z && (ip[15] == 0 || ip[15] == 1)
}

// diag dumps TCP sockets of one family with a raw inet_diag_req_v2, including SYN_RECV request sockets
// that netlink.SocketDiagTCP leaves out (its state mask stops at bit 11).
func (c *connCollector) diag(family uint8) error {
	req := nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, unix.NLM_F_DUMP)
	var r [56]byte
	r[0], r[1] = family, unix.IPPROTO_TCP
	binary.NativeEndian.PutUint32(r[4:], 1<<13-2) // states 1..12
	req.AddRawData(r[:])
	v6 := family == unix.AF_INET6
	err := req.ExecuteIter(unix.NETLINK_INET_DIAG, nl.SOCK_DIAG_BY_FAMILY, func(m []byte) bool {
		if len(m) < 72 {
			return true
		}
		s := sock{state: m[1], lport: binary.BigEndian.Uint16(m[4:]), rport: binary.BigEndian.Uint16(m[6:]),
			inode: binary.NativeEndian.Uint32(m[68:]), v6: v6}
		if v6 {
			copy(s.lip[:], m[8:24])
			copy(s.rip[:], m[24:40])
		} else {
			s.lip[10], s.lip[11], s.rip[10], s.rip[11] = 0xff, 0xff, 0xff, 0xff
			copy(s.lip[12:], m[8:12])
			copy(s.rip[12:], m[24:28])
		}
		c.add(&s)
		return true
	})
	if errors.Is(err, nl.ErrDumpInterrupted) {
		return nil // partial dump is fine for counters
	}
	return err
}

func (c *connCollector) procAll() error {
	err := c.proc("/proc/net/tcp", false)
	if err6 := c.proc("/proc/net/tcp6", true); err6 != nil && !os.IsNotExist(err6) {
		err = errors.Join(err, err6)
	}
	return err
}

func (c *connCollector) proc(p string, v6 bool) error {
	b, err := hostfs.Read(p)
	if err != nil {
		return err
	}
	hdr := true
	for l := range bytes.Lines(b) {
		if hdr {
			hdr = false
			continue
		}
		c.f = fields(l, c.f)
		if len(c.f) < 10 {
			continue
		}
		s := sock{state: uint8(hexu(c.f[3])), inode: uint32(atou(c.f[9])), v6: v6}
		var ok1, ok2 bool
		s.lip, s.lport, ok1 = hexAddr(c.f[1], v6)
		s.rip, s.rport, ok2 = hexAddr(c.f[2], v6)
		if ok1 && ok2 {
			c.add(&s)
		}
	}
	return nil
}

// hexAddr parses /proc/net/tcp "0100007F:0035": address words are in host byte order.
func hexAddr(b []byte, v6 bool) (ip [16]byte, port uint16, ok bool) {
	i := bytes.IndexByte(b, ':')
	if i < 0 {
		return ip, 0, false
	}
	h := b[:i]
	switch {
	case !v6 && len(h) == 8:
		ip[10], ip[11] = 0xff, 0xff
		binary.NativeEndian.PutUint32(ip[12:], uint32(hexu(h)))
	case v6 && len(h) == 32:
		for w := 0; w < 4; w++ {
			binary.NativeEndian.PutUint32(ip[w*4:], uint32(hexu(h[w*8:w*8+8])))
		}
	default:
		return ip, 0, false
	}
	return ip, uint16(hexu(b[i+1:])), true
}

// resolveNames maps listener inodes to process names, rescanning /proc/*/fd at most once a minute and
// only when an unknown listener shows up.
func (c *connCollector) resolveNames() {
	miss := false
	for _, ino := range c.linodes {
		if _, ok := c.names[ino]; !ok && ino != 0 {
			miss = true
			break
		}
	}
	if miss && now().Sub(c.scanAt) >= time.Minute {
		c.scanAt = now()
		c.names = scanSocketOwners(c.linodes)
	}
	for i, ino := range c.linodes {
		c.listen[i].Process = c.names[ino]
	}
}

func scanSocketOwners(want []uint32) map[uint32]string {
	need := make(map[uint32]bool, len(want))
	for _, w := range want {
		need[w] = true
	}
	out := make(map[uint32]string, len(want))
	pids, err := readDirNames(hostfs.P("/proc"))
	if err != nil {
		return out
	}
	buf := make([]byte, 512)
	for _, pid := range pids {
		if pid[0] < '0' || pid[0] > '9' {
			continue
		}
		dir := hostfs.P("/proc/" + pid + "/fd")
		fds, err := readDirNames(dir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			l, err := os.Readlink(dir + "/" + fd)
			if err != nil || len(l) < 10 || l[:8] != "socket:[" {
				continue
			}
			n, err := strconv.ParseUint(l[8:len(l)-1], 10, 32)
			if err != nil || !need[uint32(n)] {
				continue
			}
			if _, ok := out[uint32(n)]; ok {
				continue
			}
			if b, err := readInto(hostfs.P("/proc/"+pid+"/comm"), buf); err == nil {
				out[uint32(n)] = string(trimNL(b))
			}
		}
	}
	return out
}

type kv[K comparable] struct {
	k K
	v int32
}

// topK returns the n largest counts, largest first.
func topK[K comparable](seq iter.Seq2[K, int32], n int) []kv[K] {
	top := make([]kv[K], 0, n+1)
	for k, v := range seq {
		if len(top) == n && v <= top[n-1].v {
			continue
		}
		i := len(top)
		for i > 0 && top[i-1].v < v {
			i--
		}
		top = append(top, kv[K]{})
		copy(top[i+1:], top[i:])
		top[i] = kv[K]{k, v}
		if len(top) > n {
			top = top[:n]
		}
	}
	return top
}

// topN returns the n largest counts; subnet keys get a /24 or /64 suffix.
func topN(m map[[16]byte]int32, n int, subnet bool) []IPCount {
	top := topK(maps.All(m), n)
	out := make([]IPCount, len(top))
	for i, x := range top {
		s := net.IP(x.k[:]).String()
		if subnet {
			if isV4(&x.k) {
				s += "/24"
			} else {
				s += "/64"
			}
		}
		out[i] = IPCount{IP: s, Count: int(x.v)}
	}
	return out
}

// pkey is one remote address and port: the local port when inbound, the remote port when outbound.
type pkey struct {
	ip   [16]byte
	port uint16
	in   bool
}

// topFlows returns the n busiest inbound source IP -> local port pairs by ESTABLISHED and SYN_RECV sockets.
func topFlows(m map[pkey][13]int32, n int) []Flow {
	top := topK(func(yield func(pkey, int32) bool) {
		for k, v := range m {
			if a := v[tcpEstablished] + v[tcpSynRecv]; k.in && a > 0 && !yield(k, a) {
				return
			}
		}
	}, n)
	out := make([]Flow, len(top))
	for i, x := range top {
		a := netip.AddrFrom16(x.k.ip).Unmap()
		out[i] = Flow{IP: a.String(), Dest: strconv.Itoa(int(x.k.port)) + "/tcp", Count: int(x.v), Cloudflare: isCF(a)}
	}
	return out
}

// topPeers returns the n peers with the most sockets in any state, both directions, with their state breakdown.
func topPeers(m map[pkey][13]int32, n int) []Peer {
	top := topK(func(yield func(pkey, int32) bool) {
		for k, v := range m {
			var t int32
			for _, x := range v {
				t += x
			}
			if !yield(k, t) {
				return
			}
		}
	}, n)
	out := make([]Peer, len(top))
	var b []byte
	for i, x := range top {
		b = b[:0]
		for st, cnt := range m[x.k] {
			if cnt == 0 {
				continue
			}
			if len(b) > 0 {
				b = append(b, " / "...)
			}
			b = append(strconv.AppendInt(b, int64(cnt), 10), ' ')
			b = append(b, tcpStateNames[st]...)
		}
		out[i] = Peer{IP: netip.AddrFrom16(x.k.ip).Unmap().String(), Port: int(x.k.port), Inbound: x.k.in,
			States: string(b), Total: int(x.v)}
	}
	return out
}

func sortTop(p []PortCount) {
	for i := 1; i < len(p); i++ {
		for j := i; j > 0 && p[j].Count > p[j-1].Count; j-- {
			p[j], p[j-1] = p[j-1], p[j]
		}
	}
}
