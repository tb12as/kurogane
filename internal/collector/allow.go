package collector

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"time"
)

// allowTTL is how long a hostname lookup is trusted: managed-service addresses change.
const allowTTL = 5 * time.Minute

// lookup resolves allowlisted hostnames; replaced in tests.
var lookup = net.DefaultResolver.LookupNetIP

// allowlist holds remote addresses the attack counters ignore (collector.conn_allowlist): fixed IPs and CIDRs
// plus hostnames re-resolved every allowTTL.
type allowlist struct {
	fixed []netip.Prefix
	hosts map[string][]netip.Addr // last good lookup per hostname
	pfx   []netip.Prefix          // fixed + resolved
	at    time.Time
}

func newAllowlist(entries []string) allowlist {
	a := allowlist{hosts: map[string][]netip.Addr{}}
	for _, e := range entries {
		if p, err := netip.ParsePrefix(e); err == nil {
			a.fixed = append(a.fixed, netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-unmapBits(p.Addr())).Masked())
			continue
		}
		if ip, err := netip.ParseAddr(e); err == nil {
			ip = ip.Unmap()
			a.fixed = append(a.fixed, netip.PrefixFrom(ip, ip.BitLen()))
			continue
		}
		a.hosts[e] = nil
	}
	a.pfx = a.fixed
	return a
}

// unmapBits is the prefix length lost when a v4-mapped prefix is unmapped.
func unmapBits(a netip.Addr) int {
	if a.Is4In6() {
		return 96
	}
	return 0
}

// refresh re-resolves the hostnames once allowTTL has passed; a failed lookup keeps that host's last addresses.
func (a *allowlist) refresh(ctx context.Context) {
	if len(a.hosts) == 0 || (!a.at.IsZero() && now().Sub(a.at) < allowTTL) {
		return
	}
	a.at = now()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	pfx := append([]netip.Prefix(nil), a.fixed...)
	for h := range a.hosts {
		ips, err := lookup(ctx, "ip", h)
		if err != nil {
			slog.Warn("collector.conn_allowlist: lookup failed, keeping the last addresses", "host", h, "err", err)
		} else {
			a.hosts[h] = ips
		}
		for _, ip := range a.hosts[h] {
			ip = ip.Unmap()
			pfx = append(pfx, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	a.pfx = pfx
}

func (a *allowlist) has(ip *[16]byte) bool {
	if len(a.pfx) == 0 {
		return false
	}
	x := netip.AddrFrom16(*ip).Unmap()
	for _, p := range a.pfx {
		if p.Contains(x) {
			return true
		}
	}
	return false
}
