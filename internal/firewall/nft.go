package firewall

import (
	"net"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// netlinkNft owns table `inet kurogane` with timeout sets banned4/banned6 dropped on input.
type netlinkNft struct {
	t      *nftables.Table
	s4, s6 *nftables.Set
}

const (
	nfprotoIPv4 = 2
	nfprotoIPv6 = 10
)

func elem(p net.IP, d time.Duration) nftables.SetElement {
	if d < time.Second {
		d = time.Second
	}
	return nftables.SetElement{Key: p, Timeout: d.Truncate(time.Millisecond)}
}

func (n *netlinkNft) setup(bans []Ban) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	n.t = &nftables.Table{Family: nftables.TableFamilyINet, Name: "kurogane"}
	n.s4 = &nftables.Set{Table: n.t, Name: "banned4", KeyType: nftables.TypeIPAddr, HasTimeout: true}
	n.s6 = &nftables.Set{Table: n.t, Name: "banned6", KeyType: nftables.TypeIP6Addr, HasTimeout: true}
	ts, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return err
	}
	// recreate from scratch so a stale table never keeps old rules
	for _, t := range ts {
		if t.Name == n.t.Name {
			c.DelTable(n.t)
		}
	}
	c.AddTable(n.t)
	var e4, e6 []nftables.SetElement
	now := time.Now()
	for _, b := range bans {
		p := parseIP(b.IP)
		if p == nil || !b.ExpiresAt.After(now) {
			continue
		}
		if p.To4() != nil {
			e4 = append(e4, elem(p, b.ExpiresAt.Sub(now)))
		} else {
			e6 = append(e6, elem(p.To16(), b.ExpiresAt.Sub(now)))
		}
	}
	if err := c.AddSet(n.s4, e4); err != nil {
		return err
	}
	if err := c.AddSet(n.s6, e6); err != nil {
		return err
	}
	ch := c.AddChain(&nftables.Chain{Name: "input", Table: n.t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityRef(-10)})
	for _, r := range []struct {
		proto    byte
		off, len uint32
		s        *nftables.Set
	}{{nfprotoIPv4, 12, 4, n.s4}, {nfprotoIPv6, 8, 16, n.s6}} {
		c.AddRule(&nftables.Rule{Table: n.t, Chain: ch, Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{r.proto}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: r.off, Len: r.len},
			&expr.Lookup{SourceRegister: 1, SetName: r.s.Name, SetID: r.s.ID},
			&expr.Verdict{Kind: expr.VerdictDrop},
		}})
	}
	return c.Flush()
}

func (n *netlinkNft) set(p net.IP) (*nftables.Set, net.IP) {
	if v4 := p.To4(); v4 != nil {
		return n.s4, v4
	}
	return n.s6, p.To16()
}

func (n *netlinkNft) add(p net.IP, d time.Duration) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	s, k := n.set(p)
	if err := c.SetAddElements(s, []nftables.SetElement{elem(k, d)}); err != nil {
		return err
	}
	return c.Flush()
}

func (n *netlinkNft) del(p net.IP) error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	s, k := n.set(p)
	if err := c.SetDeleteElements(s, []nftables.SetElement{{Key: k}}); err != nil {
		return err
	}
	return c.Flush()
}
