package firewall

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/hostfs"
	"github.com/tb12as/kurogane/internal/store"
)

type fakeNft struct{ set map[string]time.Duration }

func (f *fakeNft) setup(bans []Ban) error {
	f.set = map[string]time.Duration{}
	for _, b := range bans {
		f.set[b.IP] = time.Until(b.ExpiresAt)
	}
	return nil
}
func (f *fakeNft) add(p net.IP, d time.Duration) error { f.set[p.String()] = d; return nil }
func (f *fakeNft) del(p net.IP) error                  { delete(f.set, p.String()); return nil }

func setup(t *testing.T) (*executor.Fake, *fakeNft) {
	t.Helper()
	old := hostfs.Root
	hostfs.Root = t.TempDir()
	t.Cleanup(func() { hostfs.Root = old })
	fn := &fakeNft{}
	on := newNft
	newNft = func() nftBackend { return fn }
	nftForTests = true
	t.Cleanup(func() { newNft = on; nftForTests = false })
	return executor.NewFake(), fn
}

func TestBanNftAllowlistCapPersist(t *testing.T) {
	ex, fn := setup(t)
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := New(ex)
	m.SetStore(st)
	if err := m.SetAllowlist([]string{"203.0.113.0/24", "2001:db8::1"}); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"127.0.0.1", "::1", "203.0.113.9", "2001:db8::1"} {
		if err := m.Ban(ctx, ip, time.Hour, "t"); !errors.Is(err, ErrExempt) {
			t.Fatalf("%s must be exempt, got %v", ip, err)
		}
	}
	if err := m.Ban(ctx, "198.51.100.7", time.Hour, "bf"); err != nil {
		t.Fatal(err)
	}
	if m.Backend() != "nftables" || fn.set["198.51.100.7"] == 0 {
		t.Fatalf("backend %s set %v", m.Backend(), fn.set)
	}
	if err := m.Ban(ctx, "2001:db8::99", time.Hour, "bf"); err != nil || len(m.Bans()) != 2 {
		t.Fatalf("v6 ban: %v %v", err, m.Bans())
	}

	// restart: bans come back from bbolt and are re-applied on setup
	m2 := New(ex)
	m2.SetStore(st)
	if m2.Backend() != "nftables" || len(m2.Bans()) != 2 || fn.set["198.51.100.7"] == 0 {
		t.Fatalf("persisted bans not restored: %v %v", m2.Bans(), fn.set)
	}
	if err := m2.Unban(ctx, "198.51.100.7"); err != nil || len(m2.Bans()) != 1 {
		t.Fatalf("unban: %v", err)
	}
	if err := m2.Unban(ctx, "198.51.100.7"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}

	old := MaxBans
	MaxBans = 1
	defer func() { MaxBans = old }()
	if err := m2.Ban(ctx, "198.51.100.8", time.Hour, "x"); !errors.Is(err, ErrCap) {
		t.Fatalf("want cap error, got %v", err)
	}
}

func TestBanUFWAndExpiry(t *testing.T) {
	ex, _ := setup(t)
	ex.Outputs["ufw status"] = "Status: active\n"
	ctx := context.Background()
	m := New(ex)
	if err := m.Ban(ctx, "198.51.100.7", 50*time.Millisecond, "bf"); err != nil {
		t.Fatal(err)
	}
	if !ex.Called("ufw prepend deny from 198.51.100.7") {
		t.Fatalf("ufw not used: %v", ex)
	}
	time.Sleep(80 * time.Millisecond)
	m.Sweep(ctx)
	if len(m.Bans()) != 0 || !ex.Called("ufw --force delete deny from 198.51.100.7") {
		t.Fatalf("expired ban not swept: %v", ex)
	}
}

func TestBanFirewalldIptables(t *testing.T) {
	ex, _ := setup(t)
	ex.Outputs["firewall-cmd --state"] = "running\n"
	m := New(ex)
	if err := m.Ban(context.Background(), "198.51.100.7", time.Hour, ""); err != nil {
		t.Fatal(err)
	}
	if !ex.Called(`firewall-cmd --add-rich-rule rule family="ipv4" source address="198.51.100.7" drop`) {
		t.Fatalf("firewalld not used: %v", ex)
	}

	ex2, _ := setup(t)
	ex2.Errors["nft list tables"] = errors.New("no nft")
	ex2.Errors["iptables -C INPUT -j SERVERKEEPER"] = errors.New("missing")
	ex2.Errors["iptables -C SERVERKEEPER -s 198.51.100.7 -j DROP"] = errors.New("missing")
	m2 := New(ex2)
	if err := m2.Ban(context.Background(), "198.51.100.7", time.Hour, ""); err != nil {
		t.Fatal(err)
	}
	if m2.Backend() != "iptables" || !ex2.Called("iptables -I INPUT 1 -j SERVERKEEPER") ||
		!ex2.Called("iptables -I SERVERKEEPER -s 198.51.100.7 -j DROP") {
		t.Fatalf("iptables path: %v", ex2)
	}
}

func TestDetectParsers(t *testing.T) {
	pol, ports := parseUFW(`Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
443                        ALLOW IN    Anywhere
Anywhere                   DENY IN     198.51.100.7
22/tcp (v6)                ALLOW IN    Anywhere (v6)
`)
	if pol != "deny" || len(ports) != 2 || ports[0] != "22/tcp" || ports[1] != "443" {
		t.Fatalf("ufw: %s %v", pol, ports)
	}
	pol, ports = parseFirewalld("public (active)\n  target: default\n  services: dhcpv6-client ssh\n  ports: 2222/tcp\n")
	if pol != "reject" || len(ports) != 3 {
		t.Fatalf("firewalld: %s %v", pol, ports)
	}
	pol, ports, n, err := parseNftJSON([]byte(`{"nftables":[{"metainfo":{}},
{"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","prio":0,"policy":"drop"}},
{"rule":{"family":"inet","table":"filter","chain":"input","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22}},{"accept":null}]}},
{"rule":{"family":"inet","table":"filter","chain":"input","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"set":[80,443]}}},{"accept":null}]}}]}`))
	if err != nil || n != 1 || pol != "drop" || len(ports) != 3 || ports[0] != "22/tcp" {
		t.Fatalf("nft: %v %s %v", err, pol, ports)
	}
	pol, ports, rules := parseIptables("-P INPUT DROP\n-P FORWARD DROP\n-A INPUT -j SERVERKEEPER\n" +
		"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n-A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT\n")
	if pol != "drop" || rules != 2 || len(ports) != 3 {
		t.Fatalf("iptables: %s %v %d", pol, ports, rules)
	}

	ex, _ := setup(t)
	ex.Outputs["ufw status"] = "Status: active\n"
	ex.Outputs["ufw status verbose"] = "Status: active\nDefault: deny (incoming), allow (outgoing)\n"
	if in := New(ex).Detect(context.Background()); in.Firewall != "ufw" || in.DefaultInbound != "deny" ||
		in.BanBackend != "ufw" {
		t.Fatalf("detect: %+v", in)
	}
}
