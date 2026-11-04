package agentlink

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tb12as/kurogane/internal/collector"
	"github.com/tb12as/kurogane/internal/db"
	"github.com/tb12as/kurogane/internal/pb"
	"github.com/tb12as/kurogane/internal/sites"
	"github.com/tb12as/kurogane/internal/webconf"
)

func TestBufferBounded(t *testing.T) {
	l := &Link{}
	for i := 0; i < maxSamples+10; i++ {
		l.OnSnapshot(&collector.Snapshot{TS: time.UnixMilli(int64(i)), Samples: []collector.Sample{{Metric: "m"}}})
	}
	for i := 0; i < maxQueue+5; i++ {
		l.ForwardAudit(db.AuditEntry{Action: "x"})
	}
	if len(l.samples) != maxSamples || l.samples[0].GetSamples().TsMs != 10 {
		t.Fatalf("samples %d first %d", len(l.samples), l.samples[0].GetSamples().TsMs)
	}
	if len(l.out) != maxQueue {
		t.Fatal(len(l.out))
	}
}

func TestExecTypedOps(t *testing.T) {
	l := &Link{
		RemoveKey: func(_ context.Context, fp, user string) (int, error) { return 2, nil },
		Scan:      func(context.Context) (db.Scan, error) { return db.Scan{}, errors.New("busy") },
	}
	r := l.exec(context.Background(), &pb.Op{Id: "1", Kind: &pb.Op_RemoveKey{RemoveKey: &pb.RemoveKey{Fingerprint: "f"}}})
	if res := r.GetOpResult(); !res.Ok || res.Result != `{"removed":2}` {
		t.Fatal(res)
	}
	r = l.exec(context.Background(), &pb.Op{Id: "2", Kind: &pb.Op_RunScan{RunScan: &pb.RunScan{}}})
	if res := r.GetOpResult(); res.Ok || res.Error != "busy" {
		t.Fatal(res)
	}
	if r := l.exec(context.Background(), &pb.Op{Id: "3"}); r.GetOpResult().Ok {
		t.Fatal("empty op accepted")
	}
}

func TestSitesMsgAndSetSite(t *testing.T) {
	inv := sites.Inventory{ScannedAt: time.Unix(1, 0), Sites: []sites.Site{{ID: "nginx:/x#0", Name: "x", Enabled: true,
		Listen: []webconf.Listen{{Port: 443, TLS: true}, {Addr: "::", Port: 443, TLS: true}, {Port: 80}}}}}
	m, sig := sitesMsg(inv)
	s := m.GetSites().Sites[0]
	if len(s.Ports) != 2 || !s.Tls || s.Toggleable || s.HasCertDays {
		t.Fatalf("site = %+v", s)
	}
	inv.ScannedAt = time.Unix(99, 0)
	if _, sig2 := sitesMsg(inv); sig2 != sig {
		t.Fatal("scan time changed the signature")
	}
	inv.Sites[0].Enabled = false
	if _, sig3 := sitesMsg(inv); sig3 == sig {
		t.Fatal("a real change kept the signature")
	}

	l := &Link{}
	r := l.exec(context.Background(), &pb.Op{Id: "o1", Kind: &pb.Op_SetSite{SetSite: &pb.SetSite{SiteId: "x"}}}).GetOpResult()
	if r.Ok || !strings.Contains(r.Error, "site management is off") {
		t.Fatalf("result = %+v", r)
	}
	n := 0
	l.Sites = func() sites.Inventory { n++; return inv }
	l.pushSites(false)
	l.pushSites(false)
	l.pushSites(true)
	if len(l.out) != 2 {
		t.Fatalf("queued %d inventory messages, want 2 (first + forced)", len(l.out))
	}
}
