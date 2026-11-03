package agentlink

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tb12as/serverman/internal/collector"
	"github.com/tb12as/serverman/internal/db"
	"github.com/tb12as/serverman/internal/pb"
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
