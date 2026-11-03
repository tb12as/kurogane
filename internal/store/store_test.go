package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/tb12as/serverman/internal/collector"
)

func TestAppendQueryRollup(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := time.Now().Add(-10 * time.Minute).Truncate(time.Minute)
	for i := 0; i < 60; i++ { // 10 minutes at 10s
		ts := base.Add(time.Duration(i) * 10 * time.Second)
		err := s.Append(ts, []collector.Sample{
			{Metric: "cpu.total_pct", Value: float64(i)},
			{Metric: "disk.used_pct", Labels: map[string]string{"mount": "/"}, Value: 50},
			{Metric: "mem.available_pct", Value: 30},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	res, err := s.Query(Query{Names: []string{"cpu", "disk"}, From: base, To: base.Add(10 * time.Minute), Step: 10 * time.Second}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 || len(res[0].Points) != 60 {
		t.Fatalf("raw query: %d series, %+v", len(res), res)
	}
	if res[1].Labels["mount"] != "/" {
		t.Fatalf("labels lost: %+v", res[1])
	}
	roll, err := s.Query(Query{Names: []string{"cpu"}, From: base, To: base.Add(10 * time.Minute), Step: time.Minute}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// 9 complete minutes flushed; first minute avg of 0..5 = 2.5, max 5
	if len(roll) != 1 || len(roll[0].Points) != 9 || roll[0].Points[0][1] != 2.5 || roll[0].Points[0][2] != 5 {
		t.Fatalf("rollup: %+v", roll)
	}
	if err := s.Prune(0, time.Hour); err != nil {
		t.Fatal(err)
	}
	res, _ = s.Query(Query{Names: []string{"cpu"}, From: base, Step: 10 * time.Second}, 24*time.Hour)
	if len(res) != 0 {
		t.Fatalf("prune failed: %+v", res)
	}
}

func TestKV(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "a.db"))
	defer s.Close()
	type x struct{ A int }
	s.Put("b", "k", x{3})
	var got x
	if err := s.Get("b", "k", &got); err != nil || got.A != 3 {
		t.Fatal(err, got)
	}
	k1, _ := s.Enqueue("q", x{1})
	k2, _ := s.Enqueue("q", x{2})
	if k1 >= k2 {
		t.Fatal("queue order")
	}
	n := 0
	s.List("q", func(string, []byte) error { n++; return nil })
	if n != 2 {
		t.Fatal(n)
	}
}
