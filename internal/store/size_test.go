package store

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tb12as/kurogane/internal/collector"
)

// PRD §5 acceptance: a 7-day store (24 h raw + 7 d rollups at a 10 s interval) stays under 200 MB.
// Slow (simulates 60480 ticks), so it runs only with SK_SIZE_TEST=1.
func TestSevenDayStoreSize(t *testing.T) {
	if os.Getenv("SK_SIZE_TEST") != "1" {
		t.Skip("set SK_SIZE_TEST=1")
	}
	p := filepath.Join(t.TempDir(), "agent.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	s.db.NoSync = true // speed only; does not change the file size
	const series = 300
	start := time.Now().Add(-7 * 24 * time.Hour)
	batch := make([]collector.Sample, series)
	for i := range batch {
		batch[i] = collector.Sample{Metric: "m.v", Labels: map[string]string{"id": fmt.Sprint(i)}}
	}
	for tick := 0; tick < 7*24*360; tick++ {
		for i := range batch {
			batch[i].Value = float64((tick*7 + i) % 1000)
		}
		if err := s.Append(start.Add(time.Duration(tick)*10*time.Second), batch); err != nil {
			t.Fatal(err)
		}
		if tick%3600 == 0 { // prune every 10 h like the agent's periodic pruning
			s.Prune(24*time.Hour, 7*24*time.Hour)
		}
	}
	s.Prune(24*time.Hour, 7*24*time.Hour)
	s.Close()
	st, _ := os.Stat(p)
	mb := float64(st.Size()) / (1 << 20)
	t.Logf("7-day store with %d series: %.1f MB", series, mb)
	if mb >= 200 {
		t.Fatalf("store %.1f MB exceeds the 200 MB budget", mb)
	}
}
