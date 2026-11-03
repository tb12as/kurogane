package collector

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/tb12as/serverman/internal/config"
	"github.com/tb12as/serverman/internal/executor"
)

// TestLiveSmoke reads the real host read-only; run with SK_LIVE=1.
func TestLiveSmoke(t *testing.T) {
	if os.Getenv("SK_LIVE") == "" {
		t.Skip("set SK_LIVE=1")
	}
	m := NewManager(config.Collector{Interval: time.Second, WatchServices: []string{"ssh", "cron"}}, executor.Local{})
	ctx := context.Background()
	m.collect(ctx, 0)
	time.Sleep(time.Second)
	t0 := time.Now()
	s := m.collect(ctx, 0)
	t.Logf("tick took %v, %d samples", time.Since(t0), len(s.Samples))
	for _, x := range s.Samples {
		t.Logf("%s = %.2f", x.Key(), x.Value)
	}
	t.Logf("system %+v", s.System)
	t.Logf("conns %+v", s.Conns)
	t.Logf("topcpu %+v", s.TopCPU[:3])
	t.Logf("topmem %+v", s.TopMem[:3])
	t.Logf("services %+v mounts %+v", s.Services, s.Mounts)
}
