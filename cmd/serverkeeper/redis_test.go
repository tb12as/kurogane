package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/tb12as/serverman/internal/collector"
)

func TestPrintRedis(t *testing.T) {
	hit := 92.5
	rs := []collector.RedisInstance{
		{Name: "redis", Status: "up", Version: "7.2.4", Role: "master", Replicas: 1, MemoryUsed: 512 << 20, MaxMemory: 1 << 30,
			OpsPS: 120, HitRatio: &hit, Clients: 8, LastSave: time.Unix(1762200000, 0), RDBStatus: "err"},
		{Name: "redis-cache", Addr: "127.0.0.1:6380", Status: "needs_credentials", Hint: "Set password_file."},
		{Name: "redis-queue", Addr: "127.0.0.1:6381", Status: "down", Error: "connection refused"},
	}
	var b bytes.Buffer
	printRedis(&b, rs)
	for _, want := range []string{"master (1 replicas)", "512.0 MB / 1.0 GB (50%)", "92.5%", "(FAILED)", "needs credentials",
		"! redis-cache: 127.0.0.1:6380. Set password_file.", "! redis-queue: 127.0.0.1:6381: connection refused"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, b.String())
		}
	}
	if redisProblems(rs) != 1 {
		t.Errorf("problems = %d (needs_credentials is not a failure)", redisProblems(rs))
	}
	b.Reset()
	printRedis(&b, nil)
	if !strings.Contains(b.String(), "no Redis monitored") {
		t.Error(b.String())
	}
	if bytesShort(512) != "512 B" {
		t.Error(bytesShort(512))
	}
}
