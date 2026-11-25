package db

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestListEventsUntil(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	from := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	for i, id := range []string{"before", "start", "inside", "end", "after"} {
		err := s.SaveEvent(ctx, AlertEvent{ID: id, RuleID: "rule", Fingerprint: id,
			State: "firing", StartedAt: from.Add(time.Duration(i-1) * time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
	}
	evs, err := s.ListEvents(ctx, EventFilter{Since: from, Until: from.Add(2 * time.Hour)})
	if err != nil || len(evs) != 2 || evs[0].ID != "inside" || evs[1].ID != "start" {
		t.Fatalf("exclusive upper bound: %+v, %v", evs, err)
	}
	evs, err = s.ListEvents(ctx, EventFilter{Since: from, Until: from.Add(2*time.Hour + time.Nanosecond)})
	if err != nil || len(evs) != 3 || evs[0].ID != "end" {
		t.Fatalf("fractional upper bound: %+v, %v", evs, err)
	}
	evs, err = s.ListEvents(ctx, EventFilter{Since: from})
	if err != nil || len(evs) != 4 {
		t.Fatalf("unbounded: %+v, %v", evs, err)
	}
}
