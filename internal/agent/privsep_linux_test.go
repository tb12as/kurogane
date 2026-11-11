package agent

import (
	"os/user"
	"slices"
	"strconv"
	"testing"
)

// the worker credential must carry every group of the user, not an empty list that drops adm
func TestGroupIDs(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	want, err := u.GroupIds()
	if err != nil {
		t.Skip(err)
	}

	got := groupIDs(u)
	if len(got) != len(want) {
		t.Fatalf("groups = %v, want %v", got, want)
	}
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	if !slices.Contains(got, uint32(gid)) {
		t.Errorf("primary group %d missing from %v", gid, got)
	}
}
