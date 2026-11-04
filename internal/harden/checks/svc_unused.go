package checks

import (
	"context"
	"strings"

	"github.com/tb12as/kurogane/internal/hostfs"
)

// unusedUnits are desktop/LAN services rarely needed on servers, with their socket units.
var unusedUnits = map[string][]string{"avahi-daemon": {"avahi-daemon.socket"}, "cups": {"cups.socket", "cups.path"},
	"rpcbind": {"rpcbind.socket"}, "nfs-server": nil}

func hasExports() bool {
	lines, _ := hostfs.Lines("/etc/exports")
	for _, l := range lines {
		if l = strings.TrimSpace(l); l != "" && l[0] != '#' {
			return true
		}
	}
	return false
}

func unusedActive(ctx context.Context, e *Env) []string {
	st := unitStates(ctx, e, "avahi-daemon", "cups", "rpcbind", "nfs-server")
	var bad []string
	for _, u := range []string{"avahi-daemon", "cups", "rpcbind", "nfs-server"} {
		if st[u] != "active" || ((u == "nfs-server" || u == "rpcbind") && hasExports()) {
			continue
		}
		bad = append(bad, u)
	}
	return bad
}

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "SVC-UNUSED", Title: "Unused network services disabled", Category: "services", Severity: Low,
			CIS: "2.2.2", AutoFix: FixPartial,
			Rationale: "avahi, CUPS, rpcbind and an NFS server without exports add attack surface for no benefit.",
			Remediation: "`systemctl disable --now <unit>` for each listed service (the fix does this; revert " +
				"re-enables them)."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				if bad := unusedActive(ctx, c.e); len(bad) > 0 {
					return c.res(Fail, "active: "+strings.Join(bad, ", "))
				}
				return c.res(Pass, "avahi, cups, rpcbind and nfs-server inactive (or NFS exports in use)")
			},
			func(ctx context.Context, c *fnCheck) (Diff, error) {
				d := Diff{}
				for _, u := range unusedActive(ctx, c.e) {
					for _, x := range append([]string{u}, unusedUnits[u]...) {
						d.Cmds = append(d.Cmds, cmd("systemctl", "stop", x), cmd("systemctl", "disable", x))
						d.Undo = append(d.Undo, cmd("systemctl", "enable", x), cmd("systemctl", "start", x))
					}
				}
				return d, nil
			})
	})
}
