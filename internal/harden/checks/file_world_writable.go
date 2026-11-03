package checks

import (
	"context"
	"fmt"
	"strings"
)

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "FILE-WORLD-WRITABLE", Title: "No world-writable files in system directories",
			Category: "files", Severity: High, CIS: "6.1.9", AutoFix: FixPartial,
			Rationale: "World-writable files in /etc, /usr, /bin, /sbin or /lib let any user alter system programs " +
				"or configuration.",
			Remediation: "Remove the world-write bit (`chmod o-w <file>`); the fix does this for every finding."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				w := sysWalk(ctx)
				if ctx.Err() != nil {
					return c.res(Error, "filesystem walk did not finish in the scan budget")
				}
				if len(w.WorldWritable) == 0 {
					return c.res(Pass, "no world-writable files in "+strings.Join(walkDirs, " "))
				}
				var ps []string
				for _, f := range w.WorldWritable {
					ps = append(ps, fmt.Sprintf("%s (%04o)", f.Path, f.Mode))
				}
				return c.res(Fail, fmt.Sprintf("%d world-writable: %s", len(ps), short(ps, 20)))
			},
			func(ctx context.Context, c *fnCheck) (Diff, error) {
				d := Diff{}
				for _, f := range sysWalk(ctx).WorldWritable {
					d.Modes = append(d.Modes, ModeEdit{Path: f.Path, Old: f.Mode, New: f.Mode &^ 0o002})
				}
				return d, ctx.Err()
			})
	})
}
