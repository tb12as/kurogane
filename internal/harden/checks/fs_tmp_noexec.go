package checks

import (
	"context"
	"strings"

	"github.com/tb12as/serverman/internal/hostfs"
)

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "FS-TMP-NOEXEC", Title: "/tmp mounted noexec,nosuid", Category: "filesystem",
			Severity: Low, CIS: "1.1.2.4",
			Rationale: "Attackers commonly drop and run payloads from /tmp; noexec and nosuid block that.",
			Remediation: "Add `noexec,nosuid,nodev` to the /tmp entry in /etc/fstab (or tmp.mount) and " +
				"`mount -o remount /tmp`."}, e,
			func(_ context.Context, c *fnCheck) Result {
				lines, err := hostfs.Lines("/proc/self/mounts")
				if err != nil {
					return c.res(Error, "cannot read /proc/self/mounts: "+err.Error())
				}
				opts := ""
				for _, l := range lines {
					if f := strings.Fields(l); len(f) >= 4 && f[1] == "/tmp" {
						opts = f[3]
					}
				}
				if opts == "" {
					return c.res(NA, "/tmp is not a separate mount")
				}
				var miss []string
				for _, o := range []string{"noexec", "nosuid"} {
					if !contains(strings.Split(opts, ","), o) {
						miss = append(miss, o)
					}
				}
				if len(miss) > 0 {
					return c.res(Fail, "/tmp options "+opts+" (missing "+strings.Join(miss, ",")+")")
				}
				return c.res(Pass, "/tmp options "+opts)
			}, nil)
	})
}
