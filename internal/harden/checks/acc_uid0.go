package checks

import (
	"context"
	"strings"

	"github.com/tb12as/kurogane/internal/hostfs"
)

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "ACC-UID0", Title: "No UID 0 account besides root", Category: "accounts", Severity: Critical,
			CIS:         "6.2.10",
			Rationale:   "Any account with UID 0 has full root privileges and is often a sign of a backdoor.",
			Remediation: "Remove the extra UID 0 accounts or give them a unique UID (`usermod -u <uid> <user>`)."}, e,
			func(_ context.Context, c *fnCheck) Result {
				lines, err := hostfs.Lines("/etc/passwd")
				if err != nil {
					return c.res(Error, "cannot read /etc/passwd: "+err.Error())
				}
				var bad []string
				for _, l := range lines {
					f := strings.Split(l, ":")
					if len(f) > 3 && f[2] == "0" && f[0] != "root" {
						bad = append(bad, f[0])
					}
				}
				if len(bad) > 0 {
					return c.res(Fail, "UID 0 accounts besides root: "+strings.Join(bad, ", "))
				}
				return c.res(Pass, "only root has UID 0")
			}, nil)
	})
}
