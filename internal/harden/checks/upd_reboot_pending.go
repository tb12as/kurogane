package checks

import (
	"context"
	"strings"

	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/hostfs"
)

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "UPD-REBOOT-PENDING", Title: "No reboot pending", Category: "updates", Severity: Medium,
			Rationale:   "Kernel and library updates only take effect after a reboot; until then the old code runs.",
			Remediation: "Schedule a reboot in a maintenance window."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				if distro(ctx).PkgMgr == "dnf" {
					_, err := c.e.Ex.Run(ctx, "needs-restarting", "-r")
					switch {
					case err == nil:
						return c.res(Pass, "needs-restarting -r: no reboot needed")
					case executor.ExitCode(err) == 1:
						return c.res(Fail, "needs-restarting -r: reboot required")
					}
					return c.res(Error, "needs-restarting failed (install dnf-utils): "+err.Error())
				}
				for _, p := range []string{"/run/reboot-required", "/var/run/reboot-required"} {
					if hostfs.Exists(p) {
						pk, _ := readFile(p + ".pkgs")
						return c.res(Fail, strings.TrimSpace(p+" exists; packages: "+strings.Join(strings.Fields(pk), ", ")))
					}
				}
				return c.res(Pass, "no /run/reboot-required")
			}, nil)
	})
}
