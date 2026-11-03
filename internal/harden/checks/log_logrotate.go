package checks

import (
	"context"

	"github.com/tb12as/serverman/internal/hostfs"
)

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "LOG-LOGROTATE", Title: "Log rotation configured", Category: "logging", Severity: Low,
			CIS:         "4.3",
			Rationale:   "Without rotation logs grow until the disk fills, which stops logging (and often services).",
			Remediation: "Install logrotate and enable its daily run (`systemctl enable --now logrotate.timer`)."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				if !hostfs.Exists("/etc/logrotate.conf") {
					return c.res(Fail, "/etc/logrotate.conf missing (logrotate not installed)")
				}
				if hostfs.Exists("/etc/cron.daily/logrotate") {
					return c.res(Pass, "logrotate configured, run daily by cron")
				}
				if enabled(ctx, c.e, "logrotate.timer") {
					return c.res(Pass, "logrotate configured, logrotate.timer enabled")
				}
				return c.res(Fail, "logrotate configured but neither logrotate.timer nor cron.daily runs it")
			},
			func(ctx context.Context, c *fnCheck) (Diff, error) {
				d := Diff{}
				if !hostfs.Exists("/etc/logrotate.conf") {
					d.Cmds = append(d.Cmds, installCmd(ctx, "logrotate"))
				} else if hostfs.Exists("/etc/cron.daily/logrotate") || enabled(ctx, c.e, "logrotate.timer") {
					return d, nil
				}
				d.Cmds = append(d.Cmds, cmd("systemctl", "enable", "--now", "logrotate.timer"))
				d.Undo = [][]string{cmd("systemctl", "disable", "--now", "logrotate.timer")}
				return d, nil
			})
	})
}
