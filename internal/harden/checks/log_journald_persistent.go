package checks

import (
	"context"
	"strings"

	"github.com/tb12as/kurogane/internal/hostfs"
)

const journaldDropin = "/etc/systemd/journald.conf.d/99-serverkeeper.conf"

func journalPersistent() (applies, ok bool, ev string) {
	if !hostfs.Exists("/etc/systemd/journald.conf") && !hostfs.Exists("/etc/systemd/journald.conf.d") &&
		!hostfs.Exists("/var/log/journal") {
		return false, false, "systemd-journald not configured on this host"
	}
	s := strings.ToLower(iniValue(confFiles("/etc/systemd/journald.conf", "/etc/systemd/journald.conf.d"), "Storage"))
	switch {
	case s == "persistent":
		return true, true, "Storage=persistent"
	case (s == "" || s == "auto") && hostfs.Exists("/var/log/journal"):
		return true, true, "Storage=auto and /var/log/journal exists"
	case s == "":
		s = "auto"
	}
	return true, false, "Storage=" + s + " and no persistent journal directory"
}

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "LOG-JOURNALD-PERSISTENT", Title: "journald stores logs persistently", Category: "logging",
			Severity: Medium, CIS: "4.2.2.3",
			Rationale:   "Volatile logs are lost on reboot, together with the evidence of an incident.",
			Remediation: "Set `Storage=persistent` in a journald.conf drop-in and restart systemd-journald."}, e,
			func(_ context.Context, c *fnCheck) Result {
				applies, ok, ev := journalPersistent()
				switch {
				case !applies:
					return c.res(NA, ev)
				case ok:
					return c.res(Pass, ev)
				}
				return c.res(Fail, ev)
			},
			func(context.Context, *fnCheck) (Diff, error) {
				if _, ok, _ := journalPersistent(); ok {
					return Diff{}, nil
				}
				return Diff{Files: []FileEdit{{Path: journaldDropin, Mode: 0o644, New: "[Journal]\nStorage=persistent\n"}},
					Cmds: [][]string{cmd("systemctl", "restart", "systemd-journald")},
					Undo: [][]string{cmd("systemctl", "restart", "systemd-journald")}}, nil
			})
	})
}
