package checks

import (
	"context"
	"strings"

	"github.com/tb12as/kurogane/internal/hostfs"
)

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "FS-CORE-DUMPS", Title: "Core dumps restricted", Category: "filesystem", Severity: Low,
			CIS:       "1.5.4",
			Rationale: "Core dumps can contain passwords, keys and other secrets from process memory.",
			Remediation: "Add `* hard core 0` to /etc/security/limits.conf (or limits.d) and set `Storage=none` in " +
				"/etc/systemd/coredump.conf."}, e,
			func(_ context.Context, c *fnCheck) Result {
				for _, f := range append([]string{"/etc/security/limits.conf"}, dirFiles("/etc/security/limits.d")...) {
					lines, _ := hostfs.Lines(f)
					for _, l := range lines {
						x := strings.Fields(l)
						if len(x) == 4 && x[0] == "*" && x[1] == "hard" && x[2] == "core" && x[3] == "0" {
							return c.res(Pass, "`* hard core 0` in "+f)
						}
					}
				}
				st := iniValue(confFiles("/etc/systemd/coredump.conf", "/etc/systemd/coredump.conf.d"), "Storage")
				if strings.EqualFold(st, "none") {
					return c.res(Pass, "systemd-coredump Storage=none")
				}
				return c.res(Fail, "no `* hard core 0` limit and systemd-coredump Storage is not none")
			}, nil)
	})
}
