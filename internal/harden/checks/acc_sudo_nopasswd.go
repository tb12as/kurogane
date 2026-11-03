package checks

import (
	"context"
	"regexp"
	"strings"

	"github.com/serverkeeper/serverkeeper/internal/hostfs"
)

var nopasswdAll = regexp.MustCompile(`NOPASSWD\s*:\s*ALL\s*$`)

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "ACC-SUDO-NOPASSWD", Title: "No sudo rules with NOPASSWD: ALL", Category: "accounts",
			Severity: Medium, CIS: "5.3.4",
			Rationale: "Passwordless full sudo turns any compromise of that user (or its SSH key) into root.",
			Remediation: "Remove `NOPASSWD: ALL` from sudoers (edit with `visudo`), or restrict it to specific " +
				"commands. Cloud images often add it in /etc/sudoers.d/90-cloud-init-users."}, e,
			func(_ context.Context, c *fnCheck) Result {
				files := append([]string{"/etc/sudoers"}, dirFiles("/etc/sudoers.d")...)
				var hits []string
				read := 0
				for _, f := range files {
					lines, err := hostfs.Lines(f)
					if err != nil {
						continue
					}
					read++
					for _, l := range lines {
						l = strings.TrimSpace(l)
						if l != "" && l[0] != '#' && nopasswdAll.MatchString(l) {
							hits = append(hits, f+": "+l)
						}
					}
				}
				if read == 0 {
					return c.res(NA, "no readable sudoers files (sudo not installed or not root)")
				}
				if len(hits) > 0 {
					return c.res(Fail, strings.Join(hits, "; "))
				}
				return c.res(Pass, "no NOPASSWD: ALL rules")
			}, nil)
	})
}
