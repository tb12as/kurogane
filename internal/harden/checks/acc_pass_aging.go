package checks

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var passMaxRe = regexp.MustCompile(`(?m)^\s*PASS_MAX_DAYS\s+(\S+)`)

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "ACC-PASS-AGING", Title: "Password maximum age 365 days or less", Category: "accounts",
			Severity: Medium, CIS: "5.5.1.2",
			Rationale: "Password aging limits how long a leaked password stays valid.",
			Remediation: "Set `PASS_MAX_DAYS 365` in /etc/login.defs; apply to existing users with " +
				"`chage -M 365 <user>`."}, e,
			func(_ context.Context, c *fnCheck) Result {
				s, ok := readFile("/etc/login.defs")
				if !ok {
					return c.res(NA, "/etc/login.defs not found")
				}
				m := passMaxRe.FindStringSubmatch(s)
				if m == nil {
					return c.res(Fail, "PASS_MAX_DAYS not set (default 99999)")
				}
				n, err := strconv.Atoi(m[1])
				if err != nil || n <= 0 || n > 365 {
					return c.res(Fail, fmt.Sprintf("PASS_MAX_DAYS %s (want 1-365)", m[1]))
				}
				return c.res(Pass, "PASS_MAX_DAYS "+m[1])
			},
			func(context.Context, *fnCheck) (Diff, error) {
				s, ok := readFile("/etc/login.defs")
				if !ok {
					return Diff{}, fmt.Errorf("/etc/login.defs not found: install the login/shadow-utils package")
				}
				if m := passMaxRe.FindStringSubmatchIndex(s); m != nil {
					s = s[:m[0]] + "PASS_MAX_DAYS\t365" + s[m[1]:]
				} else {
					if s != "" && !strings.HasSuffix(s, "\n") {
						s += "\n"
					}
					s += "PASS_MAX_DAYS\t365\n"
				}
				return Diff{Files: []FileEdit{{Path: "/etc/login.defs", New: s, Mode: 0o644}},
					Note: "applies to new accounts; existing users keep their aging until `chage -M 365 <user>`"}, nil
			})
	})
}
