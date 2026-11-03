package checks

import (
	"context"
	"strings"

	"github.com/serverkeeper/serverkeeper/internal/hostfs"
)

func emptyPasswd() ([]string, error) {
	lines, err := hostfs.Lines("/etc/shadow")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range lines {
		f := strings.Split(l, ":")
		if len(f) > 1 && f[0] != "" && f[1] == "" {
			out = append(out, f[0])
		}
	}
	return out, nil
}

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "ACC-EMPTY-PASSWD", Title: "No accounts with empty passwords", Category: "accounts",
			Severity: Critical, CIS: "6.2.2",
			Rationale:   "An empty password lets anyone log in locally (or remotely where allowed) without a credential.",
			Remediation: "Lock the accounts (`passwd -l <user>`) or set a password (`passwd <user>`)."}, e,
			func(_ context.Context, c *fnCheck) Result {
				users, err := emptyPasswd()
				if err != nil {
					return c.res(Error, "cannot read /etc/shadow (run as root): "+err.Error())
				}
				if len(users) > 0 {
					return c.res(Fail, "accounts with empty password: "+strings.Join(users, ", "))
				}
				return c.res(Pass, "no empty password fields in /etc/shadow")
			},
			func(context.Context, *fnCheck) (Diff, error) {
				users, err := emptyPasswd()
				if err != nil {
					return Diff{}, err
				}
				d := Diff{}
				for _, u := range users {
					d.Cmds = append(d.Cmds, cmd("passwd", "-l", u))
				}
				if len(users) > 0 {
					d.Backup = []string{"/etc/shadow"}
				}
				return d, nil
			})
	})
}
