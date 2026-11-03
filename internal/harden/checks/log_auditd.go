package checks

import "context"

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "LOG-AUDITD", Title: "auditd installed and running", Category: "logging", Severity: Medium,
			CIS:       "4.1.1.1",
			Rationale: "The kernel audit log records privileged actions and file changes for incident response.",
			Remediation: "Install auditd (`apt-get install auditd` / `dnf install audit`) and " +
				"`systemctl enable --now auditd`."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				if !hasBin("auditd") {
					return c.res(Fail, "auditd not installed")
				}
				if !active(ctx, c.e, "auditd") {
					return c.res(Fail, "auditd installed but not active")
				}
				return c.res(Pass, "auditd active")
			},
			func(ctx context.Context, c *fnCheck) (Diff, error) {
				d := Diff{}
				if !hasBin("auditd") {
					pkg := "auditd"
					if distro(ctx).PkgMgr == "dnf" {
						pkg = "audit"
					}
					d.Cmds = append(d.Cmds, installCmd(ctx, pkg))
				} else if active(ctx, c.e, "auditd") {
					return d, nil
				}
				d.Cmds = append(d.Cmds, cmd("systemctl", "enable", "auditd"), cmd("systemctl", "start", "auditd"))
				d.Undo = [][]string{cmd("systemctl", "stop", "auditd"), cmd("systemctl", "disable", "auditd")}
				d.Note = "the auditd package stays installed after a revert"
				return d, nil
			})
	})
}
