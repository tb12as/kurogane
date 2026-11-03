package checks

import "context"

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "FW-ACTIVE", Title: "Host firewall active", Category: "firewall", Severity: High,
			CIS: "3.5.1.3", AutoFix: FixConfirm,
			Rationale: "Without a host firewall every service that binds a public address is reachable.",
			Remediation: "Enable ufw (Debian/Ubuntu) or firewalld (RHEL) after allowing the ports you need; " +
				"`serverkeeper harden fix FW-ACTIVE` keeps every listening port and SSH open."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				st, err := firewall(ctx, c.e)
				if err != nil {
					return c.res(Error, err.Error())
				}
				if st.Active {
					return c.res(Pass, st.Evidence)
				}
				return c.res(Fail, st.Evidence)
			},
			func(ctx context.Context, c *fnCheck) (Diff, error) {
				if st, err := firewall(ctx, c.e); err == nil && st.Active {
					return Diff{}, nil
				}
				return fwPlan(ctx, c.e, false)
			})
	})
}
