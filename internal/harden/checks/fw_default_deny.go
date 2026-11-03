package checks

import "context"

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "FW-DEFAULT-DENY", Title: "Firewall denies inbound traffic by default", Category: "firewall",
			Severity: High, CIS: "3.5.1.7", AutoFix: FixConfirm,
			Rationale: "A default-allow policy exposes every new service as soon as it starts listening.",
			Remediation: "Set the default inbound policy to deny (`ufw default deny incoming`, firewalld zone target " +
				"default/DROP, nftables input policy drop) after allowing needed ports."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				st, err := firewall(ctx, c.e)
				if err != nil {
					return c.res(Error, err.Error())
				}
				if st.Active && st.DefaultDeny {
					return c.res(Pass, st.Evidence)
				}
				return c.res(Fail, st.Evidence)
			},
			func(ctx context.Context, c *fnCheck) (Diff, error) {
				if st, err := firewall(ctx, c.e); err == nil && st.Active && st.DefaultDeny {
					return Diff{}, nil
				}
				return fwPlan(ctx, c.e, true)
			})
	})
}
