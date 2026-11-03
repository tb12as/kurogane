package checks

import "fmt"

func init() {
	register(func(e *Env) Check {
		c := sshEq(Meta{ID: "SSH-CLIENTALIVE", Title: "SSH idle sessions time out", Severity: Low, CIS: "5.2.22",
			Rationale:   "Idle sessions left open can be hijacked from an unattended terminal.",
			Remediation: "Set `ClientAliveInterval 300` and `ClientAliveCountMax 3` in sshd_config."},
			e, "clientaliveinterval", "300")
		c.eval = func(m map[string]string) (bool, string) {
			i, n := sshSeconds(m["clientaliveinterval"]), sshSeconds(m["clientalivecountmax"])
			return i > 0 && i <= 900 && n > 0, fmt.Sprintf("clientaliveinterval %s, clientalivecountmax %s "+
				"(want interval 1-900, countmax > 0)", m["clientaliveinterval"], m["clientalivecountmax"])
		}
		c.plan = func(m map[string]string) map[string]string {
			return map[string]string{"ClientAliveInterval": "300", "ClientAliveCountMax": "3"}
		}
		return c
	})
}
