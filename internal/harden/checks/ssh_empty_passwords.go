package checks

func init() {
	register(func(e *Env) Check {
		return sshEq(Meta{ID: "SSH-EMPTY-PASSWORDS", Title: "SSH empty passwords refused", Severity: Critical,
			CIS:         "5.2.9",
			Rationale:   "Accounts with empty passwords would be reachable over SSH without any credential.",
			Remediation: "Set `PermitEmptyPasswords no` in sshd_config."}, e, "permitemptypasswords", "no")
	})
}
