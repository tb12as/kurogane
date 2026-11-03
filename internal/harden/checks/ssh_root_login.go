package checks

func init() {
	register(func(e *Env) Check {
		return sshEq(Meta{ID: "SSH-ROOT-LOGIN", Title: "SSH root login disabled", Severity: High, CIS: "5.2.7",
			Rationale: "Direct root login removes accountability and gives attackers a known account to target.",
			Remediation: "Set `PermitRootLogin no` in sshd_config and log in as a regular user with sudo " +
				"(`serverkeeper harden fix SSH-ROOT-LOGIN`)."}, e, "permitrootlogin", "no")
	})
}
