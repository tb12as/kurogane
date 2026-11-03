package checks

func init() {
	register(func(e *Env) Check {
		return sshEq(Meta{ID: "SSH-PASSWORD-AUTH", Title: "SSH password authentication disabled", Severity: High,
			Rationale: "Passwords can be brute-forced or reused; key-based authentication is not exposed to guessing.",
			Remediation: "Install SSH keys for every user, then set `PasswordAuthentication no` " +
				"(`serverkeeper harden fix SSH-PASSWORD-AUTH`)."}, e, "passwordauthentication", "no")
	})
}
