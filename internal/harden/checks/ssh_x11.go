package checks

func init() {
	register(func(e *Env) Check {
		return sshEq(Meta{ID: "SSH-X11", Title: "SSH X11 forwarding disabled", Severity: Low, CIS: "5.2.12",
			Rationale:   "X11 forwarding exposes the client's display to a compromised server and is rarely needed.",
			Remediation: "Set `X11Forwarding no` in sshd_config."}, e, "x11forwarding", "no")
	})
}
