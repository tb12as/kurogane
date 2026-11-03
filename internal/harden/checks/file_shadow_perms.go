package checks

func init() {
	register(func(e *Env) Check {
		return modeCk(Meta{ID: "FILE-SHADOW-PERMS", Title: "/etc/shadow mode 640 or stricter", Severity: High,
			CIS:         "6.1.5",
			Rationale:   "/etc/shadow holds password hashes; readable copies allow offline cracking.",
			Remediation: "`chmod 640 /etc/shadow` (owner root, group shadow or root)."}, e, "/etc/shadow", 0o640)
	})
}
