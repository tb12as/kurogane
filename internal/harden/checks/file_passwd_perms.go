package checks

func init() {
	register(func(e *Env) Check {
		return modeCk(Meta{ID: "FILE-PASSWD-PERMS", Title: "/etc/passwd mode 644 or stricter", Severity: Medium,
			CIS:         "6.1.1",
			Rationale:   "A writable /etc/passwd lets users change UIDs or add accounts.",
			Remediation: "`chmod 644 /etc/passwd`."}, e, "/etc/passwd", 0o644)
	})
}
