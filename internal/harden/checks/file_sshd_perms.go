package checks

func init() {
	register(func(e *Env) Check {
		return modeCk(Meta{ID: "FILE-SSHD-PERMS", Title: "sshd_config mode 600", Severity: Medium, CIS: "5.2.1",
			Rationale:   "sshd_config controls remote access and should only be readable and writable by root.",
			Remediation: "`chmod 600 /etc/ssh/sshd_config`."}, e, "/etc/ssh/sshd_config", 0o600)
	})
}
