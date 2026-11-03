package checks

func init() {
	register(func(e *Env) Check {
		return sysctlCk(Meta{ID: "SYS-SUID-DUMPABLE", Title: "SUID programs do not dump core", Severity: Medium,
			CIS:         "1.5.4",
			Rationale:   "Core dumps of privileged programs can leak secrets such as password hashes.",
			Remediation: "Set `fs.suid_dumpable = 0` in /etc/sysctl.d."}, e, kv{"fs.suid_dumpable", "0"})
	})
}
