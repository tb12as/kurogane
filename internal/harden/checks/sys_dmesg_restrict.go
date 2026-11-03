package checks

func init() {
	register(func(e *Env) Check {
		return sysctlCk(Meta{ID: "SYS-DMESG-RESTRICT", Title: "Kernel log restricted to root", Severity: Low,
			Rationale:   "The kernel log exposes addresses and hardware details useful to local exploits.",
			Remediation: "Set `kernel.dmesg_restrict = 1` in /etc/sysctl.d."}, e, kv{"kernel.dmesg_restrict", "1"})
	})
}
