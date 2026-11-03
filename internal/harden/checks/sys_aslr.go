package checks

func init() {
	register(func(e *Env) Check {
		return sysctlCk(Meta{ID: "SYS-ASLR", Title: "Full address space layout randomisation", Severity: High,
			CIS:         "1.5.2",
			Rationale:   "ASLR makes memory-corruption exploits much harder to write reliably.",
			Remediation: "Set `kernel.randomize_va_space = 2` in /etc/sysctl.d."}, e, kv{"kernel.randomize_va_space", "2"})
	})
}
