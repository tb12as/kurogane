package checks

func init() {
	register(func(e *Env) Check {
		return sysctlCk(Meta{ID: "SYS-RP-FILTER", Title: "Reverse path filtering enabled", Severity: Medium,
			CIS:         "3.3.7",
			Rationale:   "Reverse path filtering drops spoofed packets whose source could not be routed back.",
			Remediation: "Set `net.ipv4.conf.all.rp_filter = 1` and `net.ipv4.conf.default.rp_filter = 1`."}, e,
			kv{"net.ipv4.conf.all.rp_filter", "1"}, kv{"net.ipv4.conf.default.rp_filter", "1"})
	})
}
