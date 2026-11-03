package checks

func init() {
	register(func(e *Env) Check {
		return sysctlCk(Meta{ID: "SYS-SYNCOOKIES", Title: "TCP SYN cookies enabled", Severity: Medium, CIS: "3.3.8",
			Rationale:   "SYN cookies keep the host accepting connections during a SYN flood.",
			Remediation: "Set `net.ipv4.tcp_syncookies = 1` in /etc/sysctl.d."}, e, kv{"net.ipv4.tcp_syncookies", "1"})
	})
}
