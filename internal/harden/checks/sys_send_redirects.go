package checks

func init() {
	register(func(e *Env) Check {
		return sysctlCk(Meta{ID: "SYS-SEND-REDIRECTS", Title: "ICMP redirects not sent", Severity: Medium,
			CIS:         "3.2.1",
			Rationale:   "Only routers need to send redirects; a host sending them can be abused to misroute traffic.",
			Remediation: "Set `net.ipv4.conf.all.send_redirects = 0` and `net.ipv4.conf.default.send_redirects = 0`."},
			e, kv{"net.ipv4.conf.all.send_redirects", "0"}, kv{"net.ipv4.conf.default.send_redirects", "0"})
	})
}
