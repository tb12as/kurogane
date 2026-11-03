package checks

func init() {
	register(func(e *Env) Check {
		return sysctlCk(Meta{ID: "SYS-SOURCE-ROUTE", Title: "Source-routed packets rejected", Severity: Medium,
			CIS:         "3.3.1",
			Rationale:   "Source routing lets a sender choose the path, bypassing network controls.",
			Remediation: "Set `accept_source_route = 0` for all/default on IPv4 and IPv6 in /etc/sysctl.d."}, e,
			kv{"net.ipv4.conf.all.accept_source_route", "0"}, kv{"net.ipv4.conf.default.accept_source_route", "0"},
			kv{"net.ipv6.conf.all.accept_source_route", "0"}, kv{"net.ipv6.conf.default.accept_source_route", "0"})
	})
}
