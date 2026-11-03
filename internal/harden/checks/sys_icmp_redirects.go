package checks

func init() {
	register(func(e *Env) Check {
		return sysctlCk(Meta{ID: "SYS-ICMP-REDIRECTS", Title: "ICMP redirects not accepted", Severity: Medium,
			CIS:         "3.3.2",
			Rationale:   "Accepting ICMP redirects lets an attacker on the network reroute this host's traffic.",
			Remediation: "Set `accept_redirects = 0` for all/default on IPv4 and IPv6 in /etc/sysctl.d."}, e,
			kv{"net.ipv4.conf.all.accept_redirects", "0"}, kv{"net.ipv4.conf.default.accept_redirects", "0"},
			kv{"net.ipv6.conf.all.accept_redirects", "0"}, kv{"net.ipv6.conf.default.accept_redirects", "0"})
	})
}
