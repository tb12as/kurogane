package checks

import (
	"context"
	"fmt"
	"strings"
)

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "FW-EXPECTED-PORTS", Title: "Only expected ports listen publicly", Category: "firewall",
			Severity: Medium, CIS: "3.5.1.6",
			Rationale: "Every publicly reachable port is attack surface; unexpected ones are often forgotten services.",
			Remediation: "Stop or bind unexpected services to 127.0.0.1, block them in the firewall, or add them to " +
				"`harden.expected_ports` in config.yaml."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				ports := publicPorts(ctx, c.e)
				if len(ports) == 0 {
					return c.res(Pass, "no public listeners")
				}
				ok := map[int]bool{sshPort(ctx, c.e): true}
				for _, p := range c.e.ExpectedPorts {
					ok[p] = true
				}
				var bad []string
				for _, k := range sortedPorts(ports) {
					var n int
					fmt.Sscanf(k, "%d", &n)
					if !ok[n] {
						bad = append(bad, strings.TrimSpace(k+" "+ports[k]))
					}
				}
				if len(bad) > 0 {
					return c.res(Fail, "unexpected public listeners: "+strings.Join(bad, ", "))
				}
				return c.res(Pass, "public listeners: "+strings.Join(sortedPorts(ports), ", "))
			}, nil)
	})
}
