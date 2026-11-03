package checks

import (
	"context"
	"fmt"
	"strings"
)

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "SVC-LISTENING-REVIEW", Title: "Listening services reviewed", Category: "services",
			Severity: Low, CIS: "2.4",
			Rationale:   "Knowing every listening service is the basis of attack-surface reduction.",
			Remediation: "Review the evidence; stop services you do not need or bind them to 127.0.0.1."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				ls := listeners(ctx, c.e)
				if len(ls) == 0 {
					return c.res(NA, "no listener data (collector not running and `ss` unavailable)")
				}
				seen := map[string]bool{}
				var out []string
				for _, l := range ls {
					s := fmt.Sprintf("%s %s:%d %s", l.Proto, l.Addr, l.Port, l.Process)
					if !seen[s] {
						seen[s] = true
						out = append(out, strings.TrimSpace(s))
					}
				}
				return c.res(Pass, "listening: "+strings.Join(out, "; "))
			}, nil)
	})
}
