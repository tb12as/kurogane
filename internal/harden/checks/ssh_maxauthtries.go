package checks

import (
	"fmt"
	"strconv"
)

func init() {
	register(func(e *Env) Check {
		c := sshEq(Meta{ID: "SSH-MAXAUTHTRIES", Title: "SSH MaxAuthTries 4 or less", Severity: Medium, CIS: "5.2.18",
			Rationale:   "Limiting authentication attempts per connection slows down brute-force attacks.",
			Remediation: "Set `MaxAuthTries 4` in sshd_config."}, e, "maxauthtries", "4")
		c.eval = func(m map[string]string) (bool, string) {
			n, err := strconv.Atoi(m["maxauthtries"])
			return err == nil && n > 0 && n <= 4, fmt.Sprintf("maxauthtries %s (want 1-4)", m["maxauthtries"])
		}
		return c
	})
}
