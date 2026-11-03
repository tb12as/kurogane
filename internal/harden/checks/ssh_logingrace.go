package checks

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func init() {
	register(func(e *Env) Check {
		c := sshEq(Meta{ID: "SSH-LOGINGRACE", Title: "SSH LoginGraceTime 60 s or less", Severity: Low, CIS: "5.2.21",
			Rationale:   "A long grace time lets unauthenticated connections hold sshd slots (connection exhaustion).",
			Remediation: "Set `LoginGraceTime 60` in sshd_config."}, e, "logingracetime", "60")
		c.eval = func(m map[string]string) (bool, string) {
			s := sshSeconds(m["logingracetime"])
			return s > 0 && s <= 60, fmt.Sprintf("logingracetime %s (want 1-60 s)", m["logingracetime"])
		}
		return c
	})
}

// sshSeconds parses sshd time values ("120", "2m", "1m30s"); -1 if invalid.
func sshSeconds(v string) int {
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	d, err := time.ParseDuration(strings.ToLower(v))
	if err != nil {
		return -1
	}
	return int(d.Seconds())
}
