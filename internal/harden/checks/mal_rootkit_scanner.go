package checks

import "context"

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "MAL-ROOTKIT-SCANNER", Title: "Rootkit scanner installed", Category: "malware",
			Severity:  Low,
			Rationale: "rkhunter or chkrootkit detect common rootkits and tampered system binaries.",
			Remediation: "Install rkhunter (`apt-get install rkhunter` / `dnf install rkhunter` from EPEL) and run it " +
				"from cron."}, e,
			func(_ context.Context, c *fnCheck) Result {
				for _, b := range []string{"rkhunter", "chkrootkit"} {
					if hasBin(b) {
						return c.res(Pass, b+" installed")
					}
				}
				return c.res(Fail, "neither rkhunter nor chkrootkit installed")
			}, nil)
	})
}
