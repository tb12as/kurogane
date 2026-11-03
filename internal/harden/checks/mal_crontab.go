package checks

import (
	"context"
	"regexp"
	"strings"

	"github.com/tb12as/serverman/internal/hostfs"
)

var badCron = regexp.MustCompile(`(?i)((curl|wget)\b[^|#]*\|\s*(ba|da|z)?sh\b` +
	`|base64\s+(-d|--decode)[^|#]*\|\s*(ba|da|z)?sh\b` +
	`|/dev/(tcp|udp)/|xmrig|kinsing|kdevtmpfsi|minerd|cpuminer|xmr-stak|nbminer|stratum\+tcp)`)

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "MAL-CRONTAB", Title: "No known-bad crontab entries", Category: "malware", Severity: High,
			Rationale: "Download-and-execute pipes, reverse shells and miner names in cron are typical persistence " +
				"left by compromises.",
			Remediation: "Investigate the listed entries (they usually mean the host is compromised), remove them and " +
				"rotate credentials."}, e,
			func(_ context.Context, c *fnCheck) Result {
				files := append([]string{"/etc/crontab"}, dirFiles("/etc/cron.d")...)
				files = append(files, dirFiles("/var/spool/cron")...)
				files = append(files, dirFiles("/var/spool/cron/crontabs")...)
				var hits []string
				for _, f := range files {
					lines, _ := hostfs.Lines(f)
					for _, l := range lines {
						if t := strings.TrimSpace(l); t != "" && t[0] != '#' && badCron.MatchString(t) {
							hits = append(hits, f+": "+t)
						}
					}
				}
				if len(hits) > 0 {
					return c.res(Fail, strings.Join(hits, "; "))
				}
				return c.res(Pass, "no suspicious entries in /etc/crontab, /etc/cron.d, /var/spool/cron")
			}, nil)
	})
}
