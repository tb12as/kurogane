package checks

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/tb12as/serverman/internal/certs"
)

// certMinDays is the expiry horizon below which the check fails; the cert_expiring alert warns earlier.
const certMinDays = 7

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "TLS-CERT-VALID", Title: "TLS certificates valid, strong and served", Category: "tls",
			Severity: High,
			Rationale: "An expired or mismatched certificate takes a site offline for every visitor, and weak keys " +
				"or SHA-1 signatures are rejected by current browsers.",
			Remediation: "Renew certificates before they expire (check `certbot renew --dry-run`), reload the web " +
				"server after renewal, reissue RSA keys under 2048 bits or SHA-1 signed certificates, and make each " +
				"certificate cover every nginx server_name that uses it."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				if c.e.CertsOff {
					return c.res(NA, "certificate monitoring disabled (collector.certs.enabled: false)")
				}
				list := certs.Scan(ctx, c.e.Ex, c.e.Certs)
				if len(list) == 0 {
					return c.res(NA, "no TLS certificates found (Let's Encrypt, nginx ssl_certificate, "+
						"collector.certs.paths)")
				}
				return certResult(c, list)
			}, nil)
	})
}

func certResult(c *fnCheck, list []certs.Cert) Result {
	var bad, errs []string
	next, nextDays := "", math.Inf(1)
	for _, x := range list {
		if x.Error != "" {
			errs = append(errs, fmt.Sprintf("%s: %s", x.Name, x.Error))
			continue
		}
		var why []string
		switch {
		case x.DaysLeft < 0:
			why = append(why, fmt.Sprintf("expired %s", x.NotAfter.Format("2006-01-02")))
		case x.DaysLeft < certMinDays:
			why = append(why, fmt.Sprintf("expires in %.1f days", x.DaysLeft))
		}
		if w := x.Weak(); w != "" {
			why = append(why, w)
		}
		if x.Stale {
			why = append(why, fmt.Sprintf("port %d still serves the previous certificate (until %s)", x.ServedPort,
				x.ServedNotAfter.Format("2006-01-02")))
		}
		for _, sn := range x.ServerNames {
			if sn == "" || sn == "_" || strings.ContainsAny(sn, "~$*") || strings.HasPrefix(sn, ".") {
				continue // catch-all, regex and wildcard names cannot be checked against SANs reliably
			}
			if !x.Covers(sn) {
				why = append(why, "does not cover server_name "+sn)
			}
		}
		if len(why) > 0 {
			bad = append(bad, x.Name+": "+strings.Join(why, ", "))
		}
		if x.DaysLeft < nextDays {
			next, nextDays = x.Name, x.DaysLeft
		}
	}
	if len(bad) > 0 {
		return c.res(Fail, strings.Join(append(bad, errs...), "; "))
	}
	if len(errs) > 0 {
		return c.res(Error, strings.Join(errs, "; "))
	}
	return c.res(Pass, fmt.Sprintf("%d certificate(s) valid; next expiry %s in %.0f days", len(list), next, nextDays))
}
