package checks

import (
	"context"
	"strings"
)

// ntpState returns (synced, ntp enabled, evidence, err).
func ntpState(ctx context.Context, e *Env) (bool, bool, string, error) {
	out, err := e.Ex.Run(ctx, "timedatectl", "show")
	if err == nil && len(out) > 0 {
		kv := grepKV(string(out), "NTP", "NTPSynchronized")
		return contains(kv, "NTPSynchronized=yes"), contains(kv, "NTP=yes"), "timedatectl: " + strings.Join(kv, ", "), nil
	}
	out, err2 := e.Ex.Run(ctx, "chronyc", "tracking")
	if err2 == nil && len(out) > 0 {
		leap := grepPrefix(string(out), "Leap status")
		return strings.HasSuffix(leap, "Normal"), true, "chronyc tracking: " + leap, nil
	}
	if err == nil {
		err = err2
	}
	return false, false, "", err
}

func grepPrefix(s, p string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, p) {
			return strings.Join(strings.Fields(l), " ")
		}
	}
	return ""
}

func grepKV(s string, keys ...string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		k, _, _ := strings.Cut(l, "=")
		if contains(keys, k) {
			out = append(out, l)
		}
	}
	return out
}

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "TIME-NTP-SYNC", Title: "System clock synchronised (NTP)", Category: "time",
			Severity: Medium, CIS: "2.1.1.1",
			Rationale: "Accurate time is required for log correlation, TLS, TOTP and Kerberos.",
			Remediation: "`timedatectl set-ntp true` (systemd-timesyncd) or enable chronyd " +
				"(`systemctl enable --now chronyd`)."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				ok, _, ev, err := ntpState(ctx, c.e)
				switch {
				case err != nil && ev == "":
					return c.res(Error, "neither timedatectl nor chronyc answered: "+err.Error())
				case ev == "":
					return c.res(Error, "no output from timedatectl or chronyc")
				case ok:
					return c.res(Pass, ev)
				}
				return c.res(Fail, ev)
			},
			func(ctx context.Context, c *fnCheck) (Diff, error) {
				ok, on, _, _ := ntpState(ctx, c.e)
				if ok || on {
					return Diff{Note: "NTP already enabled; waiting for the first sync"}, nil
				}
				return Diff{Cmds: [][]string{cmd("timedatectl", "set-ntp", "true")},
					Undo: [][]string{cmd("timedatectl", "set-ntp", "false")}}, nil
			})
	})
}
