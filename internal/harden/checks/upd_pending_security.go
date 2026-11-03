package checks

import (
	"context"
	"fmt"
	"strings"
)

// pendingSecurity lists packages with pending security updates (simulation only, no network refresh).
func pendingSecurity(ctx context.Context, e *Env) ([]string, error) {
	if distro(ctx).PkgMgr == "dnf" {
		out, err := e.Ex.Run(ctx, "dnf", "-q", "--cacheonly", "updateinfo", "list", "--security")
		if err != nil {
			return nil, err
		}
		var pk []string
		for _, l := range strings.Split(string(out), "\n") {
			if f := strings.Fields(l); len(f) >= 3 {
				pk = append(pk, f[2])
			}
		}
		return pk, nil
	}
	out, err := e.Ex.Run(ctx, "apt-get", "-s", "upgrade")
	if err != nil {
		return nil, err
	}
	var pk []string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "Inst ") && strings.Contains(l, "-security") {
			pk = append(pk, strings.Fields(l)[1])
		}
	}
	return pk, nil
}

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "UPD-PENDING-SECURITY", Title: "No pending security updates", Category: "updates",
			Severity: High, CIS: "1.9",
			Rationale:   "Pending security updates are known, published vulnerabilities on this host.",
			Remediation: "Install them: `apt-get upgrade` (Debian/Ubuntu) or `dnf upgrade --security` (RHEL)."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				if distro(ctx).PkgMgr == "" {
					return c.res(NA, "unsupported package manager")
				}
				pk, err := pendingSecurity(ctx, c.e)
				if err != nil {
					return c.res(Error, "cannot list updates: "+err.Error())
				}
				if len(pk) > 0 {
					return c.res(Fail, fmt.Sprintf("%d pending security updates: %s", len(pk), short(pk, 10)))
				}
				return c.res(Pass, "no pending security updates (from the local package cache)")
			},
			func(ctx context.Context, c *fnCheck) (Diff, error) {
				pk, err := pendingSecurity(ctx, c.e)
				if err != nil || len(pk) == 0 {
					return Diff{}, err
				}
				d := Diff{Note: "package upgrades cannot be reverted by `harden revert`"}
				if distro(ctx).PkgMgr == "dnf" {
					d.Cmds = [][]string{cmd("dnf", "-y", "upgrade", "--security")}
				} else {
					d.Cmds = [][]string{append(cmd("apt-get", "install", "-y", "--only-upgrade"), pk...)}
				}
				return d, nil
			})
	})
}

func short(xs []string, n int) string {
	if len(xs) <= n {
		return strings.Join(xs, ", ")
	}
	return strings.Join(xs[:n], ", ") + fmt.Sprintf(" and %d more", len(xs)-n)
}
