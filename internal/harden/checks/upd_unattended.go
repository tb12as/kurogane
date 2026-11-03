package checks

import (
	"context"
	"regexp"
)

var aptUnattended = regexp.MustCompile(`APT::Periodic::Unattended-Upgrade\s+"1"`)

const autoUpgrades = "/etc/apt/apt.conf.d/20auto-upgrades"

func unattendedOn(ctx context.Context, e *Env) (bool, string) {
	if distro(ctx).PkgMgr == "dnf" {
		if !pkgInstalled(ctx, e, "dnf-automatic") {
			return false, "dnf-automatic not installed"
		}
		if enabled(ctx, e, "dnf-automatic-install.timer") {
			return true, "dnf-automatic-install.timer enabled"
		}
		conf, _ := readFile("/etc/dnf/automatic.conf")
		if enabled(ctx, e, "dnf-automatic.timer") && regexp.MustCompile(`(?m)^\s*apply_updates\s*=\s*(yes|true|1)`).
			MatchString(conf) {
			return true, "dnf-automatic.timer enabled with apply_updates = yes"
		}
		return false, "no dnf-automatic timer applies updates"
	}
	if !pkgInstalled(ctx, e, "unattended-upgrades") {
		return false, "unattended-upgrades not installed"
	}
	for _, f := range dirFiles("/etc/apt/apt.conf.d") {
		if s, _ := readFile(f); aptUnattended.MatchString(s) {
			return true, "unattended-upgrades enabled in " + f
		}
	}
	return false, `unattended-upgrades installed but APT::Periodic::Unattended-Upgrade is not "1"`
}

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "UPD-UNATTENDED", Title: "Automatic security updates enabled", Category: "updates",
			Severity: High, CIS: "1.9",
			Rationale: "Most compromises exploit known vulnerabilities whose patches were available but not installed.",
			Remediation: "Debian/Ubuntu: `apt-get install unattended-upgrades` and enable it in " +
				"/etc/apt/apt.conf.d/20auto-upgrades. RHEL: `dnf install dnf-automatic` and " +
				"`systemctl enable --now dnf-automatic-install.timer`."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				if distro(ctx).PkgMgr == "" {
					return c.res(NA, "unsupported package manager")
				}
				if ok, ev := unattendedOn(ctx, c.e); ok {
					return c.res(Pass, ev)
				} else {
					return c.res(Fail, ev)
				}
			},
			func(ctx context.Context, c *fnCheck) (Diff, error) {
				if ok, _ := unattendedOn(ctx, c.e); ok {
					return Diff{}, nil
				}
				d := Diff{}
				if distro(ctx).PkgMgr == "dnf" {
					if !pkgInstalled(ctx, c.e, "dnf-automatic") {
						d.Cmds = append(d.Cmds, installCmd(ctx, "dnf-automatic"))
					}
					d.Cmds = append(d.Cmds, cmd("systemctl", "enable", "--now", "dnf-automatic-install.timer"))
					d.Undo = [][]string{cmd("systemctl", "disable", "--now", "dnf-automatic-install.timer")}
					return d, nil
				}
				if !pkgInstalled(ctx, c.e, "unattended-upgrades") {
					d.Cmds = append(d.Cmds, installCmd(ctx, "unattended-upgrades"))
				}
				d.Files = []FileEdit{{Path: autoUpgrades, Mode: 0o644,
					New: "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"}}
				return d, nil
			})
	})
}
