package checks

import (
	"context"
	"fmt"
	"path"
	"strings"
)

// knownSUID are setuid binaries shipped by Ubuntu, Debian and RHEL base installs.
var knownSUID = map[string]bool{}

func init() {
	for _, n := range strings.Fields(`passwd chsh chfn gpasswd newgrp su sudo sudoedit mount umount pkexec fusermount
		fusermount3 chage expiry newuidmap newgidmap unix_chkpwd pam_timestamp_check userhelper mount.nfs mount.cifs
		ping ping6 traceroute6.iputils snap-confine dbus-daemon-launch-helper ssh-keysign polkit-agent-helper-1
		Xorg.wrap at crontab staprun grub2-set-bootflag sg vmware-user-suid-wrapper ntfs-3g chrome-sandbox
		lxc-user-nic gst-ptp-helper spice-client-glib-usb-acl-helper ksu firejail mount.ecryptfs_private
		umount.nfs cockpit-session usernetctl fusermount-glusterfs exim4 dmcrypt-get-device`) {
		knownSUID[n] = true
	}
	register(func(e *Env) Check {
		return fn(Meta{ID: "FILE-SUID-UNEXPECTED", Title: "No unexpected SUID binaries", Category: "files",
			Severity: Medium, CIS: "6.1.13",
			Rationale: "Unexpected setuid-root binaries are a classic privilege-escalation path and persistence trick.",
			Remediation: "Verify each binary's package (`dpkg -S` / `rpm -qf`); remove the SUID bit " +
				"(`chmod u-s <file>`) or the binary if it is not needed."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				w := sysWalk(ctx)
				if ctx.Err() != nil {
					return c.res(Error, "filesystem walk did not finish in the scan budget")
				}
				var bad []string
				for _, f := range w.SUID {
					if !knownSUID[path.Base(f.Path)] {
						bad = append(bad, f.Path)
					}
				}
				if len(bad) > 0 {
					return c.res(Fail, fmt.Sprintf("%d unexpected SUID binaries: %s", len(bad), short(bad, 20)))
				}
				return c.res(Pass, fmt.Sprintf("%d SUID binaries, all on the known-good list", len(w.SUID)))
			}, nil)
	})
}
