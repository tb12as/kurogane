package checks

import (
	"context"
	"fmt"
	"strings"
)

var (
	insecureUnits = []string{"telnet.socket", "inetd", "xinetd", "vsftpd", "proftpd", "pure-ftpd", "tftpd-hpa",
		"tftp.socket", "rsh.socket", "rlogin.socket", "rexec.socket"}
	insecurePorts = map[string]string{"21/tcp": "ftp", "23/tcp": "telnet", "69/udp": "tftp", "512/tcp": "rexec",
		"513/tcp": "rlogin", "514/tcp": "rsh"}
)

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "SVC-INSECURE", Title: "No telnet, rsh, rlogin, FTP or TFTP services", Category: "services",
			Severity: High, CIS: "2.2",
			Rationale: "These protocols send credentials and data in clear text.",
			Remediation: "Stop and remove them (`systemctl disable --now <unit>`, then purge the package); use SSH " +
				"and SFTP instead."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				var bad []string
				st := unitStates(ctx, c.e, insecureUnits...)
				for _, u := range insecureUnits {
					if st[u] == "active" {
						bad = append(bad, "unit "+u)
					}
				}
				for _, l := range listeners(ctx, c.e) {
					if n, ok := insecurePorts[fmt.Sprintf("%d/%s", l.Port, l.Proto)]; ok {
						bad = append(bad, fmt.Sprintf("%s listening on %s:%d", n, l.Addr, l.Port))
					}
				}
				if len(bad) > 0 {
					return c.res(Fail, strings.Join(bad, "; "))
				}
				return c.res(Pass, "no clear-text remote access or file transfer services")
			}, nil)
	})
}
