package checks

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/tb12as/serverman/internal/executor"
	"github.com/tb12as/serverman/internal/webconf"
)

// webConfigs parses nginx and Apache once per scan.
func webConfigs(ctx context.Context, e *Env) []*webconf.Config {
	cs, _ := memo(ctx, "webconf", func() ([]*webconf.Config, error) {
		var out []*webconf.Config
		if e.WebOff || e.Ex == nil {
			return nil, nil
		}
		for _, c := range []*webconf.Config{webconf.ParseNginx(e.Ex), webconf.ParseApache(e.Ex)} {
			if c != nil {
				out = append(out, c)
			}
		}
		return out, nil
	})
	return cs
}

const noWeb = "no nginx or Apache configuration found"

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "WEB-CONFIG-VALID", Title: "Web server configuration passes its own test", Category: "web",
			Severity: High,
			Rationale: "A configuration that fails `nginx -t` or `apachectl configtest` keeps running until the next " +
				"reload or reboot, which then fails and takes every site down.",
			Remediation: "Run the test shown in the evidence and fix the file and line it names."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				cs := webConfigs(ctx, c.e)
				if len(cs) == 0 {
					return c.res(NA, noWeb)
				}
				var bad, good []string
				for _, w := range cs {
					cmd, args := "nginx", []string{"-t"}
					if w.Server == webconf.Apache {
						cmd, args = "apachectl", []string{"configtest"}
					}
					if _, err := c.e.Ex.Run(ctx, cmd, args...); err != nil {
						msg := err.Error()
						var re *executor.RunError
						if errors.As(err, &re) && re.Stderr != "" {
							msg = strings.ReplaceAll(strings.TrimSpace(re.Stderr), "\n", "; ")
						}
						bad = append(bad, cmd+" "+strings.Join(args, " ")+": "+msg)
						continue
					}
					good = append(good, cmd+" "+strings.Join(args, " ")+" ok")
				}
				if len(bad) > 0 {
					return c.res(Fail, strings.Join(bad, "; "))
				}
				return c.res(Pass, strings.Join(good, "; "))
			}, nil)
	})

	register(func(e *Env) Check {
		return fn(Meta{ID: "WEB-SERVER-TOKENS", Title: "Web servers hide their version", Category: "web", Severity: Low,
			Rationale: "Version numbers in headers and error pages tell scanners which known vulnerabilities to try.",
			Remediation: "nginx: `server_tokens off;` in the http block. Apache: `ServerTokens Prod` and " +
				"`ServerSignature Off` (Debian: /etc/apache2/conf-enabled/security.conf)."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				cs := webConfigs(ctx, c.e)
				if len(cs) == 0 {
					return c.res(NA, noWeb)
				}
				var bad, good []string
				for _, w := range cs {
					if w.Server == webconf.Nginx {
						off := false
						for _, d := range w.Find("server_tokens") {
							if len(d.Args) == 0 {
								continue
							}
							if d.Args[0] != "off" {
								bad = append(bad, fmt.Sprintf("nginx: server_tokens %s at %s", d.Args[0], d.Where()))
							} else if d.Ctx == "http" {
								off = true
							}
						}
						if !off {
							bad = append(bad, "nginx: no `server_tokens off;` in the http block (default: on)")
						} else {
							good = append(good, "nginx: server_tokens off")
						}
						continue
					}
					tokens := "Full (default)"
					for _, d := range w.Find("servertokens") {
						if d.Block == 0 && len(d.Args) > 0 {
							tokens = d.Args[0] + " at " + d.Where()
						}
					}
					if t := strings.ToLower(strings.Fields(tokens)[0]); t != "prod" && t != "productonly" {
						bad = append(bad, "Apache: ServerTokens "+tokens)
					}
					for _, d := range w.Find("serversignature") {
						if len(d.Args) > 0 && !strings.EqualFold(d.Args[0], "off") {
							bad = append(bad, fmt.Sprintf("Apache: ServerSignature %s at %s", d.Args[0], d.Where()))
						}
					}
					if len(bad) == 0 {
						good = append(good, "Apache: ServerTokens "+tokens)
					}
				}
				if len(bad) > 0 {
					return c.res(Fail, strings.Join(bad, "; "))
				}
				return c.res(Pass, strings.Join(good, "; "))
			}, nil)
	})

	register(func(e *Env) Check {
		return fn(Meta{ID: "WEB-TLS-PROTOCOLS", Title: "Web servers allow TLS 1.2 and later only", Category: "web",
			Severity: Medium,
			Rationale: "SSLv3, TLS 1.0 and TLS 1.1 have known weaknesses and are rejected by current browsers. Many " +
				"distributions already block them in OpenSSL, but the web server configuration should not ask for them.",
			Remediation: "nginx: `ssl_protocols TLSv1.2 TLSv1.3;`. Apache: `SSLProtocol -all +TLSv1.2 +TLSv1.3`."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				cs := webConfigs(ctx, c.e)
				if len(cs) == 0 {
					return c.res(NA, noWeb)
				}
				var bad []string
				n := 0
				for _, w := range cs {
					for _, d := range append(w.Find("ssl_protocols"), w.Find("sslprotocol")...) {
						n++
						if weak := weakProtocols(d.Name, d.Args); len(weak) > 0 {
							bad = append(bad, fmt.Sprintf("%s allows %s at %s", d.Name, strings.Join(weak, ", "), d.Where()))
						}
					}
				}
				if len(bad) > 0 {
					return c.res(Fail, strings.Join(bad, "; "))
				}
				if n == 0 {
					return c.res(Pass, "no protocol directives: server defaults apply (TLS 1.2+ on nginx 1.23.4+, "+
						"OpenSSL policy on Apache)")
				}
				return c.res(Pass, fmt.Sprintf("%d protocol directive(s), none allow SSLv3, TLS 1.0 or TLS 1.1", n))
			}, nil)
	})

	register(func(e *Env) Check {
		return fn(Meta{ID: "WEB-DIR-LISTING", Title: "No automatic directory listings", Category: "web", Severity: Medium,
			Rationale: "Directory listings expose backups, configuration and other files nobody linked to.",
			Remediation: "nginx: remove `autoindex on`. Apache: use `Options -Indexes` (Debian's default " +
				"/etc/apache2/apache2.conf enables Indexes for /var/www). Ignore this check if a listing is intended."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				cs := webConfigs(ctx, c.e)
				if len(cs) == 0 {
					return c.res(NA, noWeb)
				}
				var bad []string
				for _, w := range cs {
					for _, d := range w.Find("autoindex") {
						if len(d.Args) > 0 && d.Args[0] == "on" {
							bad = append(bad, "autoindex on at "+d.Where())
						}
					}
					for _, d := range w.Find("options") {
						if slices.ContainsFunc(d.Args, func(a string) bool { return strings.EqualFold(strings.TrimPrefix(a, "+"), "Indexes") }) {
							bad = append(bad, "Options "+strings.Join(d.Args, " ")+" at "+d.Where())
						}
					}
				}
				if len(bad) > 0 {
					return c.res(Fail, strings.Join(bad, "; "))
				}
				return c.res(Pass, "no autoindex or Options Indexes")
			}, nil)
	})
}

// weakProtocols evaluates an nginx ssl_protocols or Apache SSLProtocol value and returns the weak protocols
// it enables.
func weakProtocols(name string, args []string) []string {
	on := map[string]bool{}
	for _, a := range args {
		a = strings.ToLower(a)
		if name == "ssl_protocols" {
			on[a] = true
			continue
		}
		set := true
		switch {
		case strings.HasPrefix(a, "-"):
			set, a = false, a[1:]
		case strings.HasPrefix(a, "+"):
			a = a[1:]
		}
		if a == "all" {
			for _, p := range []string{"tlsv1", "tlsv1.1", "tlsv1.2", "tlsv1.3"} {
				on[p] = set
			}
			continue
		}
		on[a] = set
	}
	var out []string
	for _, p := range []struct{ key, label string }{{"sslv2", "SSLv2"}, {"sslv3", "SSLv3"}, {"tlsv1", "TLSv1"},
		{"tlsv1.1", "TLSv1.1"}} {
		if on[p.key] {
			out = append(out, p.label)
		}
	}
	return out
}
