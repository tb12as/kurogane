package checks

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/tb12as/kurogane/internal/collector"
	"github.com/tb12as/kurogane/internal/redisinfo"
)

// redisConf is one parsed instance with what the checks need.
type redisConf struct {
	redisinfo.Config
	auth     bool     // a password is needed to run commands
	authWhy  string   // how, for the evidence
	exposed  []string // non-loopback addresses it listens on
	acl      []string // ACL user lines (inline and aclfile), passwords masked
	readErrs []string
}

func redisConfs(ctx context.Context, e *Env) []redisConf {
	out, _ := memo(ctx, "redis", func() ([]redisConf, error) {
		var out []redisConf
		for _, f := range collector.RedisConfFiles(ctx, e.Ex) {
			c, err := redisinfo.ParseConfig(e.Ex, f)
			if err != nil {
				continue
			}
			rc := redisConf{Config: c, acl: c.Users}
			if c.ACLFile != "" {
				if b, err := e.Ex.ReadFile(c.ACLFile); err == nil {
					for _, l := range strings.Split(string(b), "\n") {
						if f := strings.Fields(l); len(f) > 1 && f[0] == "user" {
							rc.acl = append(rc.acl, maskACL(f[1:]))
						}
					}
				} else {
					rc.readErrs = append(rc.readErrs, "aclfile "+c.ACLFile+": "+err.Error())
				}
			}
			rc.auth, rc.authWhy = redisAuth(rc)
			rc.exposed = redisExposed(e, rc.Config)
			out = append(out, rc)
		}
		return out, nil
	})
	return out
}

func maskACL(v []string) string {
	for i, a := range v {
		if strings.HasPrefix(a, ">") || strings.HasPrefix(a, "#") {
			v[i] = a[:1] + "***"
		}
	}
	return strings.Join(v, " ")
}

// redisAuth reports whether commands need a password: requirepass, or an ACL default user that is off or has a
// password.
func redisAuth(c redisConf) (bool, string) {
	for _, u := range c.acl {
		f := strings.Fields(u)
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		rules := " " + strings.Join(f[1:], " ") + " "
		switch {
		case strings.Contains(rules, " off "):
			return true, "ACL default user is off"
		case strings.Contains(rules, " nopass "):
			return false, "ACL default user has nopass"
		case strings.Contains(rules, ">***") || strings.Contains(rules, "#***"):
			return true, "ACL default user has a password"
		}
	}
	if c.HasPassword {
		return true, "requirepass is set"
	}
	return false, "no requirepass and no ACL default user password"
}

// redisExposed lists non-loopback addresses the instance listens on: from the live listening sockets when the
// collector has them, else from bind.
func redisExposed(e *Env, c redisinfo.Config) []string {
	var out []string
	if e.Latest != nil {
		if s := e.Latest(); s != nil {
			for _, l := range s.Conns.Listening {
				if (l.Port == c.Port || (c.TLSPort > 0 && l.Port == c.TLSPort)) && l.Port > 0 && !loopbackAddr(l.Addr) {
					out = append(out, net.JoinHostPort(l.Addr, strconv.Itoa(l.Port)))
				}
			}
			return out
		}
	}
	if c.Port == 0 && c.TLSPort == 0 {
		return nil
	}
	if len(c.Bind) == 0 {
		return []string{"* (no bind directive)"}
	}
	for _, b := range c.Bind {
		if !loopbackAddr(strings.TrimPrefix(b, "-")) {
			out = append(out, b)
		}
	}
	return out
}

func loopbackAddr(a string) bool {
	ip := net.ParseIP(strings.Trim(a, "[]"))
	return ip != nil && ip.IsLoopback()
}

func where(c redisConf, key string) string {
	if n := c.Lines[key]; n > 0 {
		return fmt.Sprintf("%s:%d", c.File, n)
	}
	return c.File
}

const noRedis = "no Redis configuration found (/etc/redis/redis*.conf, /etc/redis.conf)"

func init() {
	register(func(e *Env) Check {
		return fn(Meta{ID: "REDIS-NOT-EXPOSED", Title: "Redis is not reachable from the network without a password",
			Category: "redis", Severity: Critical,
			Rationale: "Internet scanners find open Redis ports within minutes; without a password anyone can read " +
				"the data, wipe it, or use CONFIG SET to write files and take over the host (a common cryptominer path).",
			Remediation: "Keep `bind 127.0.0.1 -::1` unless other hosts need Redis; otherwise set a password " +
				"(requirepass or ACL users), keep protected-mode yes and firewall the port to the app servers only."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				cs := redisConfs(ctx, c.e)
				if len(cs) == 0 {
					return c.res(NA, noRedis)
				}
				var bad, good []string
				for _, r := range cs {
					switch {
					case len(r.exposed) > 0 && !r.auth:
						bad = append(bad, fmt.Sprintf("%s listens on %s with no password (%s)", r.File,
							strings.Join(r.exposed, ", "), r.authWhy))
					case len(r.exposed) > 0:
						good = append(good, fmt.Sprintf("%s listens on %s, %s: firewall the port", r.File,
							strings.Join(r.exposed, ", "), r.authWhy))
					default:
						good = append(good, r.File+" listens on loopback only")
					}
				}
				if len(bad) > 0 {
					return c.res(Fail, strings.Join(bad, "; "))
				}
				return c.res(Pass, strings.Join(good, "; "))
			}, nil)
	})

	register(func(e *Env) Check {
		return fn(Meta{ID: "REDIS-AUTH", Title: "Redis requires a password", Category: "redis", Severity: Medium,
			Rationale: "Without a password any local process or user (a compromised web app included) can read, " +
				"change or delete everything in Redis.",
			Remediation: "Set `requirepass`, or define ACL users and turn the default user off " +
				"(`user default off`). Give Kurogane its own read-only user: -@all +ping +info +slowlog|get."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				cs := redisConfs(ctx, c.e)
				if len(cs) == 0 {
					return c.res(NA, noRedis)
				}
				var bad, good []string
				for _, r := range cs {
					if r.auth {
						good = append(good, r.File+": "+r.authWhy)
					} else {
						bad = append(bad, r.File+": "+r.authWhy)
					}
				}
				if len(bad) > 0 {
					return c.res(Fail, strings.Join(bad, "; "))
				}
				return c.res(Pass, strings.Join(good, "; "))
			}, nil)
	})

	register(func(e *Env) Check {
		return fn(Meta{ID: "REDIS-PROTECTED-MODE", Title: "Redis protected mode is on", Category: "redis",
			Severity: Medium,
			Rationale: "Protected mode refuses outside connections while no password is set; turning it off is the " +
				"usual first step of an accidentally exposed Redis.",
			Remediation: "Remove `protected-mode no` (the default is yes)."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				cs := redisConfs(ctx, c.e)
				if len(cs) == 0 {
					return c.res(NA, noRedis)
				}
				var bad []string
				for _, r := range cs {
					if !r.ProtectedMode {
						bad = append(bad, "protected-mode no at "+where(r, "protected-mode"))
					}
				}
				if len(bad) > 0 {
					return c.res(Fail, strings.Join(bad, "; "))
				}
				return c.res(Pass, "protected-mode yes")
			}, nil)
	})

	register(func(e *Env) Check {
		return fn(Meta{ID: "REDIS-DANGEROUS-COMMANDS", Title: "Redis admin commands are restricted on networked instances",
			Category: "redis", Severity: Low,
			Rationale: "FLUSHALL, FLUSHDB, CONFIG and DEBUG let any client that gets in wipe the data or rewrite " +
				"Redis's files.",
			Remediation: "On instances other hosts can reach, use ACL users without these commands, or " +
				"`rename-command FLUSHALL \"\"` (and FLUSHDB, CONFIG, DEBUG)."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				cs := redisConfs(ctx, c.e)
				if len(cs) == 0 {
					return c.res(NA, noRedis)
				}
				var bad, good []string
				for _, r := range cs {
					if len(r.exposed) == 0 {
						good = append(good, r.File+": loopback only")
						continue
					}
					var open []string
					for _, cmd := range []string{"FLUSHALL", "FLUSHDB", "CONFIG", "DEBUG"} {
						if _, renamed := r.Renamed[cmd]; !renamed {
							open = append(open, cmd)
						}
					}
					if len(open) > 0 && len(r.acl) == 0 {
						bad = append(bad, fmt.Sprintf("%s (listening on %s): %s not renamed and no ACL users", r.File,
							strings.Join(r.exposed, ", "), strings.Join(open, ", ")))
						continue
					}
					good = append(good, r.File+": restricted")
				}
				if len(bad) > 0 {
					return c.res(Fail, strings.Join(bad, "; "))
				}
				return c.res(Pass, strings.Join(good, "; "))
			}, nil)
	})
}
