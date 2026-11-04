package redisinfo

import (
	"net"
	"path"
	"strconv"
	"strings"
)

// Reader reads host files (the agent passes its executor: redis.conf is often root-only).
type Reader interface {
	ReadFile(path string) ([]byte, error)
}

// Config is what Kurogane needs from a redis.conf (last value wins, as in Redis).
type Config struct {
	File          string            `json:"file"`
	Port          int               `json:"port"` // 0 = TCP disabled
	TLSPort       int               `json:"tls_port,omitempty"`
	Bind          []string          `json:"bind"`
	UnixSocket    string            `json:"unixsocket,omitempty"`
	ProtectedMode bool              `json:"protected_mode"`
	RequirePass   string            `json:"-"` // never serialized
	HasPassword   bool              `json:"has_password"`
	Renamed       map[string]string `json:"renamed,omitempty"` // rename-command NAME new ("" = disabled)
	Users         []string          `json:"users,omitempty"`   // inline ACL "user" lines without passwords
	ACLFile       string            `json:"aclfile,omitempty"`
	Lines         map[string]int    `json:"-"` // directive -> line of its last occurrence (main file)
}

// ParseConfig reads a redis.conf and its includes. Defaults follow Redis: port 6379, bind loopback (Redis 6+
// default config), protected-mode yes.
func ParseConfig(r Reader, file string) (Config, error) {
	c := Config{File: file, Port: 6379, ProtectedMode: true, Renamed: map[string]string{}, Lines: map[string]int{}}
	err := c.read(r, file, 0)
	c.HasPassword = c.RequirePass != ""
	return c, err
}

func (c *Config) read(r Reader, file string, depth int) error {
	if depth > 5 {
		return nil
	}
	b, err := r.ReadFile(file)
	if err != nil {
		return err
	}
	for n, raw := range strings.Split(string(b), "\n") {
		args := splitConf(strings.TrimSpace(raw))
		if len(args) == 0 || strings.HasPrefix(args[0], "#") {
			continue
		}
		key := strings.ToLower(args[0])
		v := args[1:]
		if file == c.File {
			c.Lines[key] = n + 1
		}
		switch key {
		case "include":
			for _, f := range v {
				if !path.IsAbs(f) {
					f = path.Join(path.Dir(file), f)
				}
				_ = c.read(r, f, depth+1)
			}
		case "port":
			if len(v) > 0 {
				c.Port, _ = strconv.Atoi(v[0])
			}
		case "tls-port":
			if len(v) > 0 {
				c.TLSPort, _ = strconv.Atoi(v[0])
			}
		case "bind":
			c.Bind = v
		case "unixsocket":
			if len(v) > 0 {
				c.UnixSocket = v[0]
			}
		case "protected-mode":
			c.ProtectedMode = len(v) == 0 || !strings.EqualFold(v[0], "no")
		case "requirepass":
			c.RequirePass = ""
			if len(v) > 0 {
				c.RequirePass = v[0]
			}
		case "rename-command":
			if len(v) > 0 {
				to := ""
				if len(v) > 1 {
					to = v[1]
				}
				c.Renamed[strings.ToUpper(v[0])] = to
			}
		case "user":
			if len(v) > 0 {
				c.Users = append(c.Users, aclSummary(v))
			}
		case "aclfile":
			if len(v) > 0 {
				c.ACLFile = v[0]
			}
		}
	}
	return nil
}

// aclSummary keeps an ACL user line without its passwords (">pw", "#hash").
func aclSummary(v []string) string {
	var keep []string
	for _, a := range v {
		if strings.HasPrefix(a, ">") || strings.HasPrefix(a, "#") {
			keep = append(keep, a[:1]+"***")
			continue
		}
		keep = append(keep, a)
	}
	return strings.Join(keep, " ")
}

// splitConf splits a redis.conf line, honouring double and single quotes.
func splitConf(s string) []string {
	var out []string
	var cur strings.Builder
	var q byte
	had := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case q != 0 && ch == q:
			q = 0
		case q != 0:
			if ch == '\\' && q == '"' && i+1 < len(s) {
				i++
				ch = s[i]
			}
			cur.WriteByte(ch)
		case ch == '"' || ch == '\'':
			q, had = ch, true
		case ch == ' ' || ch == '\t':
			if cur.Len() > 0 || had {
				out = append(out, cur.String())
				cur.Reset()
				had = false
			}
		default:
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 || had {
		out = append(out, cur.String())
	}
	return out
}

// Loopback reports whether every bind address is a loopback address (the safe default).
func (c Config) Loopback() bool {
	if len(c.Bind) == 0 {
		return false // no bind directive: Redis listens on all interfaces
	}
	for _, b := range c.Bind {
		ip := net.ParseIP(strings.TrimPrefix(strings.TrimPrefix(b, "-"), "::ffff:"))
		if ip == nil || !ip.IsLoopback() {
			return false
		}
	}
	return true
}

// Target returns how Kurogane connects: TCP on a loopback address when TCP is on, else TLS, else the socket.
func (c Config) Target() Target {
	host := "127.0.0.1"
	for _, b := range c.Bind {
		b = strings.TrimPrefix(b, "-")
		if ip := net.ParseIP(b); ip != nil && ip.IsLoopback() {
			host = b
			break
		}
		if b != "*" && b != "0.0.0.0" && b != "::" && b != "::*" && host == "127.0.0.1" && !hasLoopback(c.Bind) {
			host = b // only non-loopback addresses bound: connect to the first one
		}
	}
	switch {
	case c.Port > 0:
		return Target{Addr: net.JoinHostPort(host, strconv.Itoa(c.Port))}
	case c.TLSPort > 0:
		return Target{Addr: net.JoinHostPort(host, strconv.Itoa(c.TLSPort)), TLS: true}
	case c.UnixSocket != "":
		return Target{Addr: "unix:" + c.UnixSocket}
	}
	return Target{}
}

func hasLoopback(bind []string) bool {
	for _, b := range bind {
		if ip := net.ParseIP(strings.TrimPrefix(b, "-")); ip != nil && ip.IsLoopback() {
			return true
		}
	}
	return false
}
