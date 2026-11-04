// Package redisinfo is a minimal, read-only Redis client: it speaks RESP2 and only ever sends AUTH, PING, INFO
// and SLOWLOG GET. ServerKeeper never reads keys or changes Redis settings, so a full client library (cluster,
// pub/sub, pipelining) would only add code and binary size.
package redisinfo

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Target is one Redis instance.
type Target struct {
	Addr     string // host:port, or unix:/path/to.sock
	Username string // ACL user; "" = default user
	Password string // "" = no AUTH
	TLS      bool
	Timeout  time.Duration // per call, default 2s
}

// Errors callers tell apart.
var (
	// ErrNoAuth means the server wants a password and none was given: the instance "needs credentials".
	ErrNoAuth = errors.New("redis requires a password (NOAUTH)")
	// ErrAuth means the given credentials were rejected.
	ErrAuth = errors.New("redis rejected the credentials")
)

// Error is an error reply from the server.
type Error string

func (e Error) Error() string { return "redis: " + string(e) }

// Conn is an open, authenticated connection.
type Conn struct {
	c       net.Conn
	r       *bufio.Reader
	timeout time.Duration
}

// Dial connects and authenticates. Without a password it sends PING so a server that needs one answers NOAUTH
// now (ErrNoAuth) rather than on the first real command.
func Dial(ctx context.Context, t Target) (*Conn, error) {
	if t.Timeout <= 0 {
		t.Timeout = 2 * time.Second
	}
	network, addr := "tcp", t.Addr
	if p, ok := strings.CutPrefix(addr, "unix:"); ok {
		network, addr = "unix", p
	}
	d := &net.Dialer{Timeout: t.Timeout}
	var c net.Conn
	var err error
	if t.TLS && network == "tcp" {
		host, _, _ := net.SplitHostPort(addr)
		td := &tls.Dialer{NetDialer: d, Config: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12,
			InsecureSkipVerify: true}} // #nosec G402 -- local instance, usually a self-signed certificate
		c, err = td.DialContext(ctx, network, addr)
	} else {
		c, err = d.DialContext(ctx, network, addr)
	}
	if err != nil {
		return nil, err
	}
	conn := &Conn{c: c, r: bufio.NewReaderSize(c, 16<<10), timeout: t.Timeout}
	if t.Password != "" {
		args := []string{"AUTH", t.Password}
		if t.Username != "" {
			args = []string{"AUTH", t.Username, t.Password}
		}
		if _, err := conn.Do(args...); err != nil {
			var re Error
			if errors.As(err, &re) && strings.Contains(string(re), "without any password configured") {
				return conn, nil // a password we did not need: the connection is fine
			}
			conn.Close()
			if errors.As(err, &re) {
				return nil, ErrAuth
			}
			return nil, err
		}
		return conn, nil
	}
	if _, err := conn.Do("PING"); err != nil {
		conn.Close()
		var re Error
		if errors.As(err, &re) && strings.HasPrefix(string(re), "NOAUTH") {
			return nil, ErrNoAuth
		}
		return nil, err
	}
	return conn, nil
}

// Close closes the connection.
func (c *Conn) Close() error { return c.c.Close() }

// Do sends one command and returns its reply: string, int64, nil, []any or an Error.
func (c *Conn) Do(args ...string) (any, error) {
	if err := c.c.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := io.WriteString(c.c, b.String()); err != nil {
		return nil, err
	}
	v, err := c.read(0)
	if err != nil {
		return nil, err
	}
	if e, ok := v.(Error); ok {
		return nil, e
	}
	return v, nil
}

// maxBulk bounds one reply (INFO is a few KB; anything huge is not what we asked for).
const maxBulk = 4 << 20

func (c *Conn) read(depth int) (any, error) {
	if depth > 4 {
		return nil, errors.New("redis: reply nested too deeply")
	}
	line, err := c.r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	if line == "" {
		return nil, errors.New("redis: empty reply line")
	}
	body := line[1:]
	switch line[0] {
	case '+':
		return body, nil
	case '-':
		return Error(body), nil
	case ':':
		return strconv.ParseInt(body, 10, 64)
	case '$':
		n, err := strconv.Atoi(body)
		if err != nil || n > maxBulk {
			return nil, fmt.Errorf("redis: bad bulk length %q", body)
		}
		if n < 0 {
			return nil, nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(c.r, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(body)
		if err != nil || n > 10000 {
			return nil, fmt.Errorf("redis: bad array length %q", body)
		}
		if n < 0 {
			return nil, nil
		}
		out := make([]any, 0, n)
		for i := 0; i < n; i++ {
			v, err := c.read(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
	return nil, fmt.Errorf("redis: unexpected reply type %q", line[0])
}

// Ping measures one PING round trip.
func (c *Conn) Ping() (time.Duration, error) {
	start := time.Now()
	_, err := c.Do("PING")
	return time.Since(start), err
}

// Info returns INFO (all default sections) parsed.
func (c *Conn) Info() (Info, error) {
	v, err := c.Do("INFO")
	if err != nil {
		return nil, err
	}
	s, ok := v.(string)
	if !ok {
		return nil, errors.New("redis: INFO did not return text")
	}
	return ParseInfo(s), nil
}

// SlowEntry is one slow log entry. Only the command name is kept: arguments can hold keys, values or passwords.
type SlowEntry struct {
	ID       int64         `json:"id"`
	At       time.Time     `json:"at"`
	Duration time.Duration `json:"duration_ns"`
	Command  string        `json:"command"`
}

// SlowLog returns up to n recent slow log entries.
func (c *Conn) SlowLog(n int) ([]SlowEntry, error) {
	v, err := c.Do("SLOWLOG", "GET", strconv.Itoa(n))
	if err != nil {
		return nil, err
	}
	rows, _ := v.([]any)
	var out []SlowEntry
	for _, r := range rows {
		f, ok := r.([]any)
		if !ok || len(f) < 4 {
			continue
		}
		id, _ := f[0].(int64)
		ts, _ := f[1].(int64)
		us, _ := f[2].(int64)
		e := SlowEntry{ID: id, At: time.Unix(ts, 0).UTC(), Duration: time.Duration(us) * time.Microsecond}
		if args, ok := f[3].([]any); ok && len(args) > 0 {
			name, _ := args[0].(string)
			e.Command = strings.ToUpper(name)
			// subcommands (CONFIG SET, CLIENT KILL) are safe to show; their arguments are not
			if len(args) > 1 && subcommand[e.Command] {
				if sub, ok := args[1].(string); ok {
					e.Command += " " + strings.ToUpper(sub)
				}
			}
		}
		out = append(out, e)
	}
	return out, nil
}

var subcommand = map[string]bool{"CONFIG": true, "CLIENT": true, "CLUSTER": true, "SCRIPT": true, "XINFO": true,
	"OBJECT": true, "MEMORY": true, "ACL": true, "FUNCTION": true, "MODULE": true, "COMMAND": true}
