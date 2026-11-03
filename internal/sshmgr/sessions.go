package sshmgr

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/serverkeeper/serverkeeper/internal/hostfs"
)

// Session is an active login (§6.4).
type Session struct {
	ID      string    `json:"id,omitempty"` // logind session id (when utmp is absent)
	User    string    `json:"user"`
	TTY     string    `json:"tty"`
	From    string    `json:"from"`
	Started time.Time `json:"started"`
	PID     int       `json:"pid"`
}

const utmpSize = 384 // glibc struct utmp on amd64 and arm64

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// parseUtmp returns USER_PROCESS records.
func parseUtmp(b []byte) []Session {
	var out []Session
	for off := 0; off+utmpSize <= len(b); off += utmpSize {
		r := b[off : off+utmpSize]
		if binary.LittleEndian.Uint16(r[0:2]) != 7 { // USER_PROCESS
			continue
		}
		out = append(out, Session{
			PID:     int(int32(binary.LittleEndian.Uint32(r[4:8]))),
			TTY:     cstr(r[8:40]),
			User:    cstr(r[44:76]),
			From:    cstr(r[76:332]),
			Started: time.Unix(int64(int32(binary.LittleEndian.Uint32(r[340:344]))), 0),
		})
	}
	return out
}

// Sessions lists active sessions from utmp, or from systemd-logind on systems that no longer write utmp.
func (m *Manager) Sessions(ctx context.Context) ([]Session, error) {
	for _, p := range []string{"/run/utmp", "/var/run/utmp"} {
		if b, err := hostfs.Read(p); err == nil {
			return parseUtmp(b), nil
		}
	}
	out, err := m.d.Ex.Run(ctx, "loginctl", "list-sessions", "--no-legend", "--no-pager")
	if err != nil {
		return nil, fmt.Errorf("no utmp and loginctl failed (%v): session listing needs utmp or systemd-logind: %w",
			err, fs.ErrNotExist)
	}
	ss := []Session{}
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		p, err := m.d.Ex.Run(ctx, "loginctl", "show-session", f[0], "-p", "Name", "-p", "TTY", "-p", "RemoteHost",
			"-p", "Leader", "-p", "Timestamp", "-p", "Class")
		if err != nil {
			continue
		}
		if s, ok := parseLogind(f[0], string(p)); ok {
			ss = append(ss, s)
		}
	}
	return ss, nil
}

// parseLogind parses `loginctl show-session -p ...` output; manager/greeter sessions are skipped.
func parseLogind(id, out string) (Session, bool) {
	s := Session{ID: id}
	class := ""
	for _, l := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(l), "=")
		switch k {
		case "Name":
			s.User = v
		case "TTY":
			s.TTY = v
		case "RemoteHost":
			s.From = v
		case "Leader":
			s.PID, _ = strconv.Atoi(v)
		case "Class":
			class = v
		case "Timestamp":
			if t, err := time.ParseInLocation("Mon 2006-01-02 15:04:05 MST", v, time.Local); err == nil {
				s.Started = t
			}
		}
	}
	return s, class == "user" && s.User != ""
}

// KillSession terminates the session with pid (only pids listed as sessions can be killed).
func (m *Manager) KillSession(ctx context.Context, pid int) (Session, error) {
	ss, err := m.Sessions(ctx)
	if err != nil {
		return Session{}, err
	}
	for _, s := range ss {
		if s.PID != pid {
			continue
		}
		switch {
		case s.ID != "":
			_, err = m.d.Ex.Run(ctx, "loginctl", "terminate-session", s.ID)
		case s.TTY != "":
			_, err = m.d.Ex.Run(ctx, "pkill", "-KILL", "-t", s.TTY)
		default:
			_, err = m.d.Ex.Run(ctx, "kill", "-HUP", fmt.Sprint(pid))
		}
		if err == nil {
			m.d.Audit.Record(ctx, "ssh.session.kill", fmt.Sprintf("%s %s pid %d", s.User, s.TTY, pid), s, nil)
		}
		return s, err
	}
	return Session{}, fmt.Errorf("no active session with pid %d: list them with `serverkeeper ssh sessions`", pid)
}

// Login is one parsed auth-log event.
type Login struct {
	TS          time.Time `json:"ts"`
	User        string    `json:"user"`
	IP          string    `json:"ip"`
	Success     bool      `json:"success"`
	Method      string    `json:"method"`
	Invalid     bool      `json:"invalid_user,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
}

var (
	reAccepted = regexp.MustCompile(`Accepted (\S+) for (\S+) from (\S+) port \d+(?: ssh2(?:: (\S+) (\S+))?)?`)
	reFailed   = regexp.MustCompile(`Failed (\S+) for (invalid user )?(\S+) from (\S+) port \d+`)
	reInvalid  = regexp.MustCompile(`Invalid user (\S*) from (\S+)`)
	reSyslogTS = regexp.MustCompile(`^([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d)`)
)

// parseAuthLine parses one sshd log line (syslog or RFC3339 timestamp); ok=false for other lines.
func parseAuthLine(l string, now time.Time) (Login, bool) {
	if !strings.Contains(l, "sshd") {
		return Login{}, false
	}
	var ev Login
	switch {
	case reAccepted.MatchString(l):
		x := reAccepted.FindStringSubmatch(l)
		ev = Login{Success: true, Method: x[1], User: x[2], IP: x[3], Fingerprint: x[5]}
	case reFailed.MatchString(l):
		x := reFailed.FindStringSubmatch(l)
		ev = Login{Method: x[1], Invalid: x[2] != "", User: x[3], IP: x[4]}
	case reInvalid.MatchString(l):
		x := reInvalid.FindStringSubmatch(l)
		ev = Login{Method: "invalid-user", Invalid: true, User: x[1], IP: x[2]}
	default:
		return Login{}, false
	}
	ev.TS = parseTS(l, now)
	return ev, true
}

func parseTS(l string, now time.Time) time.Time {
	if f := strings.Fields(l); len(f) > 0 {
		if t, err := time.Parse(time.RFC3339Nano, f[0]); err == nil {
			return t
		}
	}
	if x := reSyslogTS.FindString(l); x != "" {
		if t, err := time.ParseInLocation("Jan _2 15:04:05", x, time.Local); err == nil {
			t = t.AddDate(now.Year(), 0, 0)
			if t.After(now.Add(24 * time.Hour)) { // log from last year
				t = t.AddDate(-1, 0, 0)
			}
			return t
		}
	}
	return now
}

func authLogPath() string {
	for _, p := range []string{"/var/log/auth.log", "/var/log/secure"} {
		if hostfs.Exists(p) {
			return p
		}
	}
	return ""
}

// History parses the auth log (or journald) since t.
func (m *Manager) History(ctx context.Context, since time.Time) ([]Login, error) {
	var text string
	if p := authLogPath(); p != "" {
		b, err := m.d.Ex.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		text = string(b)
	} else {
		out, err := m.d.Ex.Run(ctx, "journalctl", "_COMM=sshd", "--since", since.Format("2006-01-02 15:04:05"),
			"-o", "short-iso", "--no-pager")
		if err != nil {
			return nil, fmt.Errorf("no /var/log/auth.log or /var/log/secure and journalctl failed: %w", err)
		}
		text = string(out)
	}
	now := m.now()
	var out []Login
	for _, l := range strings.Split(text, "\n") {
		if ev, ok := parseAuthLine(l, now); ok && !ev.TS.Before(since) {
			out = append(out, ev)
		}
	}
	return out, nil
}

// Count is a value with a number of occurrences.
type Count struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// LoginSummary is login history plus top failing IPs and users.
type LoginSummary struct {
	Logins      []Login `json:"logins"`
	Success     int     `json:"success"`
	Failed      int     `json:"failed"`
	TopFailIPs  []Count `json:"top_failing_ips"`
	TopFailUser []Count `json:"top_failing_users"`
}

func top(m map[string]int, n int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// Summary returns history with the top failing sources (§6.4).
func (m *Manager) Summary(ctx context.Context, since time.Time) (LoginSummary, error) {
	ls, err := m.History(ctx, since)
	if err != nil {
		return LoginSummary{}, err
	}
	ips, users := map[string]int{}, map[string]int{}
	s := LoginSummary{Logins: append([]Login{}, ls...)}
	for _, l := range ls {
		if l.Success {
			s.Success++
			continue
		}
		s.Failed++
		ips[l.IP]++
		users[l.User]++
	}
	s.TopFailIPs, s.TopFailUser = top(ips, 10), top(users, 10)
	if len(s.Logins) > 1000 {
		s.Logins = s.Logins[len(s.Logins)-1000:]
	}
	return s, nil
}
