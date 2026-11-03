package checks

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/serverkeeper/serverkeeper/internal/collector"
)

// Listener is a listening socket.
type Listener = collector.Listener

// listeners returns listening sockets: the collector snapshot first, `ss` as fallback.
func listeners(ctx context.Context, e *Env) []Listener {
	ls, _ := memo(ctx, "listen", func() ([]Listener, error) {
		if e.Latest != nil {
			if s := e.Latest(); s != nil && len(s.Conns.Listening) > 0 {
				return s.Conns.Listening, nil
			}
		}
		var out []Listener
		if b, err := e.Ex.Run(ctx, "ss", "-tlnpH"); err == nil {
			out = append(out, parseSS(string(b), "tcp")...)
		}
		if b, err := e.Ex.Run(ctx, "ss", "-uanpH"); err == nil {
			out = append(out, parseSS(string(b), "udp")...)
		}
		return out, nil
	})
	return ls
}

// parseSS parses `ss -tlnpH` / `ss -uanpH` lines (udp keeps UNCONN sockets only).
func parseSS(s, proto string) []Listener {
	var out []Listener
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) < 5 || (proto == "udp" && f[0] != "UNCONN") {
			continue
		}
		i := strings.LastIndexByte(f[3], ':')
		if i < 0 {
			continue
		}
		port, err := strconv.Atoi(f[3][i+1:])
		if err != nil {
			continue
		}
		ln := Listener{Proto: proto, Addr: f[3][:i], Port: port}
		if len(f) > 5 {
			if a := strings.Index(f[5], `(("`); a >= 0 {
				rest := f[5][a+3:]
				if b := strings.IndexByte(rest, '"'); b >= 0 {
					ln.Process = rest[:b]
				}
			}
		}
		out = append(out, ln)
	}
	return out
}

// public reports whether a listen address is reachable from outside the host.
func public(addr string) bool {
	a := strings.Trim(addr, "[]")
	if i := strings.IndexByte(a, '%'); i >= 0 {
		a = a[:i]
	}
	if a == "localhost" {
		return false
	}
	ip := net.ParseIP(a)
	return ip == nil || !(ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast())
}

// publicPorts returns de-duplicated public listeners as "port/proto" -> process.
func publicPorts(ctx context.Context, e *Env) map[string]string {
	m := map[string]string{}
	for _, l := range listeners(ctx, e) {
		if !public(l.Addr) {
			continue
		}
		k := fmt.Sprintf("%d/%s", l.Port, l.Proto)
		if m[k] == "" {
			m[k] = l.Process
		}
	}
	return m
}

func sortedPorts(m map[string]string) []string {
	ks := sortedKeys(m)
	sort.SliceStable(ks, func(i, j int) bool {
		a, _ := strconv.Atoi(strings.Split(ks[i], "/")[0])
		b, _ := strconv.Atoi(strings.Split(ks[j], "/")[0])
		return a < b
	})
	return ks
}

// sshPort returns the configured sshd port (22 if unknown).
func sshPort(ctx context.Context, e *Env) int {
	if m, err := SSHSettings(ctx, e); err == nil {
		if p, err := strconv.Atoi(m["port"]); err == nil && p > 0 {
			return p
		}
	}
	return 22
}

// keepOpen is the set of ports a firewall fix must leave open: every public listener plus the SSH port.
func keepOpen(ctx context.Context, e *Env) []string {
	m := publicPorts(ctx, e)
	m[fmt.Sprintf("%d/tcp", sshPort(ctx, e))] = "sshd"
	return sortedPorts(m)
}
