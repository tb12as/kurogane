package certs

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/tb12as/serverman/internal/hostfs"
)

// Reader reads host files. The agent passes its executor, so root-only certbot directories are read by the
// privileged parent through the existing "read" operation.
type Reader interface {
	ReadFile(path string) ([]byte, error)
}

// Options configures a scan.
type Options struct {
	Paths   []string      // extra certificate files
	Ports   []int         // local ports to probe with TLS handshakes; empty disables probing
	Timeout time.Duration // per handshake, default 3s
	Now     func() time.Time
}

// Source is a discovered certificate file.
type Source struct {
	Path        string
	Origin      string
	Lineage     string   // Let's Encrypt lineage (live/<name>)
	ServerNames []string // nginx server_name values
}

const (
	leRenewal = "/etc/letsencrypt/renewal"
	leLive    = "/etc/letsencrypt/live"
	nginxConf = "/etc/nginx/nginx.conf"
	nginxDir  = "/etc/nginx"
)

// Discover lists certificate files from Let's Encrypt, the nginx configuration and extra, de-duplicated by
// path. A file found in several places keeps the first origin and the union of its nginx server names.
func Discover(r Reader, extra []string) []Source {
	var out []Source
	idx := map[string]int{}
	add := func(s Source) {
		s.Path = path.Clean(s.Path)
		if skipPath(s.Path) {
			return
		}
		if i, ok := idx[s.Path]; ok {
			for _, n := range s.ServerNames {
				if !slices.Contains(out[i].ServerNames, n) {
					out[i].ServerNames = append(out[i].ServerNames, n)
				}
			}
			return
		}
		idx[s.Path] = len(out)
		out = append(out, s)
	}
	for _, s := range letsEncrypt(r) {
		add(s)
	}
	for _, s := range nginx(r) {
		add(s)
	}
	for _, p := range extra {
		if p != "" {
			add(Source{Path: p, Origin: OriginConfig})
		}
	}
	return out
}

// skipPath refuses paths that name private keys or contain variables.
func skipPath(p string) bool {
	b := strings.ToLower(path.Base(p))
	return !path.IsAbs(p) || strings.ContainsAny(p, "$") || strings.Contains(b, "privkey") ||
		strings.HasSuffix(b, ".key")
}

// letsEncrypt reads renewal/*.conf (world-readable) for the live paths, falling back to listing live/.
func letsEncrypt(r Reader) []Source {
	var out []Source
	seen := map[string]bool{}
	ents, _ := os.ReadDir(hostfs.P(leRenewal))
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), ".conf")
		if !ok || e.IsDir() {
			continue
		}
		b, err := r.ReadFile(leRenewal + "/" + e.Name())
		if err != nil {
			continue
		}
		p := renewalValue(b, "fullchain")
		if p == "" {
			p = renewalValue(b, "cert")
		}
		if p == "" {
			p = leLive + "/" + name + "/fullchain.pem"
		}
		seen[name] = true
		out = append(out, Source{Path: p, Origin: OriginLetsEncrypt, Lineage: name})
	}
	ents, _ = os.ReadDir(hostfs.P(leLive))
	for _, e := range ents {
		if !e.IsDir() || seen[e.Name()] {
			continue
		}
		out = append(out, Source{Path: leLive + "/" + e.Name() + "/fullchain.pem", Origin: OriginLetsEncrypt,
			Lineage: e.Name()})
	}
	return out
}

func renewalValue(b []byte, key string) string {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok && strings.TrimSpace(k) == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ---- nginx ----

type frame struct {
	name  string
	names []string
	certs []string
}

// nginx walks nginx.conf with includes expanded and returns each ssl_certificate with its server names.
func nginx(r Reader) []Source {
	toks := expand(r, nginxConf, 0, map[string]bool{})
	if len(toks) == 0 {
		return nil
	}
	var out []Source
	stack := []*frame{{name: "main"}}
	var stmt []string
	for _, t := range toks {
		top := stack[len(stack)-1]
		switch t {
		case "{":
			name := ""
			if len(stmt) > 0 {
				name = stmt[0]
			}
			stack = append(stack, &frame{name: name})
			stmt = nil
		case "}":
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
				if top.name == "server" {
					for _, c := range top.certs {
						out = append(out, Source{Path: c, Origin: OriginNginx, ServerNames: top.names})
					}
				}
			}
			stmt = nil
		case ";":
			if len(stmt) >= 2 {
				switch {
				case stmt[0] == "server_name" && top.name == "server":
					top.names = append(top.names, stmt[1:]...)
				case stmt[0] == "ssl_certificate" && top.name == "server":
					top.certs = append(top.certs, nginxPath(stmt[1]))
				case stmt[0] == "ssl_certificate" && top.name == "http":
					out = append(out, Source{Path: nginxPath(stmt[1]), Origin: OriginNginx})
				}
			}
			stmt = nil
		default:
			stmt = append(stmt, t)
		}
	}
	return out
}

func nginxPath(p string) string {
	if path.IsAbs(p) {
		return p
	}
	return nginxDir + "/" + p
}

// expand tokenizes file and splices included files in place (globs relative to /etc/nginx).
func expand(r Reader, file string, depth int, seen map[string]bool) []string {
	// the Exists check keeps a host without nginx from logging a failed privileged read every scan
	if depth > 10 || seen[file] || len(seen) > 500 || !hostfs.Exists(file) {
		return nil
	}
	seen[file] = true
	b, err := r.ReadFile(file)
	if err != nil {
		return nil
	}
	in := tokenize(b)
	var out []string
	for i := 0; i < len(in); i++ {
		if in[i] == "include" && i+2 < len(in) && in[i+2] == ";" {
			for _, f := range glob(nginxPath(in[i+1])) {
				out = append(out, expand(r, f, depth+1, seen)...)
			}
			i += 2
			continue
		}
		out = append(out, in[i])
	}
	return out
}

func glob(pat string) []string {
	if !strings.ContainsAny(pat, "*?[") {
		return []string{pat}
	}
	ms, _ := filepath.Glob(hostfs.P(pat))
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		if hostfs.Root != "/" && hostfs.Root != "" {
			rel, err := filepath.Rel(hostfs.Root, m)
			if err != nil {
				continue
			}
			m = "/" + rel
		}
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// tokenize splits nginx config into words and the punctuation tokens ";", "{" and "}".
func tokenize(b []byte) []string {
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case c == '#':
			flush()
			for i < len(b) && b[i] != '\n' {
				i++
			}
		case c == '"' || c == '\'':
			flush()
			j := i + 1
			for j < len(b) && b[j] != c {
				if b[j] == '\\' {
					j++
				}
				j++
			}
			out = append(out, string(b[i+1:min(j, len(b))]))
			i = j
		case c == ';' || c == '{' || c == '}':
			flush()
			out = append(out, string(c))
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// ---- scan ----

// Scan discovers, reads and inspects every certificate, then probes the configured local ports to find
// which certificate each name is really served with and any certificate served without a file.
func Scan(ctx context.Context, r Reader, o Options) []Cert {
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	if o.Timeout <= 0 {
		o.Timeout = 3 * time.Second
	}
	var out []Cert
	for _, s := range Discover(r, o.Paths) {
		c := Cert{Path: s.Path, Origin: s.Origin, ServerNames: s.ServerNames, Name: s.Lineage}
		b, err := r.ReadFile(s.Path)
		switch {
		case err != nil:
			c.Error = readErr(err)
		case len(b) > maxPEM:
			c.Error = "file larger than 1 MiB, not a certificate"
		default:
			info, cn, err := Inspect(b)
			if err != nil {
				c.Error = err.Error()
			}
			c.Info = info
			if c.Name == "" {
				c.Name = info.Primary(cn)
			}
		}
		if c.Name == "" {
			c.Name = path.Base(path.Dir(s.Path)) + "/" + path.Base(s.Path)
		}
		out = append(out, c)
	}
	if len(o.Ports) > 0 {
		out = probe(ctx, out, o)
	}
	t := now()
	names := map[string]int{}
	for i := range out {
		names[out[i].Name]++
		if out[i].Error == "" {
			out[i].DaysLeft = Days(out[i].NotAfter, t)
		}
	}
	for i := range out {
		if names[out[i].Name] > 1 && out[i].Path != "" {
			out[i].Name += " (" + out[i].Path + ")"
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func readErr(err error) string {
	if errors.Is(err, os.ErrNotExist) {
		return "file not found"
	}
	if errors.Is(err, os.ErrPermission) {
		return "permission denied"
	}
	return err.Error()
}

func probe(ctx context.Context, out []Cert, o Options) []Cert {
	dead := map[int]bool{}
	known := map[string]bool{}
	for _, c := range out {
		if c.Fingerprint != "" {
			known[c.Fingerprint] = true
		}
	}
	try := func(port int, sni string) (Info, bool) {
		if dead[port] || ctx.Err() != nil {
			return Info{}, false
		}
		got, err := Probe(ctx, addr(port), sni, o.Timeout)
		if err != nil {
			if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
				dead[port] = true
			}
			return Info{}, false
		}
		return got, true
	}
	for i := range out {
		c := &out[i]
		sni := probeName(*c)
		if c.Error != "" || sni == "" {
			continue
		}
		for _, port := range o.Ports {
			got, ok := try(port, sni)
			if !ok {
				continue
			}
			if got.Fingerprint == c.Fingerprint {
				c.ServedPort = port
				break
			}
			if got.Covers(sni) && c.Covers(sni) {
				c.ServedPort = port
				if got.NotAfter.Before(c.NotAfter) {
					c.Stale, c.ServedNotAfter = true, got.NotAfter
				}
				break
			}
		}
	}
	// the default certificate of each port (no SNI) catches servers whose files were not found
	for _, port := range o.Ports {
		got, ok := try(port, "")
		if !ok || known[got.Fingerprint] {
			continue
		}
		known[got.Fingerprint] = true
		name := got.Primary("")
		if name == "" {
			name = fmt.Sprintf("port %d", port)
		}
		out = append(out, Cert{Name: name, Origin: OriginLive, Info: got, ServedPort: port})
	}
	return out
}

func isTimeout(err error) bool {
	var ne interface{ Timeout() bool }
	return errors.As(err, &ne) && ne.Timeout()
}
