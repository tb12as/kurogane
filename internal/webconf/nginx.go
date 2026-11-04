package webconf

import (
	"strings"

	"github.com/tb12as/serverman/internal/hostfs"
)

// nginx locations.
const (
	NginxRoot = "/etc/nginx"
	NginxMain = "/etc/nginx/nginx.conf"
)

type token struct {
	s      string
	file   string
	line   int
	quoted bool
}

func (t token) punct(c string) bool { return !t.quoted && t.s == c }

// tokenize splits nginx config into words and the punctuation tokens ";", "{" and "}".
func tokenize(b []byte, file string) []token {
	var out []token
	var cur strings.Builder
	line, start := 1, 1
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, token{s: cur.String(), file: file, line: start})
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
			line++
		case c == '"' || c == '\'':
			flush()
			l0 := line
			j := i + 1
			for j < len(b) && b[j] != c {
				if b[j] == '\\' {
					j++
				}
				if j < len(b) && b[j] == '\n' {
					line++
				}
				j++
			}
			out = append(out, token{s: string(b[i+1 : min(j, len(b))]), file: file, line: l0, quoted: true})
			i = j
		case c == ';' || c == '{' || c == '}':
			flush()
			out = append(out, token{s: string(c), file: file, line: line})
		case c == ' ' || c == '\t' || c == '\r':
			flush()
		case c == '\n':
			flush()
			line++
		default:
			if cur.Len() == 0 {
				start = line
			}
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// expandNginx tokenizes file and splices included files in place (globs relative to /etc/nginx).
func expandNginx(r Reader, file string, depth int, seen map[string]bool, files *[]string) []token {
	// the Exists check keeps a host without nginx from logging a failed privileged read every scan; included
	// files come from glob, which already saw them (and the worker may not be able to stat them)
	if depth > 10 || seen[file] || len(seen) > 500 || (depth == 0 && !hostfs.Exists(file)) {
		return nil
	}
	seen[file] = true
	b, err := r.ReadFile(file)
	if err != nil {
		return nil
	}
	*files = append(*files, file)
	in := tokenize(b, file)
	var out []token
	for i := 0; i < len(in); i++ {
		if in[i].s == "include" && !in[i].quoted && i+2 < len(in) && in[i+2].punct(";") {
			for _, f := range glob(r, abs(NginxRoot, in[i+1].s)) {
				out = append(out, expandNginx(r, f, depth+1, seen, files)...)
			}
			i += 2
			continue
		}
		out = append(out, in[i])
	}
	return out
}

// ParseNginx parses /etc/nginx/nginx.conf with its includes; nil when nginx is not configured.
func ParseNginx(r Reader) *Config {
	c := &Config{Server: Nginx, Root: NginxRoot, Main: NginxMain}
	toks := expandNginx(r, NginxMain, 0, map[string]bool{}, &c.Files)
	if len(toks) == 0 {
		return nil
	}
	walkNginx(c, toks, false)
	return c
}

// ParseNginxFile parses one site file on its own (a disabled site), as if it were included inside http{}.
func ParseNginxFile(r Reader, file string) (*Config, error) {
	b, err := r.ReadFile(file)
	if err != nil {
		return nil, err
	}
	c := &Config{Server: Nginx, Root: NginxRoot, Main: file, Files: []string{file}}
	walkNginx(c, tokenize(b, file), true)
	return c, nil
}

type nframe struct {
	name  string
	block int // index+1 into Blocks of the enclosing server{}, 0 outside
}

func walkNginx(c *Config, toks []token, inHTTP bool) {
	stack := []nframe{{name: "main"}}
	if inHTTP {
		stack = []nframe{{name: "http"}}
	}
	perFile := map[string]int{}
	var stmt []token
	ctx := func() string {
		names := make([]string, 0, len(stack))
		for _, f := range stack[1:] {
			names = append(names, f.name)
		}
		if inHTTP {
			names = append([]string{"http"}, names...)
		}
		return strings.Join(names, "/")
	}
	for _, t := range toks {
		top := stack[len(stack)-1]
		switch {
		case t.punct("{"):
			name, bi := "", top.block
			if len(stmt) > 0 {
				name = stmt[0].s
			}
			if name == "server" && top.name == "http" {
				b := Block{Server: Nginx, File: stmt[0].file, Line: stmt[0].line, Index: perFile[stmt[0].file]}
				perFile[stmt[0].file]++
				c.Blocks = append(c.Blocks, b)
				bi = len(c.Blocks)
			}
			stack = append(stack, nframe{name: name, block: bi})
			stmt = nil
		case t.punct("}"):
			if len(stack) > 1 {
				if top.name == "server" && top.block > 0 {
					b := &c.Blocks[top.block-1]
					if len(b.Listen) == 0 {
						b.Listen = []Listen{{Port: 80}} // nginx default: listen *:80
					}
				}
				stack = stack[:len(stack)-1]
			}
			stmt = nil
		case t.punct(";"):
			if len(stmt) > 0 {
				d := Directive{Name: strings.ToLower(stmt[0].s), File: stmt[0].file, Line: stmt[0].line, Ctx: ctx(),
					Block: top.block}
				for _, a := range stmt[1:] {
					d.Args = append(d.Args, a.s)
				}
				c.Directives = append(c.Directives, d)
				if top.block > 0 {
					nginxSite(&c.Blocks[top.block-1], d, top.name == "server")
				}
			}
			stmt = nil
		default:
			stmt = append(stmt, t)
		}
	}
}

// nginxSite folds a directive into its server block; serverLevel is false inside location{} and friends.
func nginxSite(b *Block, d Directive, serverLevel bool) {
	if len(d.Args) == 0 {
		return
	}
	switch d.Name {
	case "listen":
		l, ok := ParseListen(d.Args[0])
		if !ok {
			return
		}
		for _, f := range d.Args[1:] {
			switch f {
			case "ssl", "quic":
				l.TLS = true
			case "default_server", "default":
				l.Default = true
			}
		}
		b.Listen = append(b.Listen, l)
	case "server_name":
		if serverLevel {
			b.Names = append(b.Names, d.Args...)
		}
	case "root":
		if serverLevel || b.Root == "" {
			b.Root = d.Args[0]
		}
	case "proxy_pass", "uwsgi_pass", "grpc_pass":
		b.Upstreams = appendNew(b.Upstreams, d.Args[0])
	case "fastcgi_pass":
		b.Upstreams = appendNew(b.Upstreams, d.Args[0])
		b.PHP = true
	case "ssl_certificate":
		if serverLevel {
			b.Certs = appendNew(b.Certs, d.Args[0])
		}
	case "access_log":
		if serverLevel && d.Args[0] != "off" {
			b.AccessLog = d.Args[0]
		}
	}
}

func appendNew(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
