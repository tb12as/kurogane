package webconf

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/tb12as/serverman/internal/hostfs"
)

// Apache layouts: Debian (apache2) and RHEL (httpd).
var apacheMains = []struct{ root, main string }{
	{"/etc/apache2", "/etc/apache2/apache2.conf"},
	{"/etc/httpd", "/etc/httpd/conf/httpd.conf"},
}

type aline struct {
	text string
	file string
	line int
}

// apacheLines reads file, joins backslash continuations, drops comments and splices Include/IncludeOptional.
func apacheLines(r Reader, file string, root *string, depth int, seen map[string]bool, files *[]string) []aline {
	if depth > 10 || seen[file] || len(seen) > 500 || (depth == 0 && !hostfs.Exists(file)) {
		return nil
	}
	seen[file] = true
	b, err := r.ReadFile(file)
	if err != nil {
		return nil
	}
	*files = append(*files, file)
	var out []aline
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	n, start := 0, 0
	var cur strings.Builder
	for sc.Scan() {
		n++
		s := strings.TrimSpace(sc.Text())
		if cur.Len() == 0 {
			start = n
			if s == "" || strings.HasPrefix(s, "#") {
				continue
			}
		}
		if cont, ok := strings.CutSuffix(s, "\\"); ok {
			cur.WriteString(cont + " ")
			continue
		}
		cur.WriteString(s)
		text := strings.TrimSpace(cur.String())
		cur.Reset()
		args := splitArgs(text)
		if len(args) == 0 {
			continue
		}
		switch strings.ToLower(args[0]) {
		case "serverroot":
			if len(args) > 1 {
				*root = args[1]
			}
		case "include", "includeoptional":
			for _, pat := range args[1:] {
				for _, f := range glob(r, abs(*root, pat)) {
					out = append(out, apacheLines(r, f, root, depth+1, seen, files)...)
				}
			}
			continue
		}
		out = append(out, aline{text: text, file: file, line: start})
	}
	return out
}

// splitArgs splits an Apache line into words, honouring double quotes.
func splitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	in, had := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			in, had = !in, true
		case (c == ' ' || c == '\t') && !in:
			if cur.Len() > 0 || had {
				out = append(out, cur.String())
				cur.Reset()
				had = false
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 || had {
		out = append(out, cur.String())
	}
	return out
}

// ParseApache parses the Debian or RHEL main config with its includes; nil when Apache is not configured.
func ParseApache(r Reader) *Config {
	for _, m := range apacheMains {
		if !hostfs.Exists(m.main) {
			continue
		}
		c := &Config{Server: Apache, Root: m.root, Main: m.main}
		root := m.root
		lines := apacheLines(r, m.main, &root, 0, map[string]bool{}, &c.Files)
		walkApache(c, lines)
		return c
	}
	return nil
}

// ApacheRoot returns the configured Apache root (/etc/apache2 or /etc/httpd), "" when none exists.
func ApacheRoot() string {
	for _, m := range apacheMains {
		if hostfs.Exists(m.main) {
			return m.root
		}
	}
	return ""
}

// ParseApacheFile parses one site file on its own (a disabled site).
func ParseApacheFile(r Reader, root, file string) (*Config, error) {
	if _, err := r.ReadFile(file); err != nil {
		return nil, err
	}
	c := &Config{Server: Apache, Root: root, Main: file}
	walkApache(c, apacheLines(r, file, &root, 0, map[string]bool{}, &c.Files))
	return c, nil
}

type aframe struct {
	name  string
	block int
}

func walkApache(c *Config, lines []aline) {
	var stack []aframe
	perFile := map[string]int{}
	ctx := func() string {
		names := make([]string, len(stack))
		for i, f := range stack {
			names[i] = f.name
		}
		return strings.Join(names, "/")
	}
	cur := func() int {
		if len(stack) == 0 {
			return 0
		}
		return stack[len(stack)-1].block
	}
	for _, l := range lines {
		t := l.text
		if strings.HasPrefix(t, "</") {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if strings.HasPrefix(t, "<") {
			inner := strings.TrimSuffix(strings.TrimPrefix(t, "<"), ">")
			args := splitArgs(inner)
			if len(args) == 0 {
				continue
			}
			name := strings.ToLower(args[0])
			bi := cur()
			if name == "virtualhost" && bi == 0 {
				b := Block{Server: Apache, File: l.file, Line: l.line, Index: perFile[l.file]}
				perFile[l.file]++
				for _, a := range args[1:] {
					if ls, ok := ParseListen(a); ok {
						ls.TLS = ls.Port == 443
						b.Listen = append(b.Listen, ls)
					}
				}
				if len(b.Listen) == 0 {
					b.Listen = []Listen{{Addr: "*", Port: 80}}
				}
				c.Blocks = append(c.Blocks, b)
				bi = len(c.Blocks)
			}
			stack = append(stack, aframe{name: name, block: bi})
			continue
		}
		args := splitArgs(t)
		d := Directive{Name: strings.ToLower(args[0]), Args: args[1:], File: l.file, Line: l.line, Ctx: ctx(), Block: cur()}
		c.Directives = append(c.Directives, d)
		if d.Block > 0 {
			apacheSite(&c.Blocks[d.Block-1], d, len(stack) > 0 && stack[len(stack)-1].name == "virtualhost")
		}
	}
}

// apacheName strips a scheme and port from a ServerName value.
func apacheName(s string) string {
	if _, after, ok := strings.Cut(s, "://"); ok {
		s = after
	}
	if i := strings.LastIndexByte(s, ':'); i > 0 && !strings.Contains(s[i:], "]") {
		s = s[:i]
	}
	return s
}

func apacheSite(b *Block, d Directive, vhostLevel bool) {
	if len(d.Args) == 0 {
		return
	}
	switch d.Name {
	case "servername":
		if vhostLevel {
			b.Names = append([]string{apacheName(d.Args[0])}, b.Names...)
		}
	case "serveralias":
		if vhostLevel {
			b.Names = append(b.Names, d.Args...)
		}
	case "documentroot":
		if vhostLevel {
			b.Root = d.Args[0]
		}
	case "sslengine":
		if strings.EqualFold(d.Args[0], "on") {
			for i := range b.Listen {
				b.Listen[i].TLS = true
			}
		}
	case "sslcertificatefile":
		b.Certs = appendNew(b.Certs, d.Args[0])
	case "proxypass":
		if len(d.Args) > 1 && d.Args[1] != "!" {
			b.Upstreams = appendNew(b.Upstreams, d.Args[1])
		}
	case "sethandler":
		if strings.HasPrefix(strings.ToLower(d.Args[0]), "proxy:") {
			b.Upstreams = appendNew(b.Upstreams, d.Args[0])
			if strings.Contains(d.Args[0], "fcgi") || strings.Contains(d.Args[0], "php") {
				b.PHP = true
			}
		}
	case "customlog":
		if vhostLevel {
			b.AccessLog = d.Args[0]
		}
	}
}
