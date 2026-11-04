// Package webconf parses nginx and Apache configuration into sites (server blocks / virtual hosts) and
// directives with their file, line and context. It reads only; it never interprets variables, maps or macros,
// so anything it cannot understand is reported as-is rather than guessed.
package webconf

import (
	"path"
	"strconv"
	"strings"

	"github.com/tb12as/kurogane/internal/hostfs"
)

// Web server kinds.
const (
	Nginx  = "nginx"
	Apache = "apache"
)

// Reader reads host files (the agent passes its executor).
type Reader interface {
	ReadFile(path string) ([]byte, error)
}

// Listen is one address a site answers on.
type Listen struct {
	Addr    string `json:"addr,omitempty"` // "" or "*" = all addresses
	Port    int    `json:"port"`
	TLS     bool   `json:"tls"`
	Default bool   `json:"default,omitempty"` // nginx default_server
}

// Block is one nginx server{} or Apache <VirtualHost>.
type Block struct {
	Server    string   `json:"server"`
	File      string   `json:"file"`  // the path as included (a sites-enabled link keeps its link path)
	Line      int      `json:"line"`  // line of the block opening
	Index     int      `json:"index"` // position among the file's blocks, from 0
	Names     []string `json:"names,omitempty"`
	Listen    []Listen `json:"listen"`
	Root      string   `json:"root,omitempty"`
	Upstreams []string `json:"upstreams,omitempty"` // proxy_pass, fastcgi_pass, ProxyPass, proxy:fcgi handlers
	PHP       bool     `json:"php,omitempty"`
	Certs     []string `json:"certs,omitempty"`
	AccessLog string   `json:"access_log,omitempty"`
}

// Primary is the block's main name, "_" for a nameless catch-all.
func (b Block) Primary() string {
	for _, n := range b.Names {
		if n != "" && n != "_" {
			return n
		}
	}
	return "_"
}

// Directive is one directive with where it was found.
type Directive struct {
	Name  string   `json:"name"` // lower-cased
	Args  []string `json:"args"`
	File  string   `json:"file"`
	Line  int      `json:"line"`
	Ctx   string   `json:"ctx"`             // enclosing blocks, e.g. "http/server/location" or "virtualhost/directory"
	Block int      `json:"block,omitempty"` // index+1 into Config.Blocks, 0 outside any site
}

// Where formats file:line.
func (d Directive) Where() string { return d.File + ":" + strconv.Itoa(d.Line) }

// Config is a parsed web server configuration.
type Config struct {
	Server     string      `json:"server"`
	Root       string      `json:"root"` // /etc/nginx, /etc/apache2 or /etc/httpd
	Main       string      `json:"main"` // main config file
	Files      []string    `json:"files"`
	Blocks     []Block     `json:"blocks"`
	Directives []Directive `json:"-"`
}

// Find returns the directives named name (lower case).
func (c *Config) Find(name string) []Directive {
	var out []Directive
	for _, d := range c.Directives {
		if d.Name == name {
			out = append(out, d)
		}
	}
	return out
}

// abs resolves p against root.
func abs(root, p string) string {
	if path.IsAbs(p) {
		return path.Clean(p)
	}
	return path.Join(root, p)
}

// globber is a Reader that expands globs itself: the privsep executor does it as root, so includes into
// directories the worker cannot enter (a 0750 home holding Valet's sites) are still found.
type globber interface {
	Glob(pat string) []string
}

// glob expands an include pattern (hostfs.Glob semantics) through r when it can.
func glob(r Reader, pat string) []string {
	if g, ok := r.(globber); ok {
		return g.Glob(pat)
	}
	return hostfs.Glob(pat)
}

// ParseListen parses an nginx listen value or an Apache VirtualHost/Listen address.
func ParseListen(s string) (Listen, bool) {
	if s == "" || strings.HasPrefix(s, "unix:") {
		return Listen{}, false
	}
	if p, err := strconv.Atoi(s); err == nil {
		return Listen{Port: p}, p > 0 && p < 65536
	}
	host, port := s, ""
	if i := strings.LastIndexByte(s, ':'); i >= 0 && !strings.Contains(s[i:], "]") {
		host, port = s[:i], s[i+1:]
	}
	l := Listen{Addr: strings.Trim(host, "[]"), Port: 80}
	if port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p <= 0 || p > 65535 {
			return Listen{}, false
		}
		l.Port = p
	}
	if l.Addr == "_default_" {
		l.Addr = "*"
	}
	return l, true
}
