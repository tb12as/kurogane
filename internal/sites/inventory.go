// Package sites inventories the nginx and Apache sites on the host and enables or disables them safely: a
// toggle only moves a link or renames a file, is validated with the server's own config test, and is undone
// automatically if the reload fails or a site that answered before stops answering.
package sites

import (
	"context"
	"errors"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tb12as/serverman/internal/executor"
	"github.com/tb12as/serverman/internal/hostfs"
	"github.com/tb12as/serverman/internal/webconf"
)

// Toggle methods.
const (
	ToggleLink   = "link"   // Debian sites-available / sites-enabled
	ToggleRename = "rename" // conf.d X.conf <-> X.conf.disabled
)

// DisabledSuffix marks a conf.d file switched off by renaming.
const DisabledSuffix = ".disabled"

// layout is one place where toggleable site files live.
type layout struct {
	kind      string
	method    string
	enabled   string // dir of enabled files (links for ToggleLink)
	available string // ToggleLink only
}

var layouts = []layout{
	{webconf.Nginx, ToggleLink, "/etc/nginx/sites-enabled", "/etc/nginx/sites-available"},
	{webconf.Nginx, ToggleRename, "/etc/nginx/conf.d", ""},
	{webconf.Apache, ToggleLink, "/etc/apache2/sites-enabled", "/etc/apache2/sites-available"},
	{webconf.Apache, ToggleRename, "/etc/httpd/conf.d", ""},
}

// WebServer is one installed web server.
type WebServer struct {
	Kind        string    `json:"kind"` // nginx | apache
	Unit        string    `json:"unit"` // nginx, apache2 or httpd
	Root        string    `json:"root"`
	Main        string    `json:"main"`
	Version     string    `json:"version,omitempty"`
	Active      bool      `json:"active"`
	ConfigOK    bool      `json:"config_ok"`
	ConfigError string    `json:"config_error,omitempty"`
	TestedAt    time.Time `json:"tested_at,omitzero"`
	Files       int       `json:"files"`
}

// Site is one server block or virtual host.
type Site struct {
	ID        string           `json:"id"` // kind:file#index, stable across scans while the file stays
	Kind      string           `json:"kind"`
	Name      string           `json:"name"`
	Names     []string         `json:"names,omitempty"`
	Listen    []webconf.Listen `json:"listen"`
	Root      string           `json:"root,omitempty"`
	Upstreams []string         `json:"upstreams,omitempty"`
	PHP       bool             `json:"php,omitempty"`
	Certs     []string         `json:"certs,omitempty"`
	CertDays  *float64         `json:"cert_days,omitempty"` // soonest expiry of its certificates
	AccessLog string           `json:"access_log,omitempty"`
	File      string           `json:"file"`
	Line      int              `json:"line"`
	Enabled   bool             `json:"enabled"`
	Default   bool             `json:"default,omitempty"`
	Toggle    string           `json:"toggle,omitempty"`    // link | rename, "" when ServerKeeper will not toggle it
	NoToggle  string           `json:"no_toggle,omitempty"` // why not
	FileSites int              `json:"file_sites"`          // sites in the same file: a toggle switches them all
	Available string           `json:"available,omitempty"` // ToggleLink: the sites-available file
}

// Inventory is the result of one scan.
type Inventory struct {
	Servers   []WebServer `json:"servers"`
	Sites     []Site      `json:"sites"`
	ScannedAt time.Time   `json:"scanned_at,omitzero"`
}

// Site returns the site with id.
func (inv Inventory) Site(id string) (Site, bool) {
	for _, s := range inv.Sites {
		if s.ID == id {
			return s, true
		}
	}
	return Site{}, false
}

// Server returns the web server of kind.
func (inv Inventory) Server(kind string) (WebServer, bool) {
	for _, s := range inv.Servers {
		if s.Kind == kind {
			return s, true
		}
	}
	return WebServer{}, false
}

// Find returns sites whose id or any name equals q (case-insensitive).
func (inv Inventory) Find(q string) []Site {
	var out []Site
	for _, s := range inv.Sites {
		if s.ID == q {
			return []Site{s}
		}
		for _, n := range s.Names {
			if strings.EqualFold(n, q) {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

func siteID(kind, file string, index int) string {
	return kind + ":" + file + "#" + strconv.Itoa(index)
}

// unitFor returns the systemd unit of a web server.
func unitFor(kind, root string) string {
	switch {
	case kind == webconf.Nginx:
		return webconf.Nginx
	case root == "/etc/httpd":
		return "httpd"
	}
	return "apache2"
}

// Units returns the systemd units of the web servers configured on this host (for the service watch).
func Units() []string {
	var out []string
	if hostfs.Exists(webconf.NginxMain) {
		out = append(out, webconf.Nginx)
	}
	if r := webconf.ApacheRoot(); r != "" {
		out = append(out, unitFor(webconf.Apache, r))
	}
	return out
}

// inventory parses both web servers; config test and version are filled in by the Manager.
func inventory(r webconf.Reader) Inventory {
	var inv Inventory
	for _, c := range []*webconf.Config{webconf.ParseNginx(r), webconf.ParseApache(r)} {
		if c == nil {
			continue
		}
		inv.Servers = append(inv.Servers, WebServer{Kind: c.Server, Unit: unitFor(c.Server, c.Root), Root: c.Root,
			Main: c.Main, Files: len(c.Files)})
		inv.Sites = append(inv.Sites, enabledSites(c)...)
		inv.Sites = append(inv.Sites, disabledSites(r, c)...)
	}
	return inv
}

// enabledSites turns the blocks of the running config into sites with their toggle method.
func enabledSites(c *webconf.Config) []Site {
	perFile := map[string]int{}
	global := map[string]string{} // file -> first directive outside any site
	for _, b := range c.Blocks {
		perFile[b.File]++
	}
	for _, d := range c.Directives {
		if d.Block == 0 {
			if _, ok := global[d.File]; !ok {
				global[d.File] = describeGlobal(d)
			}
		}
	}
	defaults := map[int]bool{} // Apache: the first vhost per port is the default
	var out []Site
	for _, b := range c.Blocks {
		s := fromBlock(c.Server, b)
		s.Enabled, s.FileSites = true, perFile[b.File]
		if c.Server == webconf.Apache {
			for _, l := range b.Listen {
				if !defaults[l.Port] {
					defaults[l.Port], s.Default = true, true
				}
			}
		}
		s.Toggle, s.Available, s.NoToggle = toggleFor(c.Server, b.File, true)
		if g, ok := global[b.File]; ok && s.Toggle != "" {
			s.Toggle, s.Available = "", ""
			s.NoToggle = "the file also holds settings outside any site (" + g + "), which other sites may need"
		}
		out = append(out, s)
	}
	return out
}

// describeGlobal names a directive outside any site: the enclosing nginx block (upstream, map...) when there
// is one, else the directive itself.
func describeGlobal(d webconf.Directive) string {
	ctx := strings.TrimPrefix(strings.TrimPrefix(d.Ctx, "http"), "/")
	what := d.Name
	if blk, _, _ := strings.Cut(ctx, "/"); blk != "" && blk != "ifmodule" && blk != "ifdefine" {
		what = blk + " block"
	}
	return what + " (line " + strconv.Itoa(d.Line) + ")"
}

func fromBlock(kind string, b webconf.Block) Site {
	s := Site{ID: siteID(kind, b.File, b.Index), Kind: kind, Name: b.Primary(), Names: b.Names, Listen: b.Listen,
		Root: b.Root, Upstreams: b.Upstreams, PHP: b.PHP, Certs: b.Certs, AccessLog: b.AccessLog, File: b.File,
		Line: b.Line}
	for _, l := range b.Listen {
		s.Default = s.Default || l.Default
	}
	return s
}

// toggleFor reports how a site file can be toggled, its sites-available file, or why it cannot.
func toggleFor(kind, file string, enabled bool) (method, available, why string) {
	dir, base := path.Dir(file), path.Base(file)
	for _, l := range layouts {
		if l.kind != kind {
			continue
		}
		switch {
		case l.method == ToggleLink && enabled && dir == l.enabled:
			fi, err := os.Lstat(hostfs.P(file))
			if err != nil || fi.Mode()&os.ModeSymlink == 0 {
				return "", "", "a regular file in " + l.enabled + ": move it to " + l.available + " and link it"
			}
			t, err := os.Readlink(hostfs.P(file))
			if err != nil {
				return "", "", err.Error()
			}
			if !path.IsAbs(t) {
				t = path.Join(dir, t)
			}
			if path.Dir(path.Clean(t)) != l.available {
				return "", "", "the link points outside " + l.available
			}
			return ToggleLink, path.Clean(t), ""
		case l.method == ToggleLink && !enabled && dir == l.available:
			return ToggleLink, file, ""
		case l.method == ToggleRename && dir == l.enabled && strings.HasSuffix(base, ".conf") == enabled &&
			strings.HasSuffix(base, ".conf"+DisabledSuffix) == !enabled:
			return ToggleRename, "", ""
		}
	}
	return "", "", "defined in " + file + "; ServerKeeper toggles only files in sites-enabled/sites-available or conf.d"
}

// disabledSites parses site files that the running config does not include.
func disabledSites(r webconf.Reader, c *webconf.Config) []Site {
	included := map[string]bool{}
	for _, f := range c.Files {
		included[f] = true
	}
	linked := map[string]bool{} // sites-available files some link points to
	var out []Site
	for _, l := range layouts {
		if l.kind != c.Server {
			continue
		}
		if l.method == ToggleLink {
			ents, _ := os.ReadDir(hostfs.P(l.enabled))
			for _, e := range ents {
				if t, err := os.Readlink(hostfs.P(l.enabled + "/" + e.Name())); err == nil {
					if !path.IsAbs(t) {
						t = path.Join(l.enabled, t)
					}
					linked[path.Clean(t)] = true
				}
			}
		}
		dir := l.available
		if l.method == ToggleRename {
			dir = l.enabled
		}
		ents, _ := os.ReadDir(hostfs.P(dir))
		for _, e := range ents {
			f := dir + "/" + e.Name()
			if e.IsDir() || included[f] || linked[f] {
				continue
			}
			if l.method == ToggleRename && !strings.HasSuffix(e.Name(), ".conf"+DisabledSuffix) {
				continue
			}
			if c.Server == webconf.Apache && l.method == ToggleLink && !strings.HasSuffix(e.Name(), ".conf") {
				continue // Debian Apache includes sites-enabled/*.conf only
			}
			out = append(out, parseDisabled(r, c, f)...)
		}
	}
	return out
}

func parseDisabled(r webconf.Reader, c *webconf.Config, f string) []Site {
	var dc *webconf.Config
	var err error
	if c.Server == webconf.Nginx {
		dc, err = webconf.ParseNginxFile(r, f)
	} else {
		dc, err = webconf.ParseApacheFile(r, c.Root, f)
	}
	if err != nil {
		return nil
	}
	global := ""
	for _, d := range dc.Directives {
		if d.Block == 0 && d.File == f {
			global = describeGlobal(d)
			break
		}
	}
	var out []Site
	for _, b := range dc.Blocks {
		if b.File != f {
			continue
		}
		s := fromBlock(c.Server, b)
		s.FileSites = len(dc.Blocks)
		s.Toggle, s.Available, s.NoToggle = toggleFor(c.Server, f, false)
		if global != "" && s.Toggle != "" {
			s.Toggle, s.Available = "", ""
			s.NoToggle = "the file also holds settings outside any site (" + global + "), which other sites may need"
		}
		out = append(out, s)
	}
	return out
}

// configTest runs the server's own syntax check; ok with "" or the error output.
func configTest(ctx context.Context, ex executor.Executor, kind string) (bool, string) {
	var err error
	if kind == webconf.Nginx {
		_, err = ex.Run(ctx, "nginx", "-t")
	} else {
		_, err = ex.Run(ctx, "apachectl", "configtest")
	}
	// not installed (config left behind) or the agent is not root: the test cannot say anything, skip it
	if err == nil || executor.CannotRun(err) {
		return true, ""
	}
	var re *executor.RunError
	if errors.As(err, &re) && re.Stderr != "" {
		return false, trimTest(re.Stderr)
	}
	return false, err.Error()
}

// logPrefix is nginx's error-log stamp ("2026/11/04 04:19:20 [emerg] 14193#14193: "), kept to "[emerg] ".
var logPrefix = regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (\[\w+\]) \d+#\d+: `)

// trimTest keeps the lines of a config test that explain the failure.
func trimTest(s string) string {
	var keep []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.Contains(l, "test failed") || strings.Contains(l, "syntax is ok") {
			continue
		}
		l = strings.TrimPrefix(l, "nginx: ")
		keep = append(keep, logPrefix.ReplaceAllString(l, "$1 "))
	}
	if len(keep) == 0 {
		return strings.TrimSpace(s)
	}
	return strings.Join(keep, "; ")
}

// version asks the package manager for the installed web server version.
func version(ctx context.Context, ex executor.Executor, w WebServer) string {
	pkgs := map[string][]string{"nginx": {"nginx", "nginx-core", "nginx-full", "nginx-light"},
		"apache2": {"apache2"}, "httpd": {"httpd"}}[w.Unit]
	rpm := hostfs.DetectDistro().PkgMgr == "dnf"
	for _, p := range pkgs {
		if rpm {
			if b, err := ex.Run(ctx, "rpm", "-q", "--qf", "%{VERSION}", p); err == nil && len(b) > 0 {
				return strings.TrimSpace(string(b))
			}
			continue
		}
		b, err := ex.Run(ctx, "dpkg-query", "-W", "-f=${Version}", p)
		if v := strings.TrimSpace(string(b)); err == nil && v != "" {
			return v
		}
	}
	return ""
}

// sortSites orders by kind, then enabled first, then name.
func sortSites(s []Site) {
	sort.SliceStable(s, func(i, j int) bool {
		if s[i].Kind != s[j].Kind {
			return s[i].Kind > s[j].Kind // nginx before apache
		}
		if s[i].Enabled != s[j].Enabled {
			return s[i].Enabled
		}
		return s[i].Name < s[j].Name
	})
}
