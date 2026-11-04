package sites

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tb12as/kurogane/internal/alert"
	"github.com/tb12as/kurogane/internal/certs"
	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/hostfs"
)

var ctx = context.Background()

// tree writes files under a temp host root; a value starting with "->" makes a symlink to the rest.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	old := hostfs.Root
	hostfs.Root = dir
	t.Cleanup(func() { hostfs.Root = old })
	for p, c := range files {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if target, ok := strings.CutPrefix(c, "->"); ok {
			if err := os.Symlink(target, full); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// debianNginx is a Debian nginx host with every toggle case.
var debianNginx = map[string]string{
	"etc/os-release": "ID=ubuntu\nVERSION_ID=\"24.04\"\n",
	"etc/nginx/nginx.conf": `events {}
http {
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
    server { listen 8081; server_name status.local; }
}`,
	"etc/nginx/sites-available/default":     "server {\n listen 80 default_server;\n server_name _;\n root /var/www/html;\n}\n",
	"etc/nginx/sites-available/shop":        "server { listen 443 ssl; server_name shop.example.org; ssl_certificate /etc/ssl/shop.pem; }\nserver { listen 80; server_name shop.example.org; }\n",
	"etc/nginx/sites-available/old":         "server { listen 80; server_name old.example.org; }\n",
	"etc/nginx/sites-available/notes.txt":   "not a site",
	"etc/nginx/sites-enabled/default":       "->../sites-available/default",
	"etc/nginx/sites-enabled/shop":          "->../sites-available/shop",
	"etc/nginx/sites-enabled/local":         "server { listen 80; server_name local.example; }\n",
	"etc/nginx/conf.d/api.conf":             "server { listen 80; server_name api.example.com; location / { proxy_pass http://127.0.0.1:3000; } }\n",
	"etc/nginx/conf.d/pool.conf":            "upstream app { server 127.0.0.1:9000; }\nserver { listen 80; server_name app.example.com; location / { proxy_pass http://app; } }\n",
	"etc/nginx/conf.d/legacy.conf.disabled": "server { listen 80; server_name legacy.example.com; }\n",
}

func byName(inv Inventory) map[string]Site {
	m := map[string]Site{}
	for _, s := range inv.Sites {
		m[s.Name] = s
	}
	return m
}

func TestInventoryDebianNginx(t *testing.T) {
	tree(t, debianNginx)
	inv := inventory(executor.NewFake())
	if len(inv.Servers) != 1 || inv.Servers[0].Unit != "nginx" || inv.Servers[0].Files != 6 {
		t.Fatalf("servers = %+v", inv.Servers)
	}
	by := byName(inv)
	if len(inv.Sites) != 9 {
		t.Fatalf("%d sites: %v", len(inv.Sites), by)
	}
	for name, want := range map[string]struct {
		enabled       bool
		toggle, avail string
		noToggle      string
		fileSites     int
	}{
		"_":                  {true, ToggleLink, "/etc/nginx/sites-available/default", "", 1},
		"shop.example.org":   {true, ToggleLink, "/etc/nginx/sites-available/shop", "", 2},
		"old.example.org":    {false, ToggleLink, "/etc/nginx/sites-available/old", "", 1},
		"local.example":      {true, "", "", "a regular file in /etc/nginx/sites-enabled", 1},
		"api.example.com":    {true, ToggleRename, "", "", 1},
		"app.example.com":    {true, "", "", "settings outside any site (upstream block (line 1))", 1},
		"legacy.example.com": {false, ToggleRename, "", "", 1},
		"status.local":       {true, "", "", "defined in /etc/nginx/nginx.conf", 1},
	} {
		s, ok := by[name]
		if !ok {
			t.Errorf("%s missing", name)
			continue
		}
		if s.Enabled != want.enabled || s.Toggle != want.toggle || s.Available != want.avail ||
			!strings.Contains(s.NoToggle, want.noToggle) || (want.noToggle == "" && s.NoToggle != "") ||
			s.FileSites != want.fileSites {
			t.Errorf("%s = %+v", name, s)
		}
	}
	if s := by["_"]; !s.Default || s.ID != "nginx:/etc/nginx/sites-enabled/default#0" || s.Root != "/var/www/html" {
		t.Errorf("default = %+v", s)
	}
	if s := by["old.example.org"]; s.ID != "nginx:/etc/nginx/sites-available/old#0" || s.File != "/etc/nginx/sites-available/old" {
		t.Errorf("disabled id = %+v", s)
	}
	if got := inv.Find("SHOP.example.org"); len(got) != 2 {
		t.Errorf("Find = %+v", got)
	}
	if s, ok := inv.Site("nginx:/etc/nginx/conf.d/api.conf#0"); !ok || s.Name != "api.example.com" {
		t.Errorf("Site = %+v", s)
	}
	if u := Units(); len(u) != 1 || u[0] != "nginx" {
		t.Errorf("units = %v", u)
	}
}

func TestInventoryApache(t *testing.T) {
	tree(t, map[string]string{
		"etc/apache2/apache2.conf":                     "IncludeOptional sites-enabled/*.conf\n",
		"etc/apache2/sites-available/000-default.conf": "<VirtualHost *:80>\nDocumentRoot /var/www/html\n</VirtualHost>\n",
		"etc/apache2/sites-available/blog.conf":        "<VirtualHost *:80>\nServerName blog.example.net\n</VirtualHost>\n",
		"etc/apache2/sites-available/default-ssl.conf": "<IfModule mod_ssl.c>\n<VirtualHost _default_:443>\nServerName secure.example\nSSLEngine on\n</VirtualHost>\n</IfModule>\n",
		"etc/apache2/sites-available/README":           "<VirtualHost *:80>\nServerName ignored\n</VirtualHost>\n",
		"etc/apache2/sites-enabled/000-default.conf":   "->../sites-available/000-default.conf",
		"etc/apache2/sites-enabled/blog.conf":          "->../sites-available/blog.conf",
	})
	inv := inventory(executor.NewFake())
	by := byName(inv)
	if len(inv.Sites) != 3 || inv.Servers[0].Unit != "apache2" {
		t.Fatalf("inv = %+v", inv)
	}
	if s := by["_"]; !s.Enabled || !s.Default || s.Toggle != ToggleLink {
		t.Errorf("default = %+v", s)
	}
	if s := by["blog.example.net"]; !s.Enabled || s.Default || s.Available != "/etc/apache2/sites-available/blog.conf" {
		t.Errorf("blog = %+v", s)
	}
	if s := by["secure.example"]; s.Enabled || s.Toggle != ToggleLink || !s.Listen[0].TLS {
		t.Errorf("ssl = %+v", s)
	}
}

func TestInventoryRHEL(t *testing.T) {
	tree(t, map[string]string{
		"etc/os-release":                     "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n",
		"etc/httpd/conf/httpd.conf":          "ServerRoot \"/etc/httpd\"\nIncludeOptional conf.d/*.conf\n",
		"etc/httpd/conf.d/ssl.conf":          "Listen 443 https\n<VirtualHost _default_:443>\nSSLEngine on\n</VirtualHost>\n",
		"etc/httpd/conf.d/shop.conf":         "<VirtualHost *:80>\nServerName shop.example.org\n</VirtualHost>\n",
		"etc/httpd/conf.d/old.conf.disabled": "<VirtualHost *:80>\nServerName old.example.org\n</VirtualHost>\n",
		"etc/nginx/nginx.conf":               "http { include /etc/nginx/conf.d/*.conf; }\n",
		"etc/nginx/conf.d/app.conf":          "server { listen 8080; server_name app.example.com; }\n",
	})
	inv := inventory(executor.NewFake())
	by := byName(inv)
	if len(inv.Servers) != 2 || inv.Servers[1].Unit != "httpd" || len(inv.Sites) != 4 {
		t.Fatalf("inv = %+v", inv)
	}
	if s := by["_"]; s.Toggle != "" || !strings.Contains(s.NoToggle, "listen (line 1)") {
		t.Errorf("ssl.conf must not be toggleable: %+v", s)
	}
	if s := by["shop.example.org"]; s.Toggle != ToggleRename || !s.Enabled {
		t.Errorf("shop = %+v", s)
	}
	if s := by["old.example.org"]; s.Toggle != ToggleRename || s.Enabled || s.File != "/etc/httpd/conf.d/old.conf.disabled" {
		t.Errorf("old = %+v", s)
	}
	if s := by["app.example.com"]; s.Toggle != ToggleRename {
		t.Errorf("app = %+v", s)
	}
	if u := Units(); strings.Join(u, ",") != "nginx,httpd" {
		t.Errorf("units = %v", u)
	}
}

type fired struct{ evs []alert.Event }

func (f *fired) fire(_ context.Context, e alert.Event) { f.evs = append(f.evs, e) }

func TestManagerScan(t *testing.T) {
	tree(t, debianNginx)
	ex := executor.NewFake()
	ex.Outputs["dpkg-query -W -f=${Version} nginx"] = "1.24.0-2ubuntu7"
	ex.Errors["nginx -t"] = &executor.RunError{Cmd: "nginx -t", Stderr: "nginx: [emerg] unknown directive \"servr\" in " +
		"/etc/nginx/sites-enabled/shop:3\nnginx: configuration file /etc/nginx/nginx.conf test failed"}
	f := &fired{}
	now := time.Unix(1_800_000_000, 0)
	m := New(Deps{Ex: ex, Fire: f.fire, Now: func() time.Time { return now },
		Certs: func() []certs.Cert { return []certs.Cert{{Path: "/etc/ssl/shop.pem", DaysLeft: 12.34}} }})

	inv := m.Scan(ctx, true)
	w := inv.Servers[0]
	if w.ConfigOK || w.ConfigError != `[emerg] unknown directive "servr" in /etc/nginx/sites-enabled/shop:3` ||
		!w.Active || w.Version != "1.24.0-2ubuntu7" || !w.TestedAt.Equal(now) {
		t.Fatalf("server = %+v", w)
	}
	if len(f.evs) != 0 {
		t.Fatal("one failing test must not alert yet")
	}
	shop := inv.Find("shop.example.org")
	if len(shop) != 2 || shop[0].CertDays == nil || *shop[0].CertDays != 12.3 {
		t.Fatalf("cert days = %+v", shop)
	}
	// a scan without the test keeps the last test result
	if inv := m.Scan(ctx, false); inv.Servers[0].ConfigOK || inv.Servers[0].Version == "" {
		t.Fatalf("untested scan lost state: %+v", inv.Servers[0])
	}
	m.Scan(ctx, true)
	if len(f.evs) != 1 || f.evs[0].Rule != "web_config_invalid" || f.evs[0].Resolve ||
		!strings.Contains(f.evs[0].Text, "unknown directive") || f.evs[0].Labels["server"] != "nginx" {
		t.Fatalf("events = %+v", f.evs)
	}
	delete(ex.Errors, "nginx -t")
	m.Scan(ctx, true)
	if len(f.evs) != 2 || !f.evs[1].Resolve {
		t.Fatalf("want resolve: %+v", f.evs)
	}

	ss, _ := m.Collect(ctx)
	got := map[string]float64{}
	for _, s := range ss {
		got[s.Key()] = s.Value
	}
	if got[`web.config_ok{server="nginx"}`] != 1 || got[`web.sites{server="nginx",state="enabled"}`] != 7 ||
		got[`web.sites{server="nginx",state="disabled"}`] != 2 {
		t.Fatalf("samples = %v", got)
	}
}

func TestVersionRPMAndTrim(t *testing.T) {
	tree(t, map[string]string{"etc/os-release": "ID=\"rocky\"\nID_LIKE=\"rhel\"\n"})
	ex := executor.NewFake()
	ex.Outputs["rpm -q --qf %{VERSION} httpd"] = "2.4.62"
	if v := version(ctx, ex, WebServer{Unit: "httpd"}); v != "2.4.62" {
		t.Fatalf("version = %q", v)
	}
	if got := trimTest("2026/11/04 04:19:20 [emerg] 14193#14193: unknown directive \"x\" in /etc/nginx/a:4\n" +
		"nginx: configuration file /etc/nginx/nginx.conf test failed\n"); got != `[emerg] unknown directive "x" in /etc/nginx/a:4` {
		t.Fatalf("trimTest = %q", got)
	}
	if trimTest("AH00526: Syntax error on line 3\n") != "AH00526: Syntax error on line 3" || trimTest("\n") != "" {
		t.Fatal("trimTest")
	}
}
