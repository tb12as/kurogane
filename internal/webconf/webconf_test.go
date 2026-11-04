package webconf

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tb12as/serverman/internal/hostfs"
)

type fsReader struct{}

func (fsReader) ReadFile(p string) ([]byte, error) { return os.ReadFile(hostfs.P(p)) }

// tree writes files under a temp root; a value starting with "->" makes a symlink to the rest.
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

func TestTokenize(t *testing.T) {
	var got []string
	for _, tk := range tokenize([]byte("server { # c ; {\n ssl_certificate \"/a b.pem\";\n server_name x ';';}"), "f") {
		got = append(got, tk.s)
	}
	if strings.Join(got, "|") != "server|{|ssl_certificate|/a b.pem|;|server_name|x|;|;|}" {
		t.Fatal(got)
	}
	toks := tokenize([]byte("a;\n\n b\n  c;"), "f")
	if toks[2].line != 3 || toks[3].line != 4 {
		t.Fatalf("lines: %+v", toks)
	}
}

func TestParseListen(t *testing.T) {
	for in, want := range map[string]Listen{
		"80": {Port: 80}, "[::]:443": {Addr: "::", Port: 443}, "127.0.0.1:8080": {Addr: "127.0.0.1", Port: 8080},
		"*:443": {Addr: "*", Port: 443}, "_default_:443": {Addr: "*", Port: 443}, "example.com": {Addr: "example.com", Port: 80},
		"[::]": {Addr: "::", Port: 80},
	} {
		got, ok := ParseListen(in)
		if !ok || got != want {
			t.Errorf("ParseListen(%q) = %+v %v, want %+v", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "unix:/run/x.sock", "1.2.3.4:99999", "x:y"} {
		if _, ok := ParseListen(bad); ok {
			t.Errorf("ParseListen(%q) accepted", bad)
		}
	}
}

const nginxMain = `
user www-data;
events { worker_connections 768; }
stream { server { listen 3306; proxy_pass db; } }
http {
    server_tokens off;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_certificate certs/default.pem;
    include /etc/nginx/conf.d/*.conf;
    include sites-enabled/*;
}
`

func TestParseNginx(t *testing.T) {
	tree(t, map[string]string{
		"etc/nginx/nginx.conf": nginxMain,
		"etc/nginx/conf.d/api.conf": `server {
    listen 443 ssl http2;
    listen [::]:443 ssl;
    server_name api.example.com;
    ssl_certificate /etc/ssl/api.pem;
    location / { proxy_pass http://127.0.0.1:3000; autoindex on; }
}`,
		"etc/nginx/sites-available/default": `server {
	listen 80 default_server;
	server_name _;
	root /var/www/html;
}
server {
	server_name shop.example.org www.shop.example.org;
	root /srv/shop/public;
	access_log /var/log/nginx/shop.log;
	location ~ \.php$ { fastcgi_pass unix:/run/php/php8.3-fpm.sock; }
}`,
		"etc/nginx/sites-enabled/default": "->../sites-available/default",
	})
	c := ParseNginx(fsReader{})
	if c == nil {
		t.Fatal("nil config")
	}
	if len(c.Blocks) != 3 {
		t.Fatalf("blocks = %+v", c.Blocks)
	}
	api, def, shop := c.Blocks[0], c.Blocks[1], c.Blocks[2]
	if api.File != "/etc/nginx/conf.d/api.conf" || api.Line != 1 || api.Primary() != "api.example.com" ||
		!reflect.DeepEqual(api.Listen, []Listen{{Port: 443, TLS: true}, {Addr: "::", Port: 443, TLS: true}}) ||
		!reflect.DeepEqual(api.Upstreams, []string{"http://127.0.0.1:3000"}) || api.Certs[0] != "/etc/ssl/api.pem" {
		t.Errorf("api = %+v", api)
	}
	if def.File != "/etc/nginx/sites-enabled/default" || def.Index != 0 || def.Primary() != "_" || !def.Listen[0].Default ||
		def.Root != "/var/www/html" {
		t.Errorf("default = %+v", def)
	}
	if shop.Index != 1 || shop.Line != 6 || !shop.PHP || shop.Root != "/srv/shop/public" || len(shop.Names) != 2 ||
		shop.Listen[0].Port != 80 || shop.AccessLog != "/var/log/nginx/shop.log" {
		t.Errorf("shop = %+v", shop)
	}
	ai := c.Find("autoindex")
	if len(ai) != 1 || ai[0].Ctx != "http/server/location" || ai[0].Block != 1 || ai[0].Where() != "/etc/nginx/conf.d/api.conf:6" {
		t.Errorf("autoindex = %+v", ai)
	}
	if st := c.Find("server_tokens"); len(st) != 1 || st[0].Ctx != "http" || st[0].Block != 0 {
		t.Errorf("server_tokens = %+v", st)
	}
	if len(c.Files) != 3 {
		t.Errorf("files = %v", c.Files)
	}
	for _, d := range c.Find("listen") {
		if d.Args[0] == "3306" && d.Block != 0 {
			t.Error("stream server counted as a site")
		}
	}
}

func TestParseNginxFile(t *testing.T) {
	tree(t, map[string]string{"etc/nginx/conf.d/old.conf.disabled": "server { listen 8080; server_name old.example; }\n"})
	c, err := ParseNginxFile(fsReader{}, "/etc/nginx/conf.d/old.conf.disabled")
	if err != nil || len(c.Blocks) != 1 || c.Blocks[0].Primary() != "old.example" || c.Blocks[0].Listen[0].Port != 8080 {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := ParseNginxFile(fsReader{}, "/nope"); err == nil {
		t.Fatal("missing file parsed")
	}
	if ParseNginx(fsReader{}) != nil {
		t.Fatal("no nginx.conf must give nil")
	}
}

func TestParseApacheDebian(t *testing.T) {
	tree(t, map[string]string{
		"etc/apache2/apache2.conf": `# Debian layout
#ServerRoot "/etc/apache2"
Include ports.conf
<Directory /var/www/>
	Options Indexes FollowSymLinks
	AllowOverride None
</Directory>
IncludeOptional conf-enabled/*.conf
IncludeOptional sites-enabled/*.conf
`,
		"etc/apache2/ports.conf":                       "Listen 80\n<IfModule ssl_module>\n\tListen 443\n</IfModule>\n",
		"etc/apache2/conf-enabled/security.conf":       "ServerTokens OS\nServerSignature On\n",
		"etc/apache2/sites-available/000-default.conf": "<VirtualHost *:80>\n\tDocumentRoot /var/www/html\n</VirtualHost>\n",
		"etc/apache2/sites-available/shop.conf": `<VirtualHost *:443>
	ServerName https://shop.example.org:443
	ServerAlias www.shop.example.org \
		m.shop.example.org
	DocumentRoot "/srv/shop/public"
	SSLEngine on
	SSLCertificateFile /etc/letsencrypt/live/shop.example.org/fullchain.pem
	SSLProtocol all -SSLv3
	<FilesMatch \.php$>
		SetHandler "proxy:unix:/run/php/php8.3-fpm.sock|fcgi://localhost"
	</FilesMatch>
	ProxyPass /api http://127.0.0.1:3000/
	ProxyPass /static !
	CustomLog ${APACHE_LOG_DIR}/shop.log combined
</VirtualHost>
<VirtualHost *:80>
	ServerName shop.example.org
	Redirect permanent / https://shop.example.org/
</VirtualHost>
`,
		"etc/apache2/sites-enabled/000-default.conf": "->../sites-available/000-default.conf",
		"etc/apache2/sites-enabled/shop.conf":        "->../sites-available/shop.conf",
	})
	c := ParseApache(fsReader{})
	if c == nil || c.Root != "/etc/apache2" || ApacheRoot() != "/etc/apache2" {
		t.Fatalf("config = %+v", c)
	}
	if len(c.Blocks) != 3 {
		t.Fatalf("blocks = %+v", c.Blocks)
	}
	def, shop, redir := c.Blocks[0], c.Blocks[1], c.Blocks[2]
	if def.Primary() != "_" || def.Root != "/var/www/html" || def.Listen[0] != (Listen{Addr: "*", Port: 80}) {
		t.Errorf("default = %+v", def)
	}
	want := Block{Server: Apache, File: "/etc/apache2/sites-enabled/shop.conf", Line: 1, Index: 0,
		Names:     []string{"shop.example.org", "www.shop.example.org", "m.shop.example.org"},
		Listen:    []Listen{{Addr: "*", Port: 443, TLS: true}},
		Root:      "/srv/shop/public",
		Upstreams: []string{"proxy:unix:/run/php/php8.3-fpm.sock|fcgi://localhost", "http://127.0.0.1:3000/"},
		PHP:       true, Certs: []string{"/etc/letsencrypt/live/shop.example.org/fullchain.pem"},
		AccessLog: "${APACHE_LOG_DIR}/shop.log"}
	if !reflect.DeepEqual(shop, want) {
		t.Errorf("shop =\n%+v\nwant\n%+v", shop, want)
	}
	if redir.Index != 1 || redir.Line != 16 || redir.Listen[0].TLS {
		t.Errorf("redirect = %+v", redir)
	}
	if o := c.Find("options"); len(o) != 1 || o[0].Ctx != "directory" || o[0].Args[0] != "Indexes" || o[0].Block != 0 {
		t.Errorf("options = %+v", o)
	}
	if l := c.Find("listen"); len(l) != 2 || l[1].Ctx != "ifmodule" {
		t.Errorf("listen = %+v", l)
	}
	if st := c.Find("servertokens"); len(st) != 1 || st[0].Where() != "/etc/apache2/conf-enabled/security.conf:1" {
		t.Errorf("servertokens = %+v", st)
	}
}

func TestParseApacheRHEL(t *testing.T) {
	tree(t, map[string]string{
		"etc/httpd/conf/httpd.conf":             "ServerRoot \"/etc/httpd\"\nListen 80\nInclude conf.modules.d/*.conf\nIncludeOptional conf.d/*.conf\n",
		"etc/httpd/conf.modules.d/00-base.conf": "LoadModule mpm_event_module modules/mod_mpm_event.so\n",
		"etc/httpd/conf.d/blog.conf":            "<VirtualHost blog.example.net>\nServerName blog.example.net\n</VirtualHost>\n",
		"etc/httpd/conf.d/old.conf.disabled":    "<VirtualHost *:80>\nServerName old.example\n</VirtualHost>\n",
	})
	c := ParseApache(fsReader{})
	if c == nil || c.Root != "/etc/httpd" || len(c.Blocks) != 1 || c.Blocks[0].Primary() != "blog.example.net" {
		t.Fatalf("config = %+v", c)
	}
	d, err := ParseApacheFile(fsReader{}, "/etc/httpd", "/etc/httpd/conf.d/old.conf.disabled")
	if err != nil || len(d.Blocks) != 1 || d.Blocks[0].Primary() != "old.example" {
		t.Fatalf("disabled = %+v %v", d, err)
	}
	if _, err := ParseApacheFile(fsReader{}, "/etc/httpd", "/nope"); err == nil {
		t.Fatal("missing file parsed")
	}
}

func TestSplitArgs(t *testing.T) {
	got := splitArgs(`SetHandler "proxy:unix:/a b|fcgi://x" "" end`)
	if !reflect.DeepEqual(got, []string{"SetHandler", "proxy:unix:/a b|fcgi://x", "", "end"}) {
		t.Fatalf("%q", got)
	}
	if apacheName("https://x.example:8443") != "x.example" || apacheName("[::1]") != "[::1]" {
		t.Fatal("apacheName")
	}
}
