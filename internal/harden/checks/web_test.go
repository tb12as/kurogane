package checks

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/tb12as/kurogane/internal/executor"
)

func web(files map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range files {
		out[k] = v
	}
	return out
}

var (
	nginxGood = map[string]string{"/etc/nginx/nginx.conf": "http {\n server_tokens off;\n ssl_protocols TLSv1.2 TLSv1.3;\n" +
		" include /etc/nginx/conf.d/*.conf;\n}\n", "/etc/nginx/conf.d/a.conf": "server { listen 80; server_name a; }\n"}
	nginxBad = map[string]string{"/etc/nginx/nginx.conf": "http {\n ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n" +
		" include /etc/nginx/conf.d/*.conf;\n}\n",
		"/etc/nginx/conf.d/a.conf": "server { server_tokens on; location /f { autoindex on; } }\n"}
	apacheGood = map[string]string{"/etc/apache2/apache2.conf": "ServerTokens Prod\nServerSignature Off\n" +
		"SSLProtocol -all +TLSv1.2 +TLSv1.3\n<Directory /var/www/>\nOptions -Indexes +FollowSymLinks\n</Directory>\n"}
	apacheBad = map[string]string{"/etc/apache2/apache2.conf": "ServerSignature On\nSSLProtocol all -SSLv3\n" +
		"<Directory /var/www/>\nOptions Indexes FollowSymLinks\n</Directory>\n"}
)

func webCases() []scanCase {
	broken := map[string]error{"nginx -t": &executor.RunError{Cmd: "nginx -t", Stderr: "nginx: [emerg] bad"}}
	return []scanCase{
		{"pass", "WEB-CONFIG-VALID", Fixture{Files: web(nginxGood)}, Pass},
		{"fail", "WEB-CONFIG-VALID", Fixture{Files: web(nginxGood), Errs: broken}, Fail},
		{"none", "WEB-CONFIG-VALID", Fixture{}, NA},
		{"pass nginx", "WEB-SERVER-TOKENS", Fixture{Files: web(nginxGood)}, Pass},
		{"pass apache", "WEB-SERVER-TOKENS", Fixture{Files: web(apacheGood)}, Pass},
		{"fail nginx", "WEB-SERVER-TOKENS", Fixture{Files: web(nginxBad)}, Fail},
		{"fail apache", "WEB-SERVER-TOKENS", Fixture{Files: web(apacheBad)}, Fail},
		{"pass", "WEB-TLS-PROTOCOLS", Fixture{Files: web(nginxGood)}, Pass},
		{"defaults", "WEB-TLS-PROTOCOLS", Fixture{Files: map[string]string{"/etc/nginx/nginx.conf": "http {}\n"}}, Pass},
		{"pass apache", "WEB-TLS-PROTOCOLS", Fixture{Files: web(apacheGood)}, Pass},
		{"fail nginx", "WEB-TLS-PROTOCOLS", Fixture{Files: web(nginxBad)}, Fail},
		{"fail apache", "WEB-TLS-PROTOCOLS", Fixture{Files: web(apacheBad)}, Fail},
		{"pass", "WEB-DIR-LISTING", Fixture{Files: web(apacheGood)}, Pass},
		{"fail nginx", "WEB-DIR-LISTING", Fixture{Files: web(nginxBad)}, Fail},
		{"fail apache", "WEB-DIR-LISTING", Fixture{Files: web(apacheBad)}, Fail},
		{"none", "WEB-DIR-LISTING", Fixture{}, NA},
	}
}

func TestWebEvidence(t *testing.T) {
	e, _ := Setup(t, Fixture{Files: web(nginxBad)})
	run := func(id string) string { return find(e, id).Run(WithMemo(context.Background())).Evidence }
	if ev := run("WEB-SERVER-TOKENS"); !strings.Contains(ev, "server_tokens on at /etc/nginx/conf.d/a.conf:1") ||
		!strings.Contains(ev, "no `server_tokens off;`") {
		t.Errorf("tokens = %q", ev)
	}
	if ev := run("WEB-TLS-PROTOCOLS"); ev != "ssl_protocols allows TLSv1, TLSv1.1 at /etc/nginx/nginx.conf:2" {
		t.Errorf("protocols = %q", ev)
	}
	if ev := run("WEB-DIR-LISTING"); ev != "autoindex on at /etc/nginx/conf.d/a.conf:1" {
		t.Errorf("listing = %q", ev)
	}
	e.WebOff = true
	if r := find(e, "WEB-DIR-LISTING").Run(WithMemo(context.Background())); r.Status != NA {
		t.Fatalf("disabled: %+v", r)
	}
}

func TestWeakProtocols(t *testing.T) {
	for _, tc := range []struct {
		name string
		args string
		want []string
	}{
		{"sslprotocol", "all -SSLv3", []string{"TLSv1", "TLSv1.1"}},
		{"sslprotocol", "-all +TLSv1.2 +TLSv1.3", nil},
		{"sslprotocol", "all -TLSv1 -TLSv1.1", nil},
		{"sslprotocol", "+SSLv3 +TLSv1.2", []string{"SSLv3"}},
		{"ssl_protocols", "TLSv1.2 TLSv1.3", nil},
		{"ssl_protocols", "SSLv3 TLSv1.2", []string{"SSLv3"}},
	} {
		if got := weakProtocols(tc.name, strings.Fields(tc.args)); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s %s = %v, want %v", tc.name, tc.args, got, tc.want)
		}
	}
}
