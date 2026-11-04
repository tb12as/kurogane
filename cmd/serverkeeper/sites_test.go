package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tb12as/serverman/internal/api"
	"github.com/tb12as/serverman/internal/sites"
	"github.com/tb12as/serverman/internal/webconf"
)

func TestSitesCLI(t *testing.T) {
	d := 9.5
	inv := api.SitesResponse{Enabled: true, Inventory: sites.Inventory{
		Servers: []sites.WebServer{{Kind: "nginx", Unit: "nginx", Version: "1.24.0", Active: true, ConfigOK: false,
			ConfigError: "[emerg] bad"}},
		Sites: []sites.Site{
			{ID: "nginx:/etc/nginx/sites-enabled/shop#0", Kind: "nginx", Name: "shop.example.org",
				Names: []string{"shop.example.org"}, Listen: []webconf.Listen{{Port: 443, TLS: true}}, Enabled: true,
				Toggle: "link", Upstreams: []string{"http://127.0.0.1:3000"}, File: "/etc/nginx/sites-enabled/shop", Line: 1,
				Certs: []string{"/etc/ssl/shop.pem"}, CertDays: &d, FileSites: 2},
			{ID: "nginx:/etc/nginx/sites-enabled/shop#1", Kind: "nginx", Name: "shop.example.org",
				Names: []string{"shop.example.org"}, Listen: []webconf.Listen{{Port: 80}}, Enabled: true, Toggle: "link",
				File: "/etc/nginx/sites-enabled/shop", Line: 9, FileSites: 2},
			{ID: "nginx:/etc/nginx/nginx.conf#0", Kind: "nginx", Name: "status.local", Names: []string{"status.local"},
				Root: "/srv/status", File: "/etc/nginx/nginx.conf", Line: 4, Enabled: true, NoToggle: "defined in nginx.conf", FileSites: 1},
		}}}
	var b bytes.Buffer
	printSites(&b, inv)
	for _, want := range []string{"nginx 1.24.0 (unit nginx active) · config test FAILS: [emerg] bad", "443/tls",
		"-> http://127.0.0.1:3000", "enabled (fixed)", "/etc/nginx/nginx.conf:4"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("list lacks %q:\n%s", want, b.String())
		}
	}
	if _, err := pickSite(inv, "shop.example.org"); err == nil || !strings.Contains(err.Error(), "#1") {
		t.Errorf("ambiguous name: %v", err)
	}
	s, err := pickSite(inv, "status.local")
	if err != nil {
		t.Fatal(err)
	}
	b.Reset()
	printSite(&b, s)
	if !strings.Contains(b.String(), "not managed: defined in nginx.conf") {
		t.Errorf("show:\n%s", b.String())
	}
	b.Reset()
	printSite(&b, inv.Sites[0])
	if !strings.Contains(b.String(), "9.5 days left") || !strings.Contains(b.String(), "2 site(s) in the file") {
		t.Errorf("show:\n%s", b.String())
	}
	if _, err := pickSite(inv, "nope"); err == nil {
		t.Error("unknown name")
	}
	if _, err := pickSite(api.SitesResponse{}, "x"); err == nil || !strings.Contains(err.Error(), "off") {
		t.Errorf("off: %v", err)
	}
	b.Reset()
	printPlan(&b, sites.Plan{Action: "disable", Site: s, Diff: "- a\n", Impact: []string{"Stops serving x."},
		Warnings: []string{"default site"}})
	if b.String() != "Disable status.local\n\n- a\n\n- Stops serving x.\n! default site\n" {
		t.Errorf("plan = %q", b.String())
	}
	b.Reset()
	printSites(&b, api.SitesResponse{Enabled: true})
	if !strings.Contains(b.String(), "no nginx or Apache") {
		t.Error(b.String())
	}
}
