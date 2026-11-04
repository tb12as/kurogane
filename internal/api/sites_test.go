package api

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/tb12as/serverman/internal/auth"
	"github.com/tb12as/serverman/internal/db"
	"github.com/tb12as/serverman/internal/executor"
	"github.com/tb12as/serverman/internal/hostfs"
	"github.com/tb12as/serverman/internal/sites"
)

func TestSitesRoutes(t *testing.T) {
	st := newStack(t)
	// without a sites manager the list says "off" and actions answer 503
	var off SitesResponse
	json.Unmarshal(st.do("GET", "/api/v1/sites", st.read, nil, 200), &off)
	if off.Enabled || off.Sites == nil {
		t.Fatalf("off = %+v", off)
	}
	st.do("POST", "/api/v1/sites/plan", st.read, SiteToggle{ID: "x"}, 503)

	fixture(t, hostfs.Root, map[string]string{
		"/etc/nginx/nginx.conf":               "http { include /etc/nginx/conf.d/*.conf; }\n",
		"/etc/nginx/conf.d/shop.conf":         "server { listen 1; server_name shop.example.org; }\n",
		"/etc/nginx/conf.d/old.conf.disabled": "server { listen 1; server_name old.example.org; }\n",
	})
	st.srv.Sites = sites.New(sites.Deps{Ex: st.srv.Ex, DB: st.srv.DB, Audit: st.srv.Audit})
	st.srv.Sites.Scan(context.Background(), true)
	opTok, _, _ := st.srv.Auth.CreateToken(context.Background(), "op", []string{auth.ScopeRead, auth.ScopeWeb}, "test", 0)

	var inv SitesResponse
	json.Unmarshal(st.do("GET", "/api/v1/sites", st.read, nil, 200), &inv)
	if !inv.Enabled || len(inv.Sites) != 2 || len(inv.Servers) != 1 || !inv.Servers[0].ConfigOK {
		t.Fatalf("inventory = %+v", inv)
	}
	id := "nginx:/etc/nginx/conf.d/shop.conf#0"

	var p sites.Plan
	json.Unmarshal(st.do("POST", "/api/v1/sites/plan", st.read, SiteToggle{ID: id}, 200), &p)
	if p.Action != "disable" || !strings.Contains(p.Diff, "shop.conf.disabled") {
		t.Fatalf("plan = %+v", p)
	}
	st.do("POST", "/api/v1/sites/plan", st.read, SiteToggle{}, 400)
	st.do("POST", "/api/v1/sites/plan", st.read, SiteToggle{ID: "nope"}, 404)
	st.do("POST", "/api/v1/sites/plan", st.read, SiteToggle{ID: id, Enabled: true}, 409)

	// scopes: read can look, not act or read raw config
	st.do("POST", "/api/v1/sites/apply", st.read, SiteToggle{ID: id}, 403)
	st.do("GET", "/api/v1/sites/config?id="+id, st.read, nil, 403)
	var cfg map[string]string
	json.Unmarshal(st.do("GET", "/api/v1/sites/config?id="+strings.ReplaceAll(id, "#", "%23"), opTok, nil, 200), &cfg)
	if cfg["file"] != "/etc/nginx/conf.d/shop.conf" || !strings.Contains(cfg["content"], "shop.example.org") {
		t.Fatalf("config = %v", cfg)
	}

	var ch db.SiteChange
	json.Unmarshal(st.do("POST", "/api/v1/sites/apply", opTok, SiteToggle{ID: id}, 200), &ch)
	if ch.Status != "applied" || ch.Actor == "" {
		t.Fatalf("change = %+v", ch)
	}
	if _, err := os.Stat(hostfs.P("/etc/nginx/conf.d/shop.conf.disabled")); err != nil {
		t.Fatal("not renamed")
	}
	var cs []db.SiteChange
	json.Unmarshal(st.do("GET", "/api/v1/sites/changes", st.read, nil, 200), &cs)
	if len(cs) != 1 {
		t.Fatalf("changes = %+v", cs)
	}
	st.do("POST", "/api/v1/web/nginx/reload", opTok, nil, 200)
	st.do("POST", "/api/v1/web/apache/reload", opTok, nil, 404)
	json.Unmarshal(st.do("POST", "/api/v1/sites/rescan", st.admin, nil, 200), &inv)
	if len(inv.Sites) != 2 {
		t.Fatalf("rescan = %+v", inv)
	}
	// a failing apply maps to 422 with the reason
	st.srv.Ex.(*executor.Fake).Errors["systemctl reload nginx"] = &executor.RunError{Cmd: "systemctl", Stderr: "Job failed"}
	body := st.do("POST", "/api/v1/sites/apply", opTok, SiteToggle{ID: "nginx:/etc/nginx/conf.d/old.conf.disabled#0",
		Enabled: true}, 422)
	if !strings.Contains(string(body), "Job failed") {
		t.Fatalf("422 body = %s", body)
	}
	if _, err := os.Stat(hostfs.P("/etc/nginx/conf.d/old.conf.disabled")); err != nil {
		t.Fatal("failed enable was not undone")
	}
}
