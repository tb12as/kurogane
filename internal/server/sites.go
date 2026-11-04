package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/tb12as/serverman/internal/api"
	"github.com/tb12as/serverman/internal/db"
)

// fleetSiteData mirrors pb.Sites as stored by protojson (proto field names).
type fleetSiteData struct {
	Servers []struct {
		Kind        string `json:"kind"`
		Unit        string `json:"unit"`
		Version     string `json:"version"`
		Active      bool   `json:"active"`
		ConfigOK    bool   `json:"config_ok"`
		ConfigError string `json:"config_error"`
	} `json:"servers"`
	Sites []struct {
		ID          string   `json:"id"`
		Kind        string   `json:"kind"`
		Name        string   `json:"name"`
		Names       []string `json:"names"`
		Ports       []int    `json:"ports"`
		TLS         bool     `json:"tls"`
		Enabled     bool     `json:"enabled"`
		Toggleable  bool     `json:"toggleable"`
		HasCertDays bool     `json:"has_cert_days"`
		CertDays    float64  `json:"cert_days"`
		File        string   `json:"file"`
		NoToggle    string   `json:"no_toggle"`
	} `json:"sites"`
}

// FleetWebServer is one web server on one enrolled server.
type FleetWebServer struct {
	ServerID    string    `json:"server_id"`
	ServerName  string    `json:"server_name"`
	Connected   bool      `json:"connected"`
	UpdatedAt   time.Time `json:"updated_at"`
	Kind        string    `json:"kind"`
	Unit        string    `json:"unit"`
	Version     string    `json:"version,omitempty"`
	Active      bool      `json:"active"`
	ConfigOK    bool      `json:"config_ok"`
	ConfigError string    `json:"config_error,omitempty"`
}

// FleetSite is one site on one enrolled server.
type FleetSite struct {
	ServerID   string   `json:"server_id"`
	ServerName string   `json:"server_name"`
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Name       string   `json:"name"`
	Names      []string `json:"names"`
	Ports      []int    `json:"ports"`
	TLS        bool     `json:"tls"`
	Enabled    bool     `json:"enabled"`
	Toggleable bool     `json:"toggleable"`
	NoToggle   string   `json:"no_toggle,omitempty"`
	CertDays   *float64 `json:"cert_days,omitempty"`
	File       string   `json:"file"`
}

// FleetSites is the body of GET /fleet/sites.
type FleetSites struct {
	Servers []FleetWebServer `json:"servers"`
	Sites   []FleetSite      `json:"sites"`
}

// fleetSites lists sites across servers; q matches any name or the id (case-insensitive substring), server
// narrows to one server by id or name.
func (c *Central) fleetSites(r *http.Request) (any, error) {
	ctx := r.Context()
	rows, err := c.DB.ListFleetSites(ctx)
	if err != nil {
		return nil, err
	}
	srvs, err := c.DB.ListServers(ctx)
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	for _, s := range srvs {
		names[s.ID] = s.Name
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	only := r.URL.Query().Get("server")
	out := FleetSites{Servers: []FleetWebServer{}, Sites: []FleetSite{}}
	for _, row := range rows {
		name, ok := names[row.ServerID]
		if !ok || (only != "" && only != row.ServerID && only != name) {
			continue
		}
		var d fleetSiteData
		if err := json.Unmarshal(row.Data, &d); err != nil {
			continue
		}
		conn := c.Connected(row.ServerID)
		for _, w := range d.Servers {
			out.Servers = append(out.Servers, FleetWebServer{ServerID: row.ServerID, ServerName: name, Connected: conn,
				UpdatedAt: row.UpdatedAt, Kind: w.Kind, Unit: w.Unit, Version: w.Version, Active: w.Active,
				ConfigOK: w.ConfigOK, ConfigError: w.ConfigError})
		}
		for _, s := range d.Sites {
			if q != "" && !matchSite(q, s.ID, s.Names) {
				continue
			}
			fs := FleetSite{ServerID: row.ServerID, ServerName: name, ID: s.ID, Kind: s.Kind, Name: s.Name,
				Names: s.Names, Ports: s.Ports, TLS: s.TLS, Enabled: s.Enabled, Toggleable: s.Toggleable,
				NoToggle: s.NoToggle, File: s.File}
			if s.HasCertDays {
				d := s.CertDays
				fs.CertDays = &d
			}
			out.Sites = append(out.Sites, fs)
		}
	}
	sort.SliceStable(out.Sites, func(i, j int) bool {
		if out.Sites[i].Name != out.Sites[j].Name {
			return out.Sites[i].Name < out.Sites[j].Name
		}
		return out.Sites[i].ServerName < out.Sites[j].ServerName
	})
	return out, nil
}

func matchSite(q, id string, names []string) bool {
	if strings.Contains(strings.ToLower(id), q) {
		return true
	}
	for _, n := range names {
		if strings.Contains(strings.ToLower(n), q) {
			return true
		}
	}
	return false
}

// fleetSiteApply queues a set_site op; the agent runs the same safe toggle as locally and reports back.
func (c *Central) fleetSiteApply(r *http.Request) (any, error) {
	var q struct {
		Server  string `json:"server"`
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := api.Decode(r, &q); err != nil {
		return nil, err
	}
	srv, err := c.server(r, q.Server)
	if errors.Is(err, db.ErrNotFound) {
		return nil, api.Errf(http.StatusNotFound, "unknown server %q", q.Server)
	}
	if err != nil {
		return nil, err
	}
	got, err := c.fleetSites(r)
	if err != nil {
		return nil, err
	}
	var site *FleetSite
	for _, s := range got.(FleetSites).Sites {
		if s.ServerID == srv.ID && s.ID == q.ID {
			site = &s
			break
		}
	}
	switch {
	case site == nil:
		return nil, api.Errf(http.StatusNotFound, "server %s reported no site %q: check GET /fleet/sites", srv.Name, q.ID)
	case !site.Toggleable:
		return nil, api.Errf(http.StatusConflict, "%s on %s cannot be toggled: %s", site.Name, srv.Name, site.NoToggle)
	case site.Enabled == q.Enabled:
		return nil, api.Errf(http.StatusConflict, "%s on %s is already in that state", site.Name, srv.Name)
	}
	op, err := c.Enqueue(r.Context(), srv.ID, "set_site", setSiteOp{SiteID: q.ID, Enabled: q.Enabled})
	if err != nil {
		return nil, err
	}
	c.audit(r.Context(), srv.ID, "fleet.site.set", q.ID, map[string]any{"enabled": q.Enabled, "op": op.ID})
	return op, nil
}
