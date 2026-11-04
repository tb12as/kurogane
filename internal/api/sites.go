package api

import (
	"errors"
	"net/http"

	"github.com/tb12as/serverman/internal/auth"
	"github.com/tb12as/serverman/internal/sites"
)

func init() {
	Register(func(s *Server) {
		s.Route("GET /sites", auth.ScopeRead, s.siteList)
		s.Route("GET /sites/changes", auth.ScopeRead, s.siteChanges)
		// raw config can hold secrets (proxy auth headers, basic auth paths): web:write only
		s.Route("GET /sites/config", auth.ScopeWeb, s.siteConfig)
		s.Route("POST /sites/plan", auth.ScopeRead, s.sitePlan)
		s.Route("POST /sites/apply", auth.ScopeWeb, s.siteApply)
		s.Route("POST /sites/rescan", auth.ScopeWeb, s.siteRescan)
		s.Route("POST /web/{server}/reload", auth.ScopeWeb, s.webReload)
	})
}

// SitesResponse is the body of GET /sites.
type SitesResponse struct {
	sites.Inventory
	Enabled bool `json:"enabled"`
}

// SiteToggle is the body of POST /sites/plan and /sites/apply.
type SiteToggle struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
}

func (s *Server) sitesOn() error {
	if s.Sites == nil {
		if s.Central {
			return Errf(http.StatusServiceUnavailable, "the central server has no local web sites: use GET /fleet/sites")
		}
		return Errf(http.StatusServiceUnavailable, "site management is off: set web.enabled: true and restart the agent")
	}
	return nil
}

// siteErr maps sites errors to HTTP status codes.
func siteErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sites.ErrNotFound):
		return Errf(http.StatusNotFound, "%v", err)
	case errors.Is(err, sites.ErrRefused), errors.Is(err, sites.ErrBusy):
		return Errf(http.StatusConflict, "%v", err)
	}
	return Errf(http.StatusUnprocessableEntity, "%v", err)
}

func (s *Server) siteList(*http.Request) (any, error) {
	if s.Sites == nil && !s.Central {
		return SitesResponse{Inventory: sites.Inventory{Servers: []sites.WebServer{}, Sites: []sites.Site{}}}, nil
	}
	if err := s.sitesOn(); err != nil {
		return nil, err
	}
	inv := s.Sites.Inventory()
	if inv.Servers == nil {
		inv.Servers = []sites.WebServer{}
	}
	if inv.Sites == nil {
		inv.Sites = []sites.Site{}
	}
	return SitesResponse{Inventory: inv, Enabled: true}, nil
}

func (s *Server) siteChanges(r *http.Request) (any, error) {
	if err := s.sitesOn(); err != nil {
		return nil, err
	}
	return s.Sites.Changes(r.Context())
}

func (s *Server) siteConfig(r *http.Request) (any, error) {
	if err := s.sitesOn(); err != nil {
		return nil, err
	}
	f, text, err := s.Sites.Config(r.Context(), r.URL.Query().Get("id"))
	if err != nil {
		return nil, siteErr(err)
	}
	return map[string]string{"file": f, "content": text}, nil
}

func (s *Server) toggleBody(r *http.Request) (SiteToggle, error) {
	var q SiteToggle
	if err := s.sitesOn(); err != nil {
		return q, err
	}
	if err := Decode(r, &q); err != nil {
		return q, err
	}
	if q.ID == "" {
		return q, Errf(http.StatusBadRequest, "id is required: take it from GET /sites")
	}
	return q, nil
}

func (s *Server) sitePlan(r *http.Request) (any, error) {
	q, err := s.toggleBody(r)
	if err != nil {
		return nil, err
	}
	p, err := s.Sites.Plan(r.Context(), q.ID, q.Enabled)
	return p, siteErr(err)
}

func (s *Server) siteApply(r *http.Request) (any, error) {
	q, err := s.toggleBody(r)
	if err != nil {
		return nil, err
	}
	ch, err := s.Sites.Apply(r.Context(), q.ID, q.Enabled)
	return ch, siteErr(err)
}

func (s *Server) siteRescan(r *http.Request) (any, error) {
	if err := s.sitesOn(); err != nil {
		return nil, err
	}
	return SitesResponse{Inventory: s.Sites.Scan(r.Context(), true), Enabled: true}, nil
}

func (s *Server) webReload(r *http.Request) (any, error) {
	if err := s.sitesOn(); err != nil {
		return nil, err
	}
	if err := s.Sites.Reload(r.Context(), r.PathValue("server")); err != nil {
		return nil, siteErr(err)
	}
	return map[string]bool{"reloaded": true}, nil
}
