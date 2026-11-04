package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/tb12as/kurogane/internal/auth"
	"github.com/tb12as/kurogane/internal/certs"
)

func init() {
	Register(func(s *Server) {
		s.Route("GET /certs", auth.ScopeRead, s.certs)
		// a rescan only reads files and opens local handshakes, so read scope is enough; the cooldown keeps a
		// read token from turning it into a busy loop
		s.Route("POST /certs/rescan", auth.ScopeRead, s.rescanCerts)
	})
}

// rescanCooldown is the minimum time between on-demand certificate scans.
const rescanCooldown = 10 * time.Second

var rescanMu sync.Mutex

// CertsResponse is the body of GET /certs and POST /certs/rescan.
type CertsResponse struct {
	Enabled   bool         `json:"enabled"`
	ScannedAt time.Time    `json:"scanned_at,omitzero"`
	Certs     []certs.Cert `json:"certs"`
}

func (s *Server) certsResp(list []certs.Cert, at time.Time) CertsResponse {
	if list == nil {
		list = []certs.Cert{}
	}
	return CertsResponse{Enabled: s.Metrics.CertsEnabled(), ScannedAt: at, Certs: list}
}

func (s *Server) certs(*http.Request) (any, error) {
	if s.Metrics == nil {
		return nil, Errf(http.StatusServiceUnavailable, "no local collector on this server: query an agent instead")
	}
	list, at := s.Metrics.Certs()
	return s.certsResp(list, at), nil
}

func (s *Server) rescanCerts(r *http.Request) (any, error) {
	if s.Metrics == nil {
		return nil, Errf(http.StatusServiceUnavailable, "no local collector on this server: query an agent instead")
	}
	if !s.Metrics.CertsEnabled() {
		return nil, Errf(http.StatusConflict, "certificate monitoring is off: set collector.certs.enabled: true")
	}
	rescanMu.Lock()
	defer rescanMu.Unlock()
	if list, at := s.Metrics.Certs(); !at.IsZero() && time.Since(at) < rescanCooldown {
		return s.certsResp(list, at), nil
	}
	list, at := s.Metrics.RescanCerts(r.Context())
	return s.certsResp(list, at), nil
}
