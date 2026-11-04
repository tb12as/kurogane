// Package api serves the REST API (/api/v1), the SSE stream and the embedded web UI (PRD §9, §10.2).
package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tb12as/kurogane/internal/alert"
	"github.com/tb12as/kurogane/internal/audit"
	"github.com/tb12as/kurogane/internal/auth"
	"github.com/tb12as/kurogane/internal/collector"
	"github.com/tb12as/kurogane/internal/config"
	"github.com/tb12as/kurogane/internal/db"
	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/firewall"
	"github.com/tb12as/kurogane/internal/harden"
	"github.com/tb12as/kurogane/internal/secret"
	"github.com/tb12as/kurogane/internal/sites"
	"github.com/tb12as/kurogane/internal/sshmgr"
	"github.com/tb12as/kurogane/internal/store"
)

// Server holds every service the handlers need. Nil services disable their routes' behaviour
// (e.g. the central server has no local collector).
type Server struct {
	Cfg      *config.Config
	DB       db.Store
	Store    *store.Store
	Auth     *auth.Service
	Audit    *audit.Logger
	Box      *secret.Box
	Ex       executor.Executor
	Metrics  *collector.Manager
	Sites    *sites.Manager
	Alerts   *alert.Engine
	SSH      *sshmgr.Manager
	Harden   *harden.Service
	Firewall *firewall.Manager
	Hub      *Hub
	UI       fs.FS
	Version  string
	Central  bool

	mux *http.ServeMux
}

// Handler returns a JSON-encodable result or an error.
type Handler func(r *http.Request) (any, error)

var (
	regMu      sync.Mutex
	registrars []func(*Server)
)

// Register adds a route registrar; domain files call it from init().
func Register(f func(*Server)) {
	regMu.Lock()
	registrars = append(registrars, f)
	regMu.Unlock()
}

// HTTPError carries a status code; Msg should state cause and next step (§11.5).
type HTTPError struct {
	Code int    `json:"-"`
	Msg  string `json:"error"`
}

func (e *HTTPError) Error() string { return e.Msg }

// Errf builds an HTTPError.
func Errf(code int, format string, a ...any) error {
	return &HTTPError{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// Build wires all routes.
func (s *Server) Build() http.Handler {
	if s.Hub == nil {
		s.Hub = NewHub()
	}
	s.mux = http.NewServeMux()
	regMu.Lock()
	regs := append([]func(*Server){}, registrars...)
	regMu.Unlock()
	for _, f := range regs {
		f(s)
	}
	if s.UI != nil {
		s.mux.Handle("GET /", spa(s.UI))
	}
	return securityHeaders(s.mux)
}

// Route registers an /api/v1 JSON route requiring scope ("" = public).
func (s *Server) Route(pattern, scope string, h Handler) {
	method, path, _ := strings.Cut(pattern, " ")
	s.mux.HandleFunc(method+" /api/v1"+path, func(w http.ResponseWriter, r *http.Request) {
		r, p, ok := s.authorize(w, r, scope)
		if !ok {
			return
		}
		v, err := h(r)
		status := http.StatusOK
		if err != nil {
			status = writeErr(w, err)
		} else {
			if method == http.MethodPost && v != nil {
				status = http.StatusOK
			}
			WriteJSON(w, status, v)
		}
		if method != http.MethodGet && p != nil && s.Audit != nil {
			s.Audit.Record(r.Context(), "api."+strings.ToLower(method)+" "+r.URL.Path, fmt.Sprint(status), nil, nil)
		}
	})
}

// Raw registers a non-JSON route (SSE, file export, Prometheus) under an absolute path.
func (s *Server) Raw(pattern, scope string, h http.HandlerFunc) {
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		r, _, ok := s.authorize(w, r, scope)
		if ok {
			h(w, r)
		}
	})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request, scope string) (*http.Request, *auth.Principal, bool) {
	ip := clientIP(r)
	if scope == "" {
		return r.WithContext(audit.WithActor(r.Context(), "anonymous", ip)), nil, true
	}
	if s.Auth == nil {
		writeErr(w, Errf(http.StatusServiceUnavailable, "auth not configured"))
		return r, nil, false
	}
	p, err := s.Auth.Authenticate(r)
	if err != nil {
		code := http.StatusUnauthorized
		if errors.Is(err, auth.ErrCSRF) {
			code = http.StatusForbidden
		}
		writeErr(w, Errf(code, "%s", err.Error()))
		return r, nil, false
	}
	if !p.Has(scope) {
		writeErr(w, Errf(http.StatusForbidden, "%s: need %q", auth.ErrForbidden, scope))
		return r, nil, false
	}
	ctx := audit.WithActor(r.Context(), p.Actor, ip)
	ctx = context.WithValue(ctx, principalKey{}, p)
	return r.WithContext(ctx), p, true
}

type principalKey struct{}

// PrincipalFrom returns the authenticated caller.
func PrincipalFrom(r *http.Request) *auth.Principal {
	p, _ := r.Context().Value(principalKey{}).(*auth.Principal)
	return p
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func writeErr(w http.ResponseWriter, err error) int {
	var he *HTTPError
	if !errors.As(err, &he) {
		he = &HTTPError{Code: http.StatusInternalServerError, Msg: err.Error()}
		switch {
		case errors.Is(err, db.ErrNotFound), errors.Is(err, store.ErrNotFound), errors.Is(err, fs.ErrNotExist):
			he.Code = http.StatusNotFound
		case errors.Is(err, executor.ErrDenied):
			he.Code = http.StatusForbidden
		}
	}
	he.Msg = secret.Redact(he.Msg)
	WriteJSON(w, he.Code, he)
	return he.Code
}

// WriteJSON writes v as JSON.
func WriteJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

// Decode reads a JSON body (max 1 MB) into v.
func Decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return Errf(http.StatusBadRequest, "invalid JSON body: %v", err)
	}
	return nil
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "same-origin")
		hd.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
			"script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
		if r.TLS != nil {
			hd.Set("Strict-Transport-Security", "max-age=31536000")
		}
		h.ServeHTTP(w, r)
	})
}

// spa serves static files and falls back to index.html for client-side routes.
func spa(ui fs.FS) http.Handler {
	files := http.FileServer(http.FS(ui))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p != "" {
			if _, err := fs.Stat(ui, p); err == nil {
				files.ServeHTTP(w, r)
				return
			}
		}
		for _, idx := range []string{"index.html", "200.html"} {
			if b, err := fs.ReadFile(ui, idx); err == nil {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write(b)
				return
			}
		}
		http.Error(w, "web UI not built: run `make web`", http.StatusNotFound)
	})
}

// ListenAndServe serves on cfg.Listen; non-loopback requires TLS 1.3 (§11.1).
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{Addr: addr, Handler: s.Build(), ReadHeaderTimeout: 10 * time.Second,
		BaseContext: func(net.Listener) context.Context { return ctx }}
	go func() { // #nosec G118 -- shutdown must outlive the cancelled request context
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
	}()
	var err error
	if s.Cfg != nil && s.Cfg.TLS.Cert != "" {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
		slog.Info("api listening (TLS 1.3)", "addr", addr)
		err = srv.ListenAndServeTLS(s.Cfg.TLS.Cert, s.Cfg.TLS.Key)
	} else {
		if !config.IsLoopback(addr) {
			return fmt.Errorf("refusing to listen on %s without TLS: configure tls.cert/tls.key", addr)
		}
		slog.Info("api listening", "addr", addr)
		err = srv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
