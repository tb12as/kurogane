package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/serverkeeper/serverkeeper/internal/auth"
	"github.com/serverkeeper/serverkeeper/internal/db"
)

func init() {
	Register(func(s *Server) {
		s.Route("GET /health", "", func(*http.Request) (any, error) {
			return map[string]any{"ok": true, "version": s.Version, "oidc": s.Auth != nil && s.Auth.OIDC != nil,
				"central": s.Central}, nil
		})
		s.Route("POST /auth/logout", "", s.logout)
		s.Route("GET /auth/me", auth.ScopeRead, func(r *http.Request) (any, error) {
			p := PrincipalFrom(r)
			return map[string]any{"actor": p.Actor, "role": p.Role, "scopes": p.Scopes, "csrf": p.CSRF,
				"oidc": s.Auth.OIDC != nil}, nil
		})
		s.Raw("GET /api/v1/auth/oidc/login", "", s.oidcLogin)
		s.Raw("GET /api/v1/auth/oidc/callback", "", s.oidcCallback)
		s.Raw("GET /api/v1/stream", auth.ScopeRead, s.Hub.serve)

		s.Route("GET /status", auth.ScopeRead, s.status)
		s.Route("GET /audit", auth.ScopeRead, s.listAudit)

		s.Route("GET /users", auth.ScopeAdmin, func(r *http.Request) (any, error) { return s.DB.ListUsers(r.Context()) })
		s.Route("POST /users", auth.ScopeAdmin, s.createUser)
		s.Route("DELETE /users/{id}", auth.ScopeAdmin, func(r *http.Request) (any, error) {
			id := r.PathValue("id")
			if u, err := s.DB.GetUserByName(r.Context(), id); err == nil {
				id = u.ID
			}
			s.Audit.Record(r.Context(), "user.delete", id, nil, nil)
			return nil, s.DB.DeleteUser(r.Context(), id)
		})
		s.Route("POST /users/{name}/unlock", auth.ScopeAdmin, func(r *http.Request) (any, error) {
			s.Audit.Record(r.Context(), "user.unlock", r.PathValue("name"), nil, nil)
			return nil, s.Auth.Unlock(r.Context(), r.PathValue("name"))
		})
		s.Route("GET /tokens", auth.ScopeAdmin, func(r *http.Request) (any, error) { return s.DB.ListTokens(r.Context()) })
		s.Route("POST /tokens", auth.ScopeAdmin, s.createToken)
		s.Route("DELETE /tokens/{id}", auth.ScopeAdmin, func(r *http.Request) (any, error) {
			s.Audit.Record(r.Context(), "token.delete", r.PathValue("id"), nil, nil)
			return nil, s.DB.DeleteToken(r.Context(), r.PathValue("id"))
		})
		s.Route("POST /telemetry/first-dashboard", auth.ScopeRead, s.firstDashboard)
		s.Raw("GET /api/v1/openapi.yaml", "", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/yaml")
			w.Write(OpenAPISpec)
		})
	})
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTP     string `json:"totp"`
}

func (s *Server) setSessionCookies(w http.ResponseWriter, r *http.Request, sess db.Session) {
	secure := r.TLS != nil
	http.SetCookie(w, &http.Cookie{Name: auth.SessionCookie, Value: sess.ID, Path: "/", HttpOnly: true, Secure: secure,
		SameSite: http.SameSiteStrictMode, Expires: sess.ExpiresAt})
	http.SetCookie(w, &http.Cookie{Name: auth.CSRFCookie, Value: sess.CSRF, Path: "/", Secure: secure,
		SameSite: http.SameSiteStrictMode, Expires: sess.ExpiresAt})
}

func init() {
	Register(func(s *Server) { s.mux.HandleFunc("POST /api/v1/auth/login", s.loginRaw) })
}

func (s *Server) loginRaw(w http.ResponseWriter, r *http.Request) {
	var q loginReq
	if err := Decode(r, &q); err != nil {
		writeErr(w, err)
		return
	}
	ip := clientIP(r)
	sess, u, err := s.Auth.Login(r.Context(), q.Username, q.Password, q.TOTP, ip)
	if err != nil {
		code := http.StatusUnauthorized
		if errors.Is(err, auth.ErrLocked) {
			code = http.StatusLocked
		}
		_ = s.DB.AppendAudit(r.Context(), db.AuditEntry{Actor: q.Username, Action: "auth.login_failed", SourceIP: ip})
		writeErr(w, Errf(code, "%s", err.Error()))
		return
	}
	_ = s.DB.AppendAudit(r.Context(), db.AuditEntry{Actor: u.Username, Action: "auth.login", SourceIP: ip})
	s.setSessionCookies(w, r, sess)
	WriteJSON(w, http.StatusOK, map[string]any{"user": u, "csrf": sess.CSRF, "expires_at": sess.ExpiresAt})
}

func (s *Server) logout(r *http.Request) (any, error) {
	if c, err := r.Cookie(auth.SessionCookie); err == nil {
		_ = s.Auth.Logout(r.Context(), c.Value)
	}
	return map[string]bool{"ok": true}, nil
}

func (s *Server) oidcLogin(w http.ResponseWriter, r *http.Request) {
	if s.Auth.OIDC == nil {
		http.Error(w, "OIDC not configured: set auth.oidc in config.yaml", http.StatusNotFound)
		return
	}
	state := auth.RandomToken(16)
	http.SetCookie(w, &http.Cookie{Name: "sk_oidc_state", Value: state, Path: "/", HttpOnly: true, Secure: r.TLS != nil,
		SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, s.Auth.OIDC.AuthURL(state), http.StatusFound)
}

func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("sk_oidc_state")
	if err != nil || c.Value == "" || c.Value != r.URL.Query().Get("state") {
		http.Error(w, "invalid OIDC state: start the login again", http.StatusBadRequest)
		return
	}
	sess, u, err := s.Auth.OIDCCallback(r.Context(), r, clientIP(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	_ = s.DB.AppendAudit(r.Context(), db.AuditEntry{Actor: u.Username, Action: "auth.login_oidc", SourceIP: clientIP(r)})
	s.setSessionCookies(w, r, sess)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) status(r *http.Request) (any, error) {
	ctx := r.Context()
	out := map[string]any{"server_name": s.Cfg.ServerName, "version": s.Version, "time": time.Now()}
	if s.Metrics != nil {
		if snap := s.Metrics.Latest(); snap != nil {
			m := map[string]float64{}
			for _, k := range []string{"cpu.total_pct", "mem.available_pct", "mem.used_pct", "swap.used_pct", "load.1",
				"net.tcp.established", "proc.total"} {
				if v, ok := snap.Value(k, nil); ok {
					m[k] = v
				}
			}
			out["metrics"] = m
			out["system"] = snap.System
			out["mounts"] = snap.Mounts
		}
	}
	if sc, err := s.DB.GetScan(ctx, "latest"); err == nil {
		out["hardening"] = map[string]any{"score": sc.Score, "grade": sc.Grade, "scanned_at": sc.StartedAt, "id": sc.ID}
	}
	if ev, err := s.DB.ListEvents(ctx, db.EventFilter{State: "open"}); err == nil {
		out["active_alerts"] = ev
	}
	return out, nil
}

func (s *Server) listAudit(r *http.Request) (any, error) {
	q := r.URL.Query()
	lim, _ := strconv.Atoi(q.Get("limit"))
	off, _ := strconv.Atoi(q.Get("offset"))
	f := db.AuditFilter{Actor: q.Get("actor"), Action: q.Get("action"), Limit: lim, Offset: off}
	if d := q.Get("since"); d != "" {
		if dur, err := time.ParseDuration(d); err == nil {
			f.Since = time.Now().Add(-dur)
		}
	}
	return s.DB.ListAudit(r.Context(), f)
}

func (s *Server) createUser(r *http.Request) (any, error) {
	var q struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := Decode(r, &q); err != nil {
		return nil, err
	}
	if q.Role == "" {
		q.Role = "viewer"
	}
	u, url, err := s.Auth.CreateUser(r.Context(), q.Username, q.Password, q.Role)
	if err != nil {
		return nil, Errf(http.StatusBadRequest, "%s", err.Error())
	}
	s.Audit.Record(r.Context(), "user.create", u.Username, nil, map[string]string{"role": u.Role})
	return map[string]any{"user": u, "totp_url": url}, nil
}

func (s *Server) createToken(r *http.Request) (any, error) {
	var q struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
		TTL    string   `json:"ttl"`
	}
	if err := Decode(r, &q); err != nil {
		return nil, err
	}
	var ttl time.Duration
	if q.TTL != "" {
		d, err := time.ParseDuration(q.TTL)
		if err != nil {
			return nil, Errf(http.StatusBadRequest, "invalid ttl %q", q.TTL)
		}
		ttl = d
	}
	raw, t, err := s.Auth.CreateToken(r.Context(), q.Name, q.Scopes, PrincipalFrom(r).Actor, ttl)
	if err != nil {
		return nil, Errf(http.StatusBadRequest, "%s", err.Error())
	}
	s.Audit.Record(r.Context(), "token.create", t.Name, nil, map[string]any{"scopes": t.Scopes})
	return map[string]any{"token": raw, "info": t}, nil
}

// firstDashboard records opt-in onboarding telemetry (time from init to first dashboard).
func (s *Server) firstDashboard(r *http.Request) (any, error) {
	ctx := r.Context()
	if _, err := s.DB.GetKV(ctx, "telemetry.first_dashboard"); err == nil {
		return map[string]bool{"recorded": false}, nil
	}
	now := time.Now().UTC()
	_ = s.DB.SetKV(ctx, "telemetry.first_dashboard", now.Format(time.RFC3339))
	if t := s.Cfg.Telemetry; t.Enabled && t.URL != "" {
		inst, _ := s.DB.GetKV(ctx, "telemetry.installed_at")
		go sendTelemetry(t.URL, s.Version, inst, now)
	}
	return map[string]bool{"recorded": true}, nil
}

// sendTelemetry posts only install-to-first-dashboard timing and the version (opt-in, PRD §2 success metric).
func sendTelemetry(u, version, installed string, first time.Time) {
	body := map[string]any{"version": version, "first_dashboard_at": first}
	if t, err := time.Parse(time.RFC3339, installed); err == nil {
		body["seconds_to_first_dashboard"] = int(first.Sub(t).Seconds())
	}
	b, _ := json.Marshal(body)
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Post(u, "application/json", bytes.NewReader(b))
	if err != nil {
		slog.Debug("telemetry not sent", "err", err)
		return
	}
	resp.Body.Close()
}
