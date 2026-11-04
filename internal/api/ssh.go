package api

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/tb12as/kurogane/internal/auth"
	"github.com/tb12as/kurogane/internal/config"
	"github.com/tb12as/kurogane/internal/sshmgr"
)

func init() { Register((*Server).sshRoutes) }

// parseDate accepts 2006-01-02 or RFC3339; "" is zero.
func parseDate(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
		return t.Add(24*time.Hour - time.Second), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return t, Errf(http.StatusBadRequest, "invalid date %q: use YYYY-MM-DD", s)
	}
	return t, nil
}

func (s *Server) sshRoutes() {
	if s.SSH == nil {
		return
	}
	m := s.SSH
	s.Route("GET /ssh/keys", auth.ScopeRead, func(r *http.Request) (any, error) {
		return m.Keys(r.Context(), r.URL.Query().Get("user"))
	})
	s.Route("POST /ssh/keys", auth.ScopeSSH, func(r *http.Request) (any, error) {
		var q struct {
			User      string `json:"user"`
			PublicKey string `json:"public_key"`
			GitHub    string `json:"github"`
			GitLab    string `json:"gitlab"`
			Label     string `json:"label"`
			ExpiresAt string `json:"expires_at"`
		}
		if err := Decode(r, &q); err != nil {
			return nil, err
		}
		exp, err := parseDate(q.ExpiresAt)
		if err != nil {
			return nil, err
		}
		if q.User == "" {
			return nil, Errf(http.StatusBadRequest, "user is required")
		}
		switch {
		case q.GitHub != "":
			return bad(m.ImportKeys(r.Context(), "github", q.GitHub, q.User, q.Label, exp))
		case q.GitLab != "":
			return bad(m.ImportKeys(r.Context(), "gitlab", q.GitLab, q.User, q.Label, exp))
		case q.PublicKey == "":
			return nil, Errf(http.StatusBadRequest, "public_key, github or gitlab is required")
		}
		return bad(m.AddKey(r.Context(), q.User, q.PublicKey, q.Label, exp))
	})
	s.Route("DELETE /ssh/keys/{fp}", auth.ScopeSSH, func(r *http.Request) (any, error) {
		fp, _ := url.PathUnescape(r.PathValue("fp"))
		n, err := m.RemoveKey(r.Context(), fp, r.URL.Query().Get("user"))
		if err != nil {
			return nil, Errf(http.StatusNotFound, "%s", err.Error())
		}
		return map[string]int{"removed": n}, nil
	})
	s.Route("PATCH /ssh/keys/{fp}", auth.ScopeSSH, func(r *http.Request) (any, error) {
		fp, _ := url.PathUnescape(r.PathValue("fp"))
		var q struct {
			User        string  `json:"user"`
			Label       *string `json:"label"`
			OwnerPerson *string `json:"owner_person"`
			ExpiresAt   *string `json:"expires_at"`
		}
		if err := Decode(r, &q); err != nil {
			return nil, err
		}
		var exp *time.Time
		if q.ExpiresAt != nil {
			t, err := parseDate(*q.ExpiresAt)
			if err != nil {
				return nil, err
			}
			exp = &t
		}
		return m.UpdateKey(r.Context(), fp, q.User, q.Label, q.OwnerPerson, exp)
	})

	s.Route("GET /ssh/config", auth.ScopeRead, func(r *http.Request) (any, error) {
		rows, err := m.ShowConfig(r.Context())
		if err != nil {
			return nil, err
		}
		out := map[string]any{"settings": rows}
		if p, ok := m.PendingChange(); ok {
			out["pending"] = p
		}
		return out, nil
	})
	s.Route("PATCH /ssh/config", auth.ScopeSSH, func(r *http.Request) (any, error) {
		var q struct {
			Set      map[string]string `json:"set"`
			Rollback string            `json:"rollback"`
			DryRun   bool              `json:"dry_run"`
			Session  string            `json:"ssh_connection"`
		}
		if err := Decode(r, &q); err != nil {
			return nil, err
		}
		if q.DryRun {
			return bad(m.Plan(r.Context(), q.Set))
		}
		var d time.Duration
		if q.Rollback != "" {
			var err error
			if d, err = config.ParseDuration(q.Rollback); err != nil || d < 10*time.Second {
				return nil, Errf(http.StatusBadRequest, "rollback must be a duration of at least 10s, e.g. 120s")
			}
		}
		return bad(m.SafeApplyFrom(r.Context(), q.Set, d, q.Session))
	})
	s.Route("POST /ssh/config/confirm", auth.ScopeSSH, func(r *http.Request) (any, error) {
		var q struct {
			Session string `json:"ssh_connection"`
		}
		if err := Decode(r, &q); err != nil {
			return nil, err
		}
		return bad(m.Confirm(r.Context(), q.Session))
	})
	s.Route("GET /ssh/changes", auth.ScopeRead, func(r *http.Request) (any, error) { return m.Changes(r.Context()) })

	s.Route("GET /ssh/sessions", auth.ScopeRead, func(r *http.Request) (any, error) { return m.Sessions(r.Context()) })
	s.Route("DELETE /ssh/sessions/{pid}", auth.ScopeSSH, func(r *http.Request) (any, error) {
		pid, err := strconv.Atoi(r.PathValue("pid"))
		if err != nil {
			return nil, Errf(http.StatusBadRequest, "pid must be a number")
		}
		return bad(m.KillSession(r.Context(), pid))
	})
	s.Route("GET /ssh/logins", auth.ScopeRead, func(r *http.Request) (any, error) {
		since := time.Now().Add(-24 * time.Hour)
		if v := r.URL.Query().Get("since"); v != "" {
			d, err := config.ParseDuration(v)
			if err != nil {
				return nil, Errf(http.StatusBadRequest, "invalid since %q: use a duration like 24h or 7d", v)
			}
			since = time.Now().Add(-d)
		}
		return m.Summary(r.Context(), since)
	})
	s.Route("GET /ssh/bans", auth.ScopeRead, func(r *http.Request) (any, error) {
		if s.Firewall == nil {
			return []any{}, nil
		}
		return map[string]any{"backend": s.Firewall.Backend(), "bans": s.Firewall.Bans()}, nil
	})
	s.Route("DELETE /ssh/bans/{ip}", auth.ScopeSSH, func(r *http.Request) (any, error) {
		if s.Firewall == nil {
			return nil, Errf(http.StatusNotFound, "firewall not available")
		}
		s.Audit.Record(r.Context(), "firewall.unban", r.PathValue("ip"), nil, nil)
		return nil, s.Firewall.Unban(r.Context(), r.PathValue("ip"))
	})
	s.Route("POST /ssh/ca/init", auth.ScopeSSH, func(r *http.Request) (any, error) {
		pub, err := m.InitCA(r.Context(), 0)
		if err != nil {
			return nil, Errf(http.StatusBadRequest, "%s", err.Error())
		}
		return map[string]string{"ca_public_key": pub, "path": sshmgr.CAPubPath}, nil
	})
	s.Route("POST /ssh/ca/sign", auth.ScopeSSH, func(r *http.Request) (any, error) {
		var q struct {
			PublicKey  string   `json:"public_key"`
			Principals []string `json:"principals"`
			TTL        string   `json:"ttl"`
			KeyID      string   `json:"key_id"`
		}
		if err := Decode(r, &q); err != nil {
			return nil, err
		}
		var ttl time.Duration
		if q.TTL != "" {
			var err error
			if ttl, err = config.ParseDuration(q.TTL); err != nil {
				return nil, Errf(http.StatusBadRequest, "invalid ttl %q", q.TTL)
			}
		}
		cert, err := m.Sign(r.Context(), q.PublicKey, q.Principals, ttl, q.KeyID)
		if err != nil {
			return nil, Errf(http.StatusBadRequest, "%s", err.Error())
		}
		return map[string]string{"certificate": cert}, nil
	})
}

// bad turns domain validation errors into 400s (they already state cause and next step).
func bad[T any](v T, err error) (any, error) {
	if err == nil {
		return v, nil
	}
	var he *HTTPError
	if errors.As(err, &he) {
		return nil, err
	}
	return nil, Errf(http.StatusBadRequest, "%s", err.Error())
}
