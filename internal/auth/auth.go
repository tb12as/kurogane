package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tb12as/serverman/internal/db"
	"github.com/tb12as/serverman/internal/secret"
)

// Scopes (PRD §10.2).
const (
	ScopeRead   = "read"
	ScopeSSH    = "ssh:write"
	ScopeHarden = "harden:write"
	ScopeWeb    = "web:write" // enable/disable web sites, reload web servers, view raw site config
	ScopeAdmin  = "admin"
)

var AllScopes = []string{ScopeRead, ScopeSSH, ScopeHarden, ScopeWeb, ScopeAdmin}

// Roles map to scopes (RBAC, v1).
var Roles = map[string][]string{
	"admin":    {ScopeAdmin, ScopeRead, ScopeSSH, ScopeHarden, ScopeWeb},
	"operator": {ScopeRead, ScopeSSH, ScopeHarden, ScopeWeb},
	"viewer":   {ScopeRead},
}

const (
	MaxFailures   = 5
	LockDuration  = 15 * time.Minute
	SessionCookie = "sk_session"
	CSRFCookie    = "sk_csrf"
	CSRFHeader    = "X-CSRF-Token"
)

var (
	ErrBadCredentials = errors.New("invalid username, password or TOTP code")
	ErrLocked         = errors.New("account locked after 5 failed logins: wait 15 minutes or unlock with `serverkeeper users unlock`")
	ErrUnauthorized   = errors.New("authentication required: log in or pass an API token (Authorization: Bearer ...)")
	ErrForbidden      = errors.New("insufficient scope for this action")
	ErrCSRF           = errors.New("missing or invalid CSRF token")
)

// Principal is an authenticated caller.
type Principal struct {
	Actor   string   `json:"actor"`
	UserID  string   `json:"user_id,omitempty"`
	Role    string   `json:"role,omitempty"`
	Scopes  []string `json:"scopes"`
	Session bool     `json:"session"`
	CSRF    string   `json:"-"`
}

// Has reports whether p holds scope s (admin implies everything).
func (p *Principal) Has(s string) bool {
	for _, x := range p.Scopes {
		if x == s || x == ScopeAdmin {
			return true
		}
	}
	return false
}

// Service authenticates requests against the Store.
type Service struct {
	S          db.Store
	Box        *secret.Box
	SessionTTL time.Duration
	Issuer     string
	OIDC       *OIDC
	now        func() time.Time
}

func NewService(s db.Store, box *secret.Box, ttl time.Duration) *Service {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	return &Service{S: s, Box: box, SessionTTL: ttl, Issuer: "ServerKeeper", now: time.Now}
}

// CreateUser adds a user with a TOTP secret; returns the otpauth URL to enroll the authenticator.
func (a *Service) CreateUser(ctx context.Context, name, password, role string) (db.User, string, error) {
	if _, ok := Roles[role]; !ok {
		return db.User{}, "", fmt.Errorf("unknown role %q (admin, operator, viewer)", role)
	}
	h, err := HashPassword(password)
	if err != nil {
		return db.User{}, "", err
	}
	sec := NewTOTPSecret()
	sealed, err := a.Box.Seal(sec)
	if err != nil {
		return db.User{}, "", err
	}
	u := db.User{ID: db.NewID(), Username: name, PasswordHash: h, TOTPSecret: sealed, TOTPEnabled: true, Role: role}
	if err := a.S.SaveUser(ctx, u); err != nil {
		return db.User{}, "", fmt.Errorf("create user %s: %w", name, err)
	}
	return u, TOTPURL(a.Issuer, name, sec), nil
}

// Login verifies password + TOTP (mandatory for the web UI) and opens a session.
func (a *Service) Login(ctx context.Context, name, password, code, ip string) (db.Session, db.User, error) {
	now := a.now()
	u, err := a.S.GetUserByName(ctx, name)
	if err != nil {
		VerifyPassword("$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0$ZmFrZWZha2VmYWtlZmFrZWZha2VmYWtlZmFrZWZha2U", password)
		return db.Session{}, db.User{}, ErrBadCredentials
	}
	if now.Before(u.LockedUntil) {
		return db.Session{}, u, ErrLocked
	}
	ok := u.PasswordHash != "" && VerifyPassword(u.PasswordHash, password)
	if ok {
		sec, err := a.Box.Open(u.TOTPSecret)
		ok = err == nil && u.TOTPEnabled && VerifyTOTP(sec, code, now)
	}
	if !ok {
		u.FailedLogins++
		if u.FailedLogins >= MaxFailures {
			u.LockedUntil, u.FailedLogins = now.Add(LockDuration), 0
		}
		_ = a.S.SaveUser(ctx, u)
		if !u.LockedUntil.IsZero() && now.Before(u.LockedUntil) {
			return db.Session{}, u, ErrLocked
		}
		return db.Session{}, u, ErrBadCredentials
	}
	u.FailedLogins, u.LockedUntil = 0, time.Time{}
	_ = a.S.SaveUser(ctx, u)
	s, err := a.NewSession(ctx, u, ip)
	return s, u, err
}

// NewSession creates a session; the returned Session.ID is the raw cookie value.
func (a *Service) NewSession(ctx context.Context, u db.User, ip string) (db.Session, error) {
	raw := RandomToken(32)
	s := db.Session{ID: HashToken(raw), UserID: u.ID, CSRF: RandomToken(24), IP: ip, CreatedAt: a.now(),
		ExpiresAt: a.now().Add(a.SessionTTL)}
	if err := a.S.CreateSession(ctx, s); err != nil {
		return s, err
	}
	s.ID = raw
	return s, nil
}

// Logout deletes the session for a raw cookie value.
func (a *Service) Logout(ctx context.Context, raw string) error {
	return a.S.DeleteSession(ctx, HashToken(raw))
}

// CreateToken issues a scoped API token; the plaintext is returned once.
func (a *Service) CreateToken(ctx context.Context, name string, scopes []string, by string, ttl time.Duration) (string, db.APIToken, error) {
	for _, s := range scopes {
		if !validScope(s) {
			return "", db.APIToken{}, fmt.Errorf("unknown scope %q (read, ssh:write, harden:write, web:write, admin)", s)
		}
	}
	raw := "sk_" + RandomToken(32)
	t := db.APIToken{ID: db.NewID(), Name: name, Hash: HashToken(raw), Scopes: scopes, CreatedBy: by, CreatedAt: a.now()}
	if ttl > 0 {
		t.ExpiresAt = a.now().Add(ttl)
	}
	return raw, t, a.S.CreateToken(ctx, t)
}

func validScope(s string) bool {
	for _, x := range AllScopes {
		if x == s {
			return true
		}
	}
	return false
}

// Authenticate resolves a Bearer token or session cookie. Session requests that mutate state must
// carry the CSRF header (double-submit).
func (a *Service) Authenticate(r *http.Request) (*Principal, error) {
	ctx := r.Context()
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		raw := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
		t, err := a.S.GetTokenByHash(ctx, HashToken(raw))
		if err != nil {
			return nil, ErrUnauthorized
		}
		if !t.ExpiresAt.IsZero() && a.now().After(t.ExpiresAt) {
			return nil, errors.New("API token expired: create a new one with `serverkeeper tokens create`")
		}
		_ = a.S.TouchToken(ctx, t.ID, a.now())
		return &Principal{Actor: "token:" + t.Name, Scopes: t.Scopes}, nil
	}
	c, err := r.Cookie(SessionCookie)
	if err != nil || c.Value == "" {
		return nil, ErrUnauthorized
	}
	s, err := a.S.GetSession(ctx, HashToken(c.Value))
	if err != nil || a.now().After(s.ExpiresAt) {
		return nil, ErrUnauthorized
	}
	u, err := a.S.GetUser(ctx, s.UserID)
	if err != nil {
		return nil, ErrUnauthorized
	}
	p := &Principal{Actor: u.Username, UserID: u.ID, Role: u.Role, Scopes: Roles[u.Role], Session: true, CSRF: s.CSRF}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
		if h := r.Header.Get(CSRFHeader); h == "" || h != s.CSRF {
			return nil, ErrCSRF
		}
	}
	return p, nil
}

// EnsureLocalToken makes sure an admin token for the local CLI exists and returns it (stored 0600 by caller).
func (a *Service) EnsureLocalToken(ctx context.Context, existing string) (string, error) {
	if existing != "" {
		if _, err := a.S.GetTokenByHash(ctx, HashToken(existing)); err == nil {
			return existing, nil
		}
	}
	_ = a.S.DeleteToken(ctx, "local-cli")
	raw, _, err := a.CreateToken(ctx, "local-cli", []string{ScopeAdmin}, "system", 0)
	return raw, err
}

// Unlock clears a lockout.
func (a *Service) Unlock(ctx context.Context, name string) error {
	u, err := a.S.GetUserByName(ctx, name)
	if err != nil {
		return err
	}
	u.FailedLogins, u.LockedUntil = 0, time.Time{}
	return a.S.SaveUser(ctx, u)
}
