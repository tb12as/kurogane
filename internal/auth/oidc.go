package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/serverkeeper/serverkeeper/internal/config"
	"github.com/serverkeeper/serverkeeper/internal/db"
	"golang.org/x/oauth2"
)

// OIDC implements SSO login (PRD §4 "Later": SSO via OIDC).
type OIDC struct {
	cfg      config.OIDC
	provider *oidc.Provider
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// NewOIDC returns nil when OIDC is not configured.
func NewOIDC(ctx context.Context, c config.OIDC) (*OIDC, error) {
	if c.Issuer == "" {
		return nil, nil
	}
	p, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery %s: %w", c.Issuer, err)
	}
	o := &OIDC{cfg: c, provider: p, verifier: p.Verifier(&oidc.Config{ClientID: c.ClientID})}
	o.oauth = oauth2.Config{ClientID: c.ClientID, ClientSecret: os.Getenv(c.ClientSecretEnv), RedirectURL: c.RedirectURL,
		Endpoint: p.Endpoint(), Scopes: []string{oidc.ScopeOpenID, "profile", "email", "groups"}}
	return o, nil
}

// AuthURL returns the provider redirect for state.
func (o *OIDC) AuthURL(state string) string { return o.oauth.AuthCodeURL(state) }

// Callback exchanges the code and maps the identity to a local user (created as viewer, or admin
// when the configured admin group is present). OIDC replaces password+TOTP; MFA is the IdP's job.
func (a *Service) OIDCCallback(ctx context.Context, r *http.Request, ip string) (db.Session, db.User, error) {
	o := a.OIDC
	if o == nil {
		return db.Session{}, db.User{}, errors.New("oidc not configured")
	}
	tok, err := o.oauth.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		return db.Session{}, db.User{}, fmt.Errorf("oidc exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok {
		return db.Session{}, db.User{}, errors.New("oidc: no id_token in response")
	}
	idt, err := o.verifier.Verify(ctx, raw)
	if err != nil {
		return db.Session{}, db.User{}, fmt.Errorf("oidc verify: %w", err)
	}
	var claims struct {
		Email             string   `json:"email"`
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
	}
	_ = idt.Claims(&claims)
	role := "viewer"
	for _, g := range claims.Groups {
		if o.cfg.AdminGroup != "" && strings.EqualFold(g, o.cfg.AdminGroup) {
			role = "admin"
		}
	}
	u, err := a.S.GetUserByOIDC(ctx, idt.Subject)
	if errors.Is(err, db.ErrNotFound) {
		name := claims.PreferredUsername
		if name == "" {
			name = claims.Email
		}
		if name == "" {
			name = "oidc-" + idt.Subject
		}
		u = db.User{ID: db.NewID(), Username: name, Role: role, OIDCSubject: idt.Subject}
	} else if err != nil {
		return db.Session{}, db.User{}, err
	}
	u.Role = role
	if err := a.S.SaveUser(ctx, u); err != nil {
		return db.Session{}, db.User{}, err
	}
	s, err := a.NewSession(ctx, u, ip)
	return s, u, err
}
