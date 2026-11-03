package auth

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tb12as/serverman/internal/config"
	"github.com/tb12as/serverman/internal/db"
	"github.com/tb12as/serverman/internal/secret"
)

func TestTOTPVector(t *testing.T) {
	// RFC 6238 SHA1 vector: secret "12345678901234567890", T=59 -> 94287082 (8 digits) -> 287082
	sec := b32.EncodeToString([]byte("12345678901234567890"))
	c, _ := TOTPCode(sec, time.Unix(59, 0))
	if c != "287082" {
		t.Fatal(c)
	}
	if !VerifyTOTP(sec, c, time.Unix(59+30, 0)) || VerifyTOTP(sec, c, time.Unix(59+120, 0)) {
		t.Fatal("skew window wrong")
	}
}

func TestLoginLockoutCSRFScopes(t *testing.T) {
	s, err := db.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	box, _ := secret.New(strings.Repeat("ab", 32))
	a := NewService(s, box, time.Hour)
	ctx := context.Background()
	u, url, err := a.CreateUser(ctx, "admin", "correct horse battery", "admin")
	if err != nil || !strings.HasPrefix(url, "otpauth://") {
		t.Fatal(err)
	}
	sec, _ := box.Open(u.TOTPSecret)
	code, _ := TOTPCode(sec, time.Now())
	if _, _, err := a.Login(ctx, "admin", "correct horse battery", "000000", ""); err == nil {
		t.Fatal("wrong totp must fail")
	}
	sess, _, err := a.Login(ctx, "admin", "correct horse battery", code, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/api/v1/ssh/keys", nil)
	r.Header.Set("Cookie", SessionCookie+"="+sess.ID)
	if _, err := a.Authenticate(r); err != ErrCSRF {
		t.Fatalf("want csrf error, got %v", err)
	}
	r.Header.Set(CSRFHeader, sess.CSRF)
	if p, err := a.Authenticate(r); err != nil || !p.Has(ScopeSSH) {
		t.Fatal(err)
	}
	for i := 0; i < MaxFailures; i++ {
		a.Login(ctx, "admin", "bad password!!", code, "")
	}
	if _, _, err := a.Login(ctx, "admin", "correct horse battery", code, ""); err != ErrLocked {
		t.Fatalf("want lock, got %v", err)
	}

	raw, _, _ := a.CreateToken(ctx, "ci", []string{ScopeRead}, "admin", 0)
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	p, err := a.Authenticate(r)
	if err != nil || p.Has(ScopeSSH) || !p.Has(ScopeRead) {
		t.Fatal("token scopes wrong", err)
	}
}

func TestTokensAndEdges(t *testing.T) {
	s, _ := db.Open(filepath.Join(t.TempDir(), "a.db"))
	defer s.Close()
	box, _ := secret.New(strings.Repeat("ab", 32))
	a := NewService(s, box, 0)
	ctx := context.Background()
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("short password must fail")
	}
	if VerifyPassword("garbage", "x") || VerifyPassword("$argon2id$v=19$m=1,t=1,p=1$!!$!!", "x") {
		t.Fatal("malformed hash must not verify")
	}
	if _, _, err := a.CreateUser(ctx, "u", "correct horse battery", "root"); err == nil {
		t.Fatal("unknown role must fail")
	}
	if _, _, err := a.Login(ctx, "nobody", "x", "000000", ""); err != ErrBadCredentials {
		t.Fatal("unknown user must be bad credentials")
	}
	tok, err := a.EnsureLocalToken(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if same, _ := a.EnsureLocalToken(ctx, tok); same != tok {
		t.Fatal("existing valid token must be kept")
	}
	if rotated, _ := a.EnsureLocalToken(ctx, "sk_stale"); rotated == tok {
		t.Fatal("stale token must be rotated")
	}
	raw, _, _ := a.CreateToken(ctx, "short", []string{ScopeRead}, "t", time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	if _, err := a.Authenticate(r); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired token: %v", err)
	}
	r = httptest.NewRequest("GET", "/", nil)
	if _, err := a.Authenticate(r); err != ErrUnauthorized {
		t.Fatal("no credentials must be unauthorized")
	}
	r.Header.Set("Cookie", SessionCookie+"=nope")
	if _, err := a.Authenticate(r); err != ErrUnauthorized {
		t.Fatal("bad session must be unauthorized")
	}
	if err := a.Unlock(ctx, "nobody"); err == nil {
		t.Fatal("unlock unknown user must fail")
	}
	if o, err := NewOIDC(ctx, config.OIDC{}); o != nil || err != nil {
		t.Fatal("empty OIDC config must disable SSO")
	}
	if !strings.Contains(TOTPURL("SK", "a b", "S"), "otpauth://totp/") || VerifyTOTP("!!", "123456", time.Now()) {
		t.Fatal("totp helpers")
	}
}
