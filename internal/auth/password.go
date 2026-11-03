// Package auth implements admin login (Argon2id + mandatory TOTP + lockout), sessions with CSRF,
// scoped API tokens, RBAC roles and optional OIDC SSO (PRD §10.2, §11.1).
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 3
	argonMem     = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
)

// HashPassword returns a PHC-format argon2id hash.
func HashPassword(pw string) (string, error) {
	if len(pw) < 10 {
		return "", errors.New("password must be at least 10 characters")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	k := argon2.IDKey([]byte(pw), salt, argonTime, argonMem, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMem, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(k)), nil
}

// VerifyPassword checks pw against a PHC argon2id hash in constant time.
func VerifyPassword(hash, pw string) bool {
	p := strings.Split(hash, "$")
	if len(p) != 6 || p[1] != "argon2id" {
		return false
	}
	var m uint32
	var t uint32
	var th uint8
	if _, err := fmt.Sscanf(p[3], "m=%d,t=%d,p=%d", &m, &t, &th); err != nil {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(p[4])
	want, err2 := base64.RawStdEncoding.DecodeString(p[5])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, th, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// RandomToken returns n random bytes base64url-encoded.
func RandomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashToken returns the sha256 hex of a bearer secret; only hashes are stored.
func HashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}
