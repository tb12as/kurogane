// Package secret encrypts webhook URLs and tokens at rest (AES-256-GCM, PRD §11.1, AL-8)
// and provides a slog handler that redacts secrets from logs.
package secret

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const prefix = "enc:"

// Box encrypts and decrypts with one key.
type Box struct{ aead cipher.AEAD }

// LoadOrCreate reads a 32-byte hex key from path (or KRGN_SECRET_KEY), creating it with mode 0600 if missing.
func LoadOrCreate(path string) (*Box, error) {
	if k := os.Getenv("KRGN_SECRET_KEY"); k != "" {
		return New(k)
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		hexKey := hex.EncodeToString(key)
		if err := os.WriteFile(path, []byte(hexKey+"\n"), 0o600); err != nil {
			return nil, fmt.Errorf("create %s: %w", path, err)
		}
		return New(hexKey)
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w (run as root or set KRGN_SECRET_KEY)", path, err)
	}
	if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s has mode %o: run chmod 600 %s", path, st.Mode().Perm(), path)
	}
	return New(strings.TrimSpace(string(b)))
}

// New builds a Box from a hex-encoded 32-byte key.
func New(hexKey string) (*Box, error) {
	key, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil || len(key) != 32 {
		return nil, errors.New("secret key must be 64 hex characters (32 bytes)")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal returns "enc:<base64(nonce|ciphertext)>".
func (b *Box) Seal(plain string) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := b.aead.Seal(nonce, nonce, []byte(plain), nil)
	return prefix + base64.RawURLEncoding.EncodeToString(ct), nil
}

// Open decrypts a sealed value; non-prefixed input is returned unchanged.
func (b *Box) Open(s string) (string, error) {
	if !strings.HasPrefix(s, prefix) {
		return s, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s[len(prefix):])
	if err != nil {
		return "", err
	}
	n := b.aead.NonceSize()
	if len(raw) < n {
		return "", errors.New("secret: ciphertext too short")
	}
	pt, err := b.aead.Open(nil, raw[:n], raw[n:], nil)
	if err != nil {
		return "", errors.New("secret: decryption failed (wrong secret.key?)")
	}
	return string(pt), nil
}

// IsSealed reports whether s is an encrypted value.
func IsSealed(s string) bool { return strings.HasPrefix(s, prefix) }

// ---- log redaction ----

var secretPatterns = regexp.MustCompile(
	`https://hooks\.slack\.com/[^\s"']+|https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/[^\s"']+|` +
		`https://api\.telegram\.org/bot[^\s"']+|sk_[A-Za-z0-9_]{20,}|enc:[A-Za-z0-9_-]{16,}`)

var secretKeys = []string{"webhook", "token", "password", "secret", "totp", "url_env_value", "authorization", "cookie"}

// Redact masks known secret shapes in s.
func Redact(s string) string { return secretPatterns.ReplaceAllString(s, "[REDACTED]") }

// RedactHandler wraps a slog.Handler and never lets secrets reach the log (AL-8).
type RedactHandler struct{ slog.Handler }

func (h RedactHandler) Handle(ctx context.Context, r slog.Record) error {
	nr := slog.NewRecord(r.Time, r.Level, Redact(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(redactAttr(a))
		return true
	})
	return h.Handler.Handle(ctx, nr)
}

func redactAttr(a slog.Attr) slog.Attr {
	k := strings.ToLower(a.Key)
	for _, s := range secretKeys {
		if strings.Contains(k, s) {
			return slog.String(a.Key, "[REDACTED]")
		}
	}
	if a.Value.Kind() == slog.KindGroup {
		attrs := a.Value.Group()
		out := make([]any, 0, len(attrs))
		for _, x := range attrs {
			out = append(out, redactAttr(x))
		}
		return slog.Group(a.Key, out...)
	}
	if a.Value.Kind() == slog.KindString || a.Value.Kind() == slog.KindAny {
		return slog.String(a.Key, Redact(a.Value.String()))
	}
	return a
}

func (h RedactHandler) WithAttrs(as []slog.Attr) slog.Handler {
	for i := range as {
		as[i] = redactAttr(as[i])
	}
	return RedactHandler{h.Handler.WithAttrs(as)}
}

func (h RedactHandler) WithGroup(n string) slog.Handler { return RedactHandler{h.Handler.WithGroup(n)} }

// SetupLogging installs a JSON slog logger with redaction (PRD §9 logging choice).
func SetupLogging(level slog.Level) {
	slog.SetDefault(slog.New(RedactHandler{slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})}))
}
