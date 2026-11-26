package secret

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSealOpenAndKeyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secret.key")
	b, err := LoadOrCreate(p)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %o", st.Mode().Perm())
	}
	ct, _ := b.Seal("https://hooks.slack.com/services/T/B/x")
	if !IsSealed(ct) || strings.Contains(ct, "slack") {
		t.Fatal("not sealed")
	}
	pt, err := b.Open(ct)
	if err != nil || pt != "https://hooks.slack.com/services/T/B/x" {
		t.Fatal(err, pt)
	}
	b2, _ := LoadOrCreate(p)
	if pt2, _ := b2.Open(ct); pt2 != pt {
		t.Fatal("key reload mismatch")
	}
}

func TestRedactLogs(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(RedactHandler{slog.NewJSONHandler(&buf, nil)})
	l.Info("send to https://discord.com/api/webhooks/123/abc", "webhook_url", "x", "target", "https://hooks.slack.com/services/a")
	if strings.Contains(buf.String(), "discord.com/api") || strings.Contains(buf.String(), "hooks.slack.com") ||
		strings.Contains(buf.String(), `"webhook_url":"x"`) {
		t.Fatal(buf.String())
	}
}

func TestRedactAPITokenLogs(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(RedactHandler{slog.NewJSONHandler(&buf, nil)})
	const token = "krgn_ab-cdEFghij_klmnopqrstuvwxyz0123456789"
	l.Info(token, "value", token)
	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"msg", "value"} {
		if record[key] != "[REDACTED]" {
			t.Errorf("%s = %q, want [REDACTED]", key, record[key])
		}
	}
}

func TestKeyErrorsAndGroups(t *testing.T) {
	if _, err := New("short"); err == nil {
		t.Fatal("short key must fail")
	}
	b, _ := New(strings.Repeat("ab", 32))
	if v, _ := b.Open("plain"); v != "plain" {
		t.Fatal("unsealed passthrough")
	}
	if _, err := b.Open("enc:!!"); err == nil {
		t.Fatal("bad base64 must fail")
	}
	other, _ := New(strings.Repeat("cd", 32))
	ct, _ := other.Seal("x")
	if _, err := b.Open(ct); err == nil {
		t.Fatal("wrong key must fail")
	}
	p := filepath.Join(t.TempDir(), "k")
	os.WriteFile(p, []byte(strings.Repeat("ab", 32)), 0o644)
	if _, err := LoadOrCreate(p); err == nil {
		t.Fatal("world-readable key must be refused")
	}
	var buf bytes.Buffer
	l := slog.New(RedactHandler{slog.NewJSONHandler(&buf, nil)}).With("token", "abc").WithGroup("g")
	l.Info("m", slog.Group("ch", "webhook", "https://hooks.slack.com/services/x"), "n", 3)
	if strings.Contains(buf.String(), "abc") || strings.Contains(buf.String(), "hooks.slack.com") {
		t.Fatal(buf.String())
	}
}
