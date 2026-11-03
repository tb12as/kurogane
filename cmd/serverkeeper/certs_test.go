package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/tb12as/serverman/internal/api"
	"github.com/tb12as/serverman/internal/certs"
)

func TestPrintCerts(t *testing.T) {
	at := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	list := []certs.Cert{
		{Name: "example.com", Origin: certs.OriginLetsEncrypt, DaysLeft: 40, ServedPort: 443,
			Info: certs.Info{Issuer: "Let's Encrypt R11", NotAfter: at.Add(40 * 24 * time.Hour)}},
		{Name: "shop.example.org", Origin: certs.OriginNginx, DaysLeft: 60, Stale: true, ServedPort: 443,
			Info: certs.Info{KeyType: "RSA", KeyBits: 1024}},
		{Name: "srv/gone.pem", Origin: certs.OriginConfig, Path: "/srv/gone.pem", Error: "file not found"},
	}
	var b bytes.Buffer
	printCerts(&b, api.CertsResponse{Enabled: true, ScannedAt: at, Certs: list})
	out := b.String()
	for _, want := range []string{"NAME", "example.com", "40.0", ":443", "stale: reload the web server",
		"RSA key 1024 bits", "/srv/gone.pem: file not found", "scanned "} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if n := certProblems(list, 14); n != 2 {
		t.Errorf("problems = %d, want 2 (stale + unreadable)", n)
	}
	if n := certProblems(list, 45); n != 3 {
		t.Errorf("problems at 45 days = %d", n)
	}
	for r, want := range map[*api.CertsResponse]string{
		{}:                             "monitoring is off",
		{Enabled: true}:                "no scan yet",
		{Enabled: true, ScannedAt: at}: "no certificates found",
	} {
		b.Reset()
		printCerts(&b, *r)
		if !strings.Contains(b.String(), want) {
			t.Errorf("%+v: %q lacks %q", r, b.String(), want)
		}
	}
}
