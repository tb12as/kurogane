package checks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/tb12as/serverman/internal/certs"
)

// testCert returns a self-signed PEM certificate, generated at test time so fixtures never expire.
func testCert(names []string, days float64, rsaBits int) string {
	var pub, key any
	if rsaBits > 0 {
		k, err := rsa.GenerateKey(rand.Reader, rsaBits)
		if err != nil {
			panic(err)
		}
		pub, key = &k.PublicKey, k
	} else {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		pub, key = &k.PublicKey, k
	}
	na := time.Now().Add(time.Duration(days * float64(24*time.Hour)))
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: na.Add(-90 * 24 * time.Hour), NotAfter: na}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, key)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func tlsFixture(pemText, serverName string) Fixture {
	return Fixture{Files: map[string]string{
		"/etc/letsencrypt/renewal/example.com.conf":       "fullchain = /etc/letsencrypt/live/example.com/fullchain.pem\n",
		"/etc/letsencrypt/live/example.com/fullchain.pem": pemText,
		"/etc/nginx/nginx.conf": "http { server { server_name " + serverName + "; " +
			"ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem; } }\n",
	}}
}

func tlsCases() []scanCase {
	good := []string{"example.com", "www.example.com"}
	return []scanCase{
		{"pass", "TLS-CERT-VALID", tlsFixture(testCert(good, 60, 0), "example.com www.example.com _"), Pass},
		{"expiring", "TLS-CERT-VALID", tlsFixture(testCert(good, 3, 0), "example.com"), Fail},
		{"expired", "TLS-CERT-VALID", tlsFixture(testCert(good, -1, 0), "example.com"), Fail},
		{"weak rsa", "TLS-CERT-VALID", tlsFixture(testCert(good, 60, 1024), "example.com"), Fail},
		{"name not covered", "TLS-CERT-VALID", tlsFixture(testCert(good, 60, 0), "shop.example.com"), Fail},
		{"none", "TLS-CERT-VALID", Fixture{}, NA},
		{"unreadable only", "TLS-CERT-VALID", Fixture{Files: map[string]string{
			"/etc/nginx/nginx.conf": "http { ssl_certificate /etc/ssl/gone.pem; }\n"}}, Error},
	}
}

func TestTLSCertEvidence(t *testing.T) {
	e, _ := Setup(t, tlsFixture(testCert([]string{"example.com"}, 2, 1024), "example.com shop.example.com"))
	r := find(e, "TLS-CERT-VALID").Run(context.Background())
	for _, want := range []string{"expires in 2.0 days", "RSA key 1024 bits", "does not cover server_name shop.example.com"} {
		if !strings.Contains(r.Evidence, want) {
			t.Errorf("evidence %q lacks %q", r.Evidence, want)
		}
	}
	e.CertsOff = true
	if r := find(e, "TLS-CERT-VALID").Run(context.Background()); r.Status != NA {
		t.Fatalf("disabled: %+v", r)
	}
	// stale served certificates fail even when the file itself is fine
	c := &fnCheck{base: base{m: Meta{ID: "TLS-CERT-VALID"}}}
	r = certResult(c, []certs.Cert{{Name: "a", DaysLeft: 50, Stale: true, ServedPort: 443}})
	if r.Status != Fail || !strings.Contains(r.Evidence, "port 443 still serves the previous certificate") {
		t.Fatalf("stale: %+v", r)
	}
	r = certResult(c, []certs.Cert{{Name: "a", DaysLeft: 50}, {Name: "b", DaysLeft: 20}})
	if r.Status != Pass || r.Evidence != "2 certificate(s) valid; next expiry b in 20 days" {
		t.Fatalf("pass: %+v", r)
	}
}
