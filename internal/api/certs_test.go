package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tb12as/kurogane/internal/collector"
	"github.com/tb12as/kurogane/internal/config"
	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/hostfs"
)

func TestCertsHandlers(t *testing.T) {
	s := &Server{}
	if _, err := s.certs(nil); err == nil || err.(*HTTPError).Code != 503 {
		t.Fatalf("certs without collector: %v", err)
	}
	if _, err := s.rescanCerts(nil); err == nil || err.(*HTTPError).Code != 503 {
		t.Fatalf("rescan without collector: %v", err)
	}
	s.Metrics = collector.NewManager(config.Collector{Interval: time.Second}, executor.NewFake())
	if _, err := s.rescanCerts(nil); err == nil || err.(*HTTPError).Code != 409 {
		t.Fatalf("rescan while disabled: %v", err)
	}
	v, err := s.certs(nil)
	if r := v.(CertsResponse); err != nil || r.Enabled || r.Certs == nil {
		t.Fatalf("disabled: %+v %v", v, err)
	}
}

func TestCertsRoutes(t *testing.T) {
	st := newStack(t)
	// the stack's fixture root is hostfs.Root: add a Let's Encrypt lineage to it
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"},
		DNSNames: []string{"example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(20 * 24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	p := hostfs.P("/etc/letsencrypt/live/example.com/fullchain.pem")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	st.srv.Cfg.Collector.Certs = config.Certs{Enabled: true, Interval: time.Hour}
	st.srv.Metrics = collector.NewManager(st.srv.Cfg.Collector, st.srv.Ex)

	var r CertsResponse
	json.Unmarshal(st.do("GET", "/api/v1/certs", st.read, nil, 200), &r)
	if !r.Enabled || !r.ScannedAt.IsZero() || len(r.Certs) != 0 {
		t.Fatalf("before scan: %+v", r)
	}
	json.Unmarshal(st.do("POST", "/api/v1/certs/rescan", st.read, nil, 200), &r)
	if len(r.Certs) != 1 || r.Certs[0].Name != "example.com" || r.Certs[0].DaysLeft < 19 || r.ScannedAt.IsZero() {
		t.Fatalf("rescan: %+v", r)
	}
	// within the cooldown the cached scan comes back
	first := r.ScannedAt
	json.Unmarshal(st.do("POST", "/api/v1/certs/rescan", st.read, nil, 200), &r)
	if !r.ScannedAt.Equal(first) {
		t.Fatal("rescan inside the cooldown scanned again")
	}
	st.do("GET", "/api/v1/certs", "", nil, 401)
}
