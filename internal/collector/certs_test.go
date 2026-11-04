package collector

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tb12as/serverman/internal/config"
	"github.com/tb12as/serverman/internal/executor"
	"github.com/tb12as/serverman/internal/hostfs"
)

// writeCert writes a self-signed certificate for name expiring at notAfter (generated, never committed).
func writeCert(t *testing.T, dir, p, name string, notAfter time.Time) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: notAfter.Add(-90 * 24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(dir, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCertCollector(t *testing.T) {
	adv := clock(t)
	dir := t.TempDir()
	old := hostfs.Root
	hostfs.Root = dir
	t.Cleanup(func() { hostfs.Root = old })
	start := now()
	writeCert(t, dir, "etc/letsencrypt/live/example.com/fullchain.pem", "example.com", start.Add(10*24*time.Hour))
	writeCert(t, dir, "srv/extra.pem", "extra.example", start.Add(-time.Hour))

	cfg := config.Collector{Interval: 10 * time.Second,
		Certs: config.Certs{Enabled: true, Paths: []string{"/srv/extra.pem", "/srv/gone.pem"}, Interval: time.Hour}}
	m := NewManager(cfg, executor.Local{})
	if !m.CertsEnabled() {
		t.Fatal("certs disabled")
	}
	// before the first scan: no samples, no list
	if s := m.collect(ctx, 0); len(s.Certs) != 0 {
		t.Fatalf("certs before scan: %+v", s.Certs)
	}
	list, at := m.RescanCerts(ctx)
	if len(list) != 3 || !at.Equal(start) {
		t.Fatalf("rescan = %+v at %v", list, at)
	}
	adv(24 * time.Hour)
	s := m.collect(ctx, 0)
	if v := get(t, s.Samples, `cert.days_left{name="example.com"}`); v != 9 {
		t.Fatalf("days_left = %v, want 9 (recomputed each tick)", v)
	}
	if v := get(t, s.Samples, `cert.days_left{name="extra.example"}`); v > -1 {
		t.Fatalf("expired days_left = %v", v)
	}
	if v := get(t, s.Samples, `cert.stale_served{name="example.com"}`); v != 0 {
		t.Fatalf("stale = %v", v)
	}
	for _, x := range s.Samples {
		if x.Labels["name"] == "srv/gone.pem" {
			t.Fatal("unreadable cert produced samples")
		}
	}
	if len(s.Certs) != 3 || s.Certs[0].DaysLeft != 9 {
		t.Fatalf("snapshot certs = %+v", s.Certs)
	}
	if got, _ := m.Certs(); len(got) != 3 {
		t.Fatalf("Certs() = %+v", got)
	}

	off := NewManager(config.Collector{Interval: time.Second}, executor.Local{})
	if l, at := off.Certs(); off.CertsEnabled() || l != nil || !at.IsZero() {
		t.Fatal("disabled manager reports certs")
	}
	if l, _ := off.RescanCerts(ctx); l != nil {
		t.Fatal("disabled rescan")
	}
}

func TestCertCollectorDefaults(t *testing.T) {
	c := newCerts(config.Certs{Enabled: true}, nil)
	if c.every != time.Hour {
		t.Fatalf("every = %v", c.every)
	}
	if _, ok := c.r.(hostReader); !ok {
		t.Fatal("nil executor must fall back to host reads")
	}
}

type constCollector struct{}

func (constCollector) Collect(context.Context) ([]Sample, error) {
	return []Sample{{Metric: "web.config_ok", Labels: map[string]string{"server": "nginx"}, Value: 1}}, nil
}

func TestAddCollectorAndWatch(t *testing.T) {
	root(t, "t1")
	ex := executor.NewFake()
	ex.Outputs["systemctl show -p ActiveState,SubState -- ssh nginx"] = "ActiveState=active\nSubState=running\n\n" +
		"ActiveState=failed\nSubState=failed\n"
	m := NewManager(config.Collector{Interval: time.Second, WatchServices: []string{"ssh"}}, ex)
	m.AddCollector("web", constCollector{})
	m.Watch("nginx", "ssh")
	s := m.collect(ctx, 0)
	get(t, s.Samples, `web.config_ok{server="nginx"}`)
	if v := get(t, s.Samples, `service.active{unit="nginx"}`); v != 0 {
		t.Fatalf("nginx active = %v", v)
	}
}
