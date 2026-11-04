package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tb12as/serverman/internal/hostfs"
)

// Certificates are generated at test time: committed fixtures would expire and break CI.

type pair struct {
	certPEM, keyPEM []byte
	tls             tls.Certificate
}

func gen(t *testing.T, names []string, notAfter time.Time, rsaBits int) pair {
	t.Helper()
	var key any
	var pub any
	if rsaBits > 0 {
		k, err := rsa.GenerateKey(rand.Reader, rsaBits)
		if err != nil {
			t.Fatal(err)
		}
		key, pub = k, &k.PublicKey
	} else {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, pub = k, &k.PublicKey
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	cn := "test"
	if len(names) > 0 {
		cn = names[0]
	}
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
		Issuer: pkix.Name{CommonName: "Test CA"}, DNSNames: names, NotBefore: notAfter.Add(-90 * 24 * time.Hour),
		NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	p := pair{certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})}
	p.tls, err = tls.X509KeyPair(p.certPEM, p.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type fsReader struct{ reads []string }

func (f *fsReader) ReadFile(p string) ([]byte, error) {
	f.reads = append(f.reads, p)
	return os.ReadFile(hostfs.P(p))
}

func root(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := hostfs.Root
	hostfs.Root = dir
	t.Cleanup(func() { hostfs.Root = old })
	return dir
}

func write(t *testing.T, dir, p string, b []byte) {
	t.Helper()
	full := filepath.Join(dir, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestInspect(t *testing.T) {
	exp := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	leaf, ca := gen(t, []string{"example.com", "www.example.com"}, exp, 2048), gen(t, nil, exp, 0)
	// key first, then leaf and chain: the key block must be skipped
	bundle := append(append(append([]byte{}, leaf.keyPEM...), leaf.certPEM...), ca.certPEM...)
	i, cn, err := Inspect(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if cn != "example.com" || i.Primary(cn) != "example.com" || i.Chain != 2 || i.KeyType != "RSA" ||
		i.KeyBits != 2048 || !i.NotAfter.Equal(exp.UTC()) || len(i.Fingerprint) != 64 || i.Issuer != "example.com" {
		t.Fatalf("info = %+v cn=%q", i, cn)
	}
	if w := i.Weak(); w != "" {
		t.Fatalf("weak = %q", w)
	}
	ec, _, err := Inspect(ca.certPEM)
	if err != nil || ec.KeyType != "ECDSA" || ec.KeyBits != 256 {
		t.Fatalf("ecdsa = %+v %v", ec, err)
	}
	if _, _, err := Inspect(leaf.keyPEM); err != ErrNoCert {
		t.Fatalf("key only: %v", err)
	}
	if _, _, err := Inspect([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")); err == nil {
		t.Fatal("garbage parsed")
	}
}

func TestWeakAndCovers(t *testing.T) {
	w := Info{KeyType: "RSA", KeyBits: 1024, SigAlg: "SHA1-RSA"}.Weak()
	if !strings.Contains(w, "1024") || !strings.Contains(w, "SHA1-RSA") {
		t.Fatalf("weak = %q", w)
	}
	i := Info{DNSNames: []string{"*.example.com", "example.com"}}
	for host, want := range map[string]bool{"example.com": true, "a.example.com": true, "A.Example.com.": true,
		"a.b.example.com": false, "example.org": false} {
		if i.Covers(host) != want {
			t.Errorf("Covers(%q) != %v", host, want)
		}
	}
	if Days(time.Unix(0, 0), time.Unix(0, 0).Add(36*time.Hour)) != -1.5 {
		t.Fatal("days")
	}
}

func fixture(t *testing.T) (string, map[string]pair) {
	dir := root(t)
	now := time.Now()
	ps := map[string]pair{
		"le":    gen(t, []string{"example.com", "www.example.com"}, now.Add(60*24*time.Hour), 0),
		"shop":  gen(t, []string{"shop.example.org"}, now.Add(5*24*time.Hour), 0),
		"api":   gen(t, []string{"*.api.example.net"}, now.Add(-24*time.Hour), 0),
		"extra": gen(t, []string{"mail.example.com"}, now.Add(200*24*time.Hour), 0),
	}
	write(t, dir, "etc/letsencrypt/renewal/example.com.conf",
		[]byte("version = 2.11.0\n[renewalparams]\ncert = /etc/letsencrypt/live/example.com/cert.pem\n"+
			"fullchain = /etc/letsencrypt/live/example.com/fullchain.pem\n"))
	write(t, dir, "etc/letsencrypt/live/example.com/fullchain.pem", ps["le"].certPEM)
	write(t, dir, "etc/letsencrypt/live/example.com/privkey.pem", ps["le"].keyPEM)
	write(t, dir, "etc/letsencrypt/live/README", []byte("x"))
	write(t, dir, "etc/nginx/nginx.conf", []byte(`
user www-data;
events { worker_connections 768; }
http {
    ssl_certificate certs/default.pem;   # relative to /etc/nginx
    include /etc/nginx/conf.d/*.conf;
    include sites-enabled/*;
}`))
	write(t, dir, "etc/nginx/certs/default.pem", ps["extra"].certPEM)
	write(t, dir, "etc/nginx/conf.d/missing-include.conf", []byte("include /etc/nginx/nope/*.conf;\n"))
	write(t, dir, "etc/nginx/sites-enabled/example", []byte(`
server {
    listen 443 ssl;
    server_name example.com www.example.com;
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    location / { root /var/www; }
}
server {
    listen 443 ssl;
    server_name shop.example.org;
    include snippets/shop-ssl.conf;
}
server {
    server_name ~^(?<sub>.+)\.dyn\.example$;
    ssl_certificate /etc/ssl/$ssl_server_name.pem;
}`))
	write(t, dir, "etc/nginx/snippets/shop-ssl.conf", []byte("ssl_certificate \"/etc/ssl/shop chain.pem\";\n"+
		"ssl_certificate_key /etc/ssl/shop.key;\n"))
	write(t, dir, "etc/ssl/shop chain.pem", ps["shop"].certPEM)
	write(t, dir, "srv/api.pem", append(append([]byte{}, ps["api"].keyPEM...), ps["api"].certPEM...))
	return dir, ps
}

func TestDiscover(t *testing.T) {
	fixture(t)
	srcs := Discover(&fsReader{}, []string{"/srv/api.pem", "/srv/api.key", "relative.pem", ""})
	var got []string
	for _, s := range srcs {
		got = append(got, s.Origin+":"+s.Path+":"+s.Lineage+":"+strings.Join(s.ServerNames, ","))
	}
	want := []string{
		"letsencrypt:/etc/letsencrypt/live/example.com/fullchain.pem:example.com:example.com,www.example.com",
		"nginx:/etc/ssl/shop chain.pem::shop.example.org",
		"nginx:/etc/nginx/certs/default.pem::",
		"config:/srv/api.pem::",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestDiscoverLiveFallback(t *testing.T) {
	dir := root(t)
	write(t, dir, "etc/letsencrypt/live/a.example/fullchain.pem", []byte("x"))
	srcs := Discover(&fsReader{}, nil)
	if len(srcs) != 1 || srcs[0].Lineage != "a.example" || srcs[0].Origin != OriginLetsEncrypt {
		t.Fatalf("%+v", srcs)
	}
}

func TestScanFiles(t *testing.T) {
	fixture(t)
	r := &fsReader{}
	cs := Scan(context.Background(), r, Options{Paths: []string{"/srv/api.pem", "/srv/missing.pem"}})
	by := map[string]Cert{}
	for _, c := range cs {
		by[c.Name] = c
	}
	if len(cs) != 5 {
		t.Fatalf("%d certs: %+v", len(cs), cs)
	}
	if c := by["example.com"]; c.Origin != OriginLetsEncrypt || c.DaysLeft < 59 || c.DaysLeft > 60 {
		t.Fatalf("le = %+v", c)
	}
	if c := by["shop.example.org"]; c.DaysLeft > 5 || c.DaysLeft < 4 || c.ServerNames[0] != "shop.example.org" {
		t.Fatalf("shop = %+v", c)
	}
	if c := by["*.api.example.net"]; c.DaysLeft > -0.9 {
		t.Fatalf("expired = %+v", c)
	}
	if c := by["srv/missing.pem"]; c.Error != "file not found" {
		t.Fatalf("missing = %+v", by)
	}
	for _, p := range r.reads {
		if strings.Contains(p, "privkey") || strings.HasSuffix(p, ".key") {
			t.Fatalf("read a key file: %s", p)
		}
	}
}

// tlsServer serves certs by SNI on 127.0.0.1 and returns its port.
func tlsServer(t *testing.T, bySNI map[string]tls.Certificate, def tls.Certificate) int {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if c, ok := bySNI[h.ServerName]; ok {
			return &c, nil
		}
		return &def, nil
	}, Certificates: []tls.Certificate{def}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestScanProbe(t *testing.T) {
	_, ps := fixture(t)
	now := time.Now()
	oldShop := gen(t, []string{"shop.example.org"}, now.Add(2*24*time.Hour), 0)
	unknown := gen(t, []string{"caddy.example"}, now.Add(10*24*time.Hour), 0)
	port := tlsServer(t, map[string]tls.Certificate{"example.com": ps["le"].tls, "shop.example.org": oldShop.tls},
		unknown.tls)
	// a closed port must be skipped quickly
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	cs := Scan(context.Background(), &fsReader{}, Options{Ports: []int{closed, port}, Timeout: time.Second})
	by := map[string]Cert{}
	for _, c := range cs {
		by[c.Name] = c
	}
	if c := by["example.com"]; c.ServedPort != port || c.Stale {
		t.Fatalf("le = %+v", c)
	}
	if c := by["shop.example.org"]; c.ServedPort != port || !c.Stale || !c.ServedNotAfter.Equal(oldShop.notAfter(t)) {
		t.Fatalf("shop = %+v", c)
	}
	if c := by["caddy.example"]; c.Origin != OriginLive || c.ServedPort != port || c.DaysLeft < 9 {
		t.Fatalf("live = %+v (all %+v)", c, cs)
	}
	if len(cs) != 4 { // three files plus the live-only default certificate
		t.Fatalf("%d certs", len(cs))
	}
}

func (p pair) notAfter(t *testing.T) time.Time {
	c, err := x509.ParseCertificate(p.tls.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return c.NotAfter.UTC()
}

func TestProbeName(t *testing.T) {
	for _, tc := range []struct {
		c    Cert
		want string
	}{
		{Cert{ServerNames: []string{"_", "~^x$", "a.example"}}, "a.example"},
		{Cert{ServerNames: []string{".example.org"}}, "www.example.org"},
		{Cert{Info: Info{DNSNames: []string{"*.example.net"}}}, "www.example.net"},
		{Cert{}, ""},
	} {
		if got := probeName(tc.c); got != tc.want {
			t.Errorf("probeName(%+v) = %q, want %q", tc.c, got, tc.want)
		}
	}
}

func TestDiscoverApache(t *testing.T) {
	dir := root(t)
	write(t, dir, "etc/httpd/conf/httpd.conf", []byte("ServerRoot /etc/httpd\nIncludeOptional conf.d/*.conf\n"+
		"SSLCertificateFile /etc/pki/tls/certs/localhost.crt\n"))
	write(t, dir, "etc/httpd/conf.d/shop.conf", []byte("<VirtualHost *:443>\nServerName shop.example.org\n"+
		"ServerAlias www.shop.example.org\nSSLEngine on\nSSLCertificateFile certs/shop.pem\n"+
		"SSLCertificateKeyFile /etc/httpd/certs/shop.key\n</VirtualHost>\n"))
	srcs := Discover(&fsReader{}, nil)
	var got []string
	for _, s := range srcs {
		got = append(got, s.Origin+":"+s.Path+":"+strings.Join(s.ServerNames, ","))
	}
	want := "apache:/etc/httpd/certs/shop.pem:shop.example.org,www.shop.example.org\n" +
		"apache:/etc/pki/tls/certs/localhost.crt:"
	if strings.Join(got, "\n") != want {
		t.Fatalf("got\n%s", strings.Join(got, "\n"))
	}
}
