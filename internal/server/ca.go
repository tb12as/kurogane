package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// ServerName is the DNS SAN of the central gRPC certificate; agents verify against it instead of the dial
// address, so central can be reached by any IP or name. Agent certs never carry it (CN = server id, client EKU).
const ServerName = "kurogane-central"

// CA is the central server's own certificate authority (ECDSA P-256), stored under data_dir/ca with 0600 keys.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	PEM  []byte
	Pool *x509.CertPool
}

// LoadOrCreateCA loads dir/ca.crt + dir/ca.key or creates them.
func LoadOrCreateCA(dir string) (*CA, error) {
	crt, key := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	cb, err := os.ReadFile(crt)
	if errors.Is(err, os.ErrNotExist) {
		return createCA(dir, crt, key)
	}
	if err != nil {
		return nil, err
	}
	kb, err := os.ReadFile(key)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w (restore it from backup or re-run `kurogane server init`)", key, err)
	}
	c, err := tls.X509KeyPair(cb, kb)
	if err != nil {
		return nil, fmt.Errorf("central CA in %s: %w", dir, err)
	}
	k, ok := c.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("central CA key %s is not ECDSA", key)
	}
	x, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return nil, err
	}
	return newCA(x, k, cb), nil
}

func newCA(x *x509.Certificate, k *ecdsa.PrivateKey, p []byte) *CA {
	pool := x509.NewCertPool()
	pool.AddCert(x)
	return &CA{Cert: x, Key: k, PEM: p, Pool: pool}
}

func createCA(dir, crt, key string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Kurogane central CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(20, 0, 0), IsCA: true,
		BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return nil, err
	}
	kd, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		return nil, err
	}
	p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(crt, p, 0o600); err != nil {
		return nil, err
	}
	x, _ := x509.ParseCertificate(der)
	return newCA(x, k, p), nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

// Fingerprint is the hex sha256 of a DER certificate.
func Fingerprint(der []byte) string {
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

// SignClient issues an agent client certificate with CN = server id.
// shortcut: 2-year certs without rotation; add a Renew RPC before the first agents reach expiry.
func (c *CA) SignClient(pub any, id string) ([]byte, string, error) {
	tpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: id},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(2, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.Cert, pub, c.Key)
	if err != nil {
		return nil, "", err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), Fingerprint(der), nil
}

// ServerCert issues the gRPC server certificate (in memory, chain includes the CA for token pinning).
func (c *CA) ServerCert() (tls.Certificate, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: ServerName},
		DNSNames: []string{ServerName}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.Cert, &k.PublicKey, c.Key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, c.Cert.Raw}, PrivateKey: k}, nil
}

// Pin is the CA fingerprint embedded in enrollment tokens.
func (c *CA) Pin() string { return Fingerprint(c.Cert.Raw) }
