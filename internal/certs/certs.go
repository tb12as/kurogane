// Package certs finds the TLS certificates a host serves, inspects them and probes the live endpoints, so the
// collector can track expiry and the hardening check can grade them. Only CERTIFICATE PEM blocks are ever
// decoded: private keys that share a file with the chain are skipped unparsed and never stored or logged.
package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Origins of a certificate.
const (
	OriginLetsEncrypt = "letsencrypt"
	OriginNginx       = "nginx"
	OriginConfig      = "config"
	OriginLive        = "live" // seen only on a probed port, no file found
)

// maxPEM caps how much of a certificate file is read.
const maxPEM = 1 << 20

// Info is what the agent keeps about one leaf certificate.
type Info struct {
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	DNSNames    []string  `json:"dns_names,omitempty"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	KeyType     string    `json:"key_type"`
	KeyBits     int       `json:"key_bits"`
	SigAlg      string    `json:"sig_alg"`
	Fingerprint string    `json:"fingerprint"` // SHA-256 of the DER leaf, hex
	Chain       int       `json:"chain"`       // certificates in the file or handshake, leaf included
}

// Cert is one monitored certificate: a file on disk, a live endpoint, or both.
type Cert struct {
	Name        string   `json:"name"`
	Path        string   `json:"path,omitempty"`
	Origin      string   `json:"origin"`
	ServerNames []string `json:"server_names,omitempty"` // nginx server_name values that use this file
	Info
	DaysLeft float64 `json:"days_left"`
	// ServedPort is the probed port that answered with this certificate (or an older one), 0 if none.
	ServedPort int `json:"served_port,omitempty"`
	// Stale is set when the port serves an older certificate for these names than the file on disk:
	// renewed, but the web server was never reloaded.
	Stale          bool      `json:"stale"`
	ServedNotAfter time.Time `json:"served_not_after,omitzero"`
	Error          string    `json:"error,omitempty"`
}

// Days returns the days from now until t, negative once t has passed.
func Days(t, now time.Time) float64 { return t.Sub(now).Hours() / 24 }

// Weak reports why a certificate's key or signature is too weak, or "" when it is fine.
func (i Info) Weak() string {
	var w []string
	if i.KeyType == "RSA" && i.KeyBits < 2048 {
		w = append(w, fmt.Sprintf("RSA key %d bits (< 2048)", i.KeyBits))
	}
	if s := strings.ToUpper(i.SigAlg); strings.Contains(s, "SHA1") || strings.Contains(s, "MD5") {
		w = append(w, "signed with "+i.SigAlg)
	}
	return strings.Join(w, ", ")
}

// Primary is the name used for labels: the first DNS SAN, else the subject CN.
func (i Info) Primary(cn string) string {
	if len(i.DNSNames) > 0 {
		return i.DNSNames[0]
	}
	return cn
}

// Covers reports whether the certificate is valid for host (wildcards match one label).
func (i Info) Covers(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, n := range i.DNSNames {
		n = strings.ToLower(n)
		if n == host {
			return true
		}
		if rest, ok := strings.CutPrefix(n, "*."); ok {
			if _, after, ok := strings.Cut(host, "."); ok && after == rest {
				return true
			}
		}
	}
	return false
}

// ErrNoCert is returned for a file without a CERTIFICATE block.
var ErrNoCert = errors.New("no PEM CERTIFICATE block found")

// Inspect parses the leaf (first CERTIFICATE block) of a PEM bundle. Other block types, private keys
// included, are skipped without being decoded.
func Inspect(b []byte) (Info, string, error) {
	var ders [][]byte
	for len(b) > 0 {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			ders = append(ders, blk.Bytes)
		}
	}
	if len(ders) == 0 {
		return Info{}, "", ErrNoCert
	}
	c, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return Info{}, "", fmt.Errorf("parse certificate: %w", err)
	}
	i := info(c)
	i.Chain = len(ders)
	return i, c.Subject.CommonName, nil
}

func info(c *x509.Certificate) Info {
	sum := sha256.Sum256(c.Raw)
	i := Info{Subject: c.Subject.String(), Issuer: issuerName(c), DNSNames: c.DNSNames, NotBefore: c.NotBefore.UTC(),
		NotAfter: c.NotAfter.UTC(), SigAlg: c.SignatureAlgorithm.String(), Fingerprint: hex.EncodeToString(sum[:])}
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		i.KeyType, i.KeyBits = "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		i.KeyType, i.KeyBits = "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		i.KeyType, i.KeyBits = "Ed25519", 256
	default:
		i.KeyType = c.PublicKeyAlgorithm.String()
	}
	return i
}

func issuerName(c *x509.Certificate) string {
	if len(c.Issuer.Organization) > 0 && c.Issuer.CommonName != "" {
		return c.Issuer.Organization[0] + " " + c.Issuer.CommonName
	}
	if c.Issuer.CommonName != "" {
		return c.Issuer.CommonName
	}
	return c.Issuer.String()
}

// Probe performs a TLS handshake with addr using sni ("" sends none) and returns the served leaf. The
// handshake verifies nothing: the point is to read what is served, including expired certificates.
func Probe(ctx context.Context, addr, sni string, timeout time.Duration) (Info, error) {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}} // #nosec G402 -- inspection only
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Info{}, err
	}
	defer conn.Close()
	st := conn.(*tls.Conn).ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return Info{}, errors.New("no certificate served")
	}
	i := info(st.PeerCertificates[0])
	i.Chain = len(st.PeerCertificates)
	return i, nil
}

// probeName picks a concrete host name for SNI: nginx server_names first, then SANs; wildcards get "www.".
func probeName(c Cert) string {
	for _, n := range append(slices.Clone(c.ServerNames), c.DNSNames...) {
		if n == "" || n == "_" || strings.ContainsAny(n, "~$") {
			continue
		}
		if rest, ok := strings.CutPrefix(n, "*."); ok {
			return "www." + rest
		}
		if strings.HasPrefix(n, ".") {
			return "www" + n
		}
		return n
	}
	return ""
}

func addr(port int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) }
