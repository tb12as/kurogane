package sshmgr

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSH-8: certificate authority with short-lived user certificates.
const (
	CAKeyPath = "/etc/serverkeeper/ssh_ca"
	CAPubPath = "/etc/ssh/serverkeeper_ca.pub"
)

// InitCA creates the CA key (once), publishes its public key and trusts it via SafeApply.
func (m *Manager) InitCA(ctx context.Context, rollback time.Duration) (string, error) {
	if _, err := m.d.Ex.ReadFile(CAKeyPath); err == nil {
		pub, err := m.d.Ex.ReadFile(CAPubPath)
		if err != nil {
			return "", fmt.Errorf("CA key exists but %s is missing: %w", CAPubPath, err)
		}
		return strings.TrimSpace(string(pub)), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "serverkeeper user CA")
	if err != nil {
		return "", err
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))) + " serverkeeper-user-ca"
	if err := m.d.Ex.WriteFile(CAKeyPath, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		return "", err
	}
	if err := m.d.Ex.WriteFile(CAPubPath, []byte(line+"\n"), 0o644); err != nil {
		return "", err
	}
	m.d.Audit.Record(ctx, "ssh.ca.init", ssh.FingerprintSHA256(sp), nil, line)
	if _, err := m.SafeApply(ctx, map[string]string{"TrustedUserCAKeys": CAPubPath}, rollback); err != nil {
		return line, fmt.Errorf("CA created but sshd not updated: %w", err)
	}
	return line, nil
}

// Sign issues a user certificate for pubkey valid for ttl (capped by ssh.ca.max_ttl).
func (m *Manager) Sign(ctx context.Context, pubkey string, principals []string, ttl time.Duration, keyID string) (string, error) {
	ca := m.d.Cfg.SSH.CA
	if ttl <= 0 {
		ttl = ca.DefaultTTL
	}
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	if ca.MaxTTL > 0 && ttl > ca.MaxTTL {
		return "", fmt.Errorf("ttl %s exceeds ssh.ca.max_ttl %s", ttl, ca.MaxTTL)
	}
	if len(principals) == 0 {
		return "", errors.New("at least one principal (login user) is required")
	}
	b, err := m.d.Ex.ReadFile(CAKeyPath)
	if err != nil {
		return "", fmt.Errorf("no SSH CA: run `serverkeeper ssh ca init` first (%w)", err)
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return "", fmt.Errorf("parse CA key: %w", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(pubkey)))
	if err != nil {
		return "", fmt.Errorf("invalid public key: %w", err)
	}
	var serial [8]byte
	_, _ = rand.Read(serial[:])
	now := m.now()
	if keyID == "" {
		keyID = strings.Join(principals, ",") + "@" + now.UTC().Format(time.RFC3339)
	}
	cert := &ssh.Certificate{Key: pub, Serial: binary.BigEndian.Uint64(serial[:]), CertType: ssh.UserCert, KeyId: keyID,
		ValidPrincipals: principals, ValidAfter: uint64(now.Add(-time.Minute).Unix()),
		ValidBefore: uint64(now.Add(ttl).Unix()),
		Permissions: ssh.Permissions{Extensions: map[string]string{"permit-pty": "", "permit-user-rc": "",
			"permit-agent-forwarding": "", "permit-port-forwarding": ""}}}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return "", err
	}
	m.d.Audit.Record(ctx, "ssh.ca.sign", keyID, nil, map[string]any{"principals": principals, "ttl": ttl.String(),
		"serial": cert.Serial, "key": ssh.FingerprintSHA256(pub)})
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))), nil
}
