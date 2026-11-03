package sshmgr

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/serverkeeper/serverkeeper/internal/audit"
	"github.com/serverkeeper/serverkeeper/internal/db"
	"github.com/serverkeeper/serverkeeper/internal/hostfs"
	"golang.org/x/crypto/ssh"
)

// Key is one authorized key as found on disk, merged with inventory metadata from the db.
type Key struct {
	db.SSHKey
	File  string   `json:"file"`
	Line  int      `json:"line"`
	Flags []string `json:"flags"` // weak-rsa, dsa, duplicate, no-label
}

// User is a local account from /etc/passwd.
type User struct {
	Name  string
	UID   int
	GID   int
	Home  string
	Shell string
}

func (u User) canLogin() bool {
	return !strings.HasSuffix(u.Shell, "/nologin") && !strings.HasSuffix(u.Shell, "/false") && u.Shell != ""
}

// Users parses /etc/passwd.
func Users() ([]User, error) {
	lines, err := hostfs.Lines("/etc/passwd")
	if err != nil {
		return nil, err
	}
	var out []User
	for _, l := range lines {
		f := strings.Split(l, ":")
		if len(f) < 7 || strings.HasPrefix(l, "#") {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		gid, _ := strconv.Atoi(f[3])
		out = append(out, User{Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: f[6]})
	}
	return out, nil
}

func lookupUser(name string) (User, error) {
	us, err := Users()
	if err != nil {
		return User{}, err
	}
	for _, u := range us {
		if u.Name == name {
			return u, nil
		}
	}
	return User{}, fmt.Errorf("user %q does not exist on this server: create it first (useradd)", name)
}

// keyFiles expands AuthorizedKeysFile tokens for u (default .ssh/authorized_keys .ssh/authorized_keys2).
func keyFiles(settings map[string]string, u User) []string {
	spec := settings["authorizedkeysfile"]
	if spec == "" || spec == "none" {
		spec = ".ssh/authorized_keys .ssh/authorized_keys2"
	}
	var out []string
	for _, p := range strings.Fields(spec) {
		p = strings.NewReplacer("%%", "%", "%h", u.Home, "%u", u.Name, "%U", strconv.Itoa(u.UID)).Replace(p)
		if !path.IsAbs(p) {
			p = path.Join(u.Home, p)
		}
		out = append(out, path.Clean(p))
	}
	return out
}

// parsedKey is one valid line of an authorized_keys file.
type parsedKey struct {
	pub     ssh.PublicKey
	comment string
	options []string
	line    int
}

// parseAuthorizedKeys parses every key line; invalid lines are skipped (they are kept on rewrite).
func parseAuthorizedKeys(b []byte) []parsedKey {
	var out []parsedKey
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for n := 1; sc.Scan(); n++ {
		l := strings.TrimSpace(sc.Text())
		if l == "" || l[0] == '#' {
			continue
		}
		pub, comment, opts, _, err := ssh.ParseAuthorizedKey([]byte(l))
		if err != nil {
			continue
		}
		out = append(out, parsedKey{pub: pub, comment: comment, options: opts, line: n})
	}
	return out
}

// Bits returns the key size in bits.
func Bits(pub ssh.PublicKey) int {
	cp, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		if strings.HasPrefix(pub.Type(), "sk-") || pub.Type() == ssh.KeyAlgoED25519 {
			return 256
		}
		return 0
	}
	switch k := cp.CryptoPublicKey().(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	}
	if pub.Type() == "ssh-dss" { // DSA: the x/crypto constant is deprecated, but such keys must still be flagged
		return 1024
	}
	return 256
}

func keyType(pub ssh.PublicKey) string {
	t := strings.TrimPrefix(pub.Type(), "ssh-")
	switch {
	case strings.HasPrefix(t, "ecdsa"):
		return "ecdsa"
	case t == "dss":
		return "dsa"
	}
	return t
}

// Keys discovers every authorized key for every local user, including root (SSH-1).
func (m *Manager) Keys(ctx context.Context, onlyUser string) ([]Key, error) {
	users, err := Users()
	if err != nil {
		return nil, err
	}
	settings, _ := m.Settings(ctx)
	meta := map[string]db.SSHKey{}
	if m.d.DB != nil {
		rows, err := m.d.DB.ListKeys(ctx, m.d.ServerID, "")
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			meta[r.User+"|"+r.Fingerprint] = r
		}
	}
	out := []Key{} // JSON [] rather than null when there are no keys
	owners := map[string]map[string]bool{}
	for _, u := range users {
		if onlyUser != "" && u.Name != onlyUser {
			continue
		}
		for _, f := range keyFiles(settings, u) {
			b, err := m.d.Ex.ReadFile(f)
			if err != nil {
				continue
			}
			for _, pk := range parseAuthorizedKeys(b) {
				fp := ssh.FingerprintSHA256(pk.pub)
				k := Key{File: f, Line: pk.line, SSHKey: db.SSHKey{ServerID: m.d.ServerID, Fingerprint: fp, User: u.Name,
					Type: keyType(pk.pub), Bits: Bits(pk.pub), Comment: pk.comment, Options: strings.Join(pk.options, ","),
					PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk.pub)))}}
				if md, ok := meta[u.Name+"|"+fp]; ok {
					k.Label, k.OwnerPerson, k.AddedAt, k.ExpiresAt, k.LastUsedAt = md.Label, md.OwnerPerson, md.AddedAt,
						md.ExpiresAt, md.LastUsedAt
				}
				if owners[fp] == nil {
					owners[fp] = map[string]bool{}
				}
				owners[fp][u.Name] = true
				out = append(out, k)
			}
		}
	}
	for i := range out {
		out[i].Flags = weakFlags(out[i], len(owners[out[i].Fingerprint]) > 1)
	}
	return out, nil
}

// weakFlags marks RSA < 3072, DSA, keys shared across users and keys with no owner label (§6.1).
func weakFlags(k Key, dup bool) []string {
	f := []string{}
	if k.Type == "rsa" && k.Bits < 3072 {
		f = append(f, "weak-rsa")
	}
	if k.Type == "dsa" {
		f = append(f, "dsa")
	}
	if dup {
		f = append(f, "duplicate")
	}
	if k.Comment == "" && k.Label == "" && k.OwnerPerson == "" {
		f = append(f, "no-label")
	}
	return f
}

// SyncKeys records discovered keys in the inventory and drops rows for keys no longer on disk.
func (m *Manager) SyncKeys(ctx context.Context) error {
	keys, err := m.Keys(ctx, "")
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, k := range keys {
		seen[k.User+"|"+k.Fingerprint] = true
		if k.AddedAt.IsZero() {
			k.AddedAt = m.now()
		}
		if err := m.d.DB.UpsertKey(ctx, k.SSHKey); err != nil {
			return err
		}
	}
	rows, err := m.d.DB.ListKeys(ctx, m.d.ServerID, "")
	if err != nil {
		return err
	}
	for _, r := range rows {
		if !seen[r.User+"|"+r.Fingerprint] {
			_ = m.d.DB.DeleteKey(ctx, r.ServerID, r.User, r.Fingerprint)
		}
	}
	return nil
}

func (m *Manager) backupFile(p string, b []byte) {
	if b == nil {
		return
	}
	dst := fmt.Sprintf("/var/lib/serverkeeper/backups/keys/%s.%s", strings.ReplaceAll(strings.TrimPrefix(p, "/"), "/", "_"),
		m.now().Format("20060102T150405"))
	_ = m.d.Ex.WriteFile(dst, b, 0o600)
}

// writeKeys writes an authorized_keys file with 0600 inside a 0700 .ssh dir owned by the user.
func (m *Manager) writeKeys(u User, file string, b []byte) error {
	dir := path.Dir(file)
	if err := m.d.Ex.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := m.d.Ex.WriteFile(file, b, 0o600); err != nil {
		return err
	}
	_ = m.d.Ex.Chown(dir, u.UID, u.GID)
	return m.d.Ex.Chown(file, u.UID, u.GID)
}

// AddKey adds a public key to user's authorized_keys (label/expiry optional) (SSH-2).
func (m *Manager) AddKey(ctx context.Context, user, pubkey, label string, expires time.Time) (db.SSHKey, error) {
	u, err := lookupUser(user)
	if err != nil {
		return db.SSHKey{}, err
	}
	pub, comment, opts, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(pubkey)))
	if err != nil {
		return db.SSHKey{}, fmt.Errorf("not a valid OpenSSH public key: %v (expected e.g. ssh-ed25519 AAAA... comment)", err)
	}
	if !expires.IsZero() && !expires.After(m.now()) {
		return db.SSHKey{}, fmt.Errorf("expiry %s is in the past", expires.Format("2006-01-02"))
	}
	settings, _ := m.Settings(ctx)
	file := keyFiles(settings, u)[0]
	old, err := m.d.Ex.ReadFile(file)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return db.SSHKey{}, err
	}
	fp := ssh.FingerprintSHA256(pub)
	exists := false
	for _, pk := range parseAuthorizedKeys(old) {
		if ssh.FingerprintSHA256(pk.pub) == fp {
			exists = true
		}
	}
	if !exists {
		line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
		if len(opts) > 0 {
			line = strings.Join(opts, ",") + " " + line
		}
		if comment == "" {
			comment = label
		}
		if comment != "" {
			line += " " + comment
		}
		nb := append([]byte{}, old...)
		if len(nb) > 0 && nb[len(nb)-1] != '\n' {
			nb = append(nb, '\n')
		}
		nb = append(nb, line+"\n"...)
		m.backupFile(file, old)
		if err := m.writeKeys(u, file, nb); err != nil {
			return db.SSHKey{}, fmt.Errorf("write %s: %w", file, err)
		}
	}
	k := db.SSHKey{ServerID: m.d.ServerID, Fingerprint: fp, User: user, Type: keyType(pub), Bits: Bits(pub),
		Label: label, Comment: comment, Options: strings.Join(opts, ","), AddedAt: m.now(), ExpiresAt: expires,
		PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))}
	if prev, err := m.d.DB.ListKeys(ctx, m.d.ServerID, user); err == nil {
		for _, p := range prev {
			if p.Fingerprint == fp {
				k.AddedAt, k.LastUsedAt, k.OwnerPerson = p.AddedAt, p.LastUsedAt, p.OwnerPerson
			}
		}
	}
	if err := m.d.DB.UpsertKey(ctx, k); err != nil {
		return k, err
	}
	m.d.Audit.Record(ctx, "ssh.key.add", user+" "+fp, nil, map[string]any{"label": label, "expires_at": expires,
		"type": k.Type, "bits": k.Bits, "already_present": exists})
	return k, nil
}

// RemoveKey removes a key by SHA256 fingerprint from user ("" = every user); returns count removed.
func (m *Manager) RemoveKey(ctx context.Context, fingerprint, user string) (int, error) {
	users, err := Users()
	if err != nil {
		return 0, err
	}
	settings, _ := m.Settings(ctx)
	n := 0
	for _, u := range users {
		if user != "" && u.Name != user {
			continue
		}
		for _, f := range keyFiles(settings, u) {
			b, err := m.d.Ex.ReadFile(f)
			if err != nil {
				continue
			}
			nb, removed := dropKey(b, fingerprint)
			if removed == 0 {
				continue
			}
			m.backupFile(f, b)
			if err := m.writeKeys(u, f, nb); err != nil {
				return n, fmt.Errorf("write %s: %w", f, err)
			}
			n += removed
			_ = m.d.DB.DeleteKey(ctx, m.d.ServerID, u.Name, fingerprint)
			m.d.Audit.Record(ctx, "ssh.key.remove", u.Name+" "+fingerprint, string(b), nil)
		}
	}
	if n == 0 {
		return 0, fmt.Errorf("key %s not found in any authorized_keys file: list keys with `serverkeeper ssh keys list`",
			fingerprint)
	}
	return n, nil
}

// dropKey removes every line holding the fingerprint and keeps everything else verbatim.
func dropKey(b []byte, fp string) ([]byte, int) {
	var out strings.Builder
	n := 0
	for _, l := range strings.SplitAfter(string(b), "\n") {
		t := strings.TrimSpace(l)
		if t != "" && t[0] != '#' {
			if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(t)); err == nil && ssh.FingerprintSHA256(pub) == fp {
				n++
				continue
			}
		}
		out.WriteString(l)
	}
	return []byte(out.String()), n
}

// UpdateKey changes inventory metadata (label, expiry, owner).
func (m *Manager) UpdateKey(ctx context.Context, fp, user string, label, owner *string, expires *time.Time) ([]db.SSHKey, error) {
	rows, err := m.d.DB.FindKeys(ctx, fp)
	if err != nil {
		return nil, err
	}
	var out []db.SSHKey
	for _, k := range rows {
		if k.ServerID != m.d.ServerID || (user != "" && k.User != user) {
			continue
		}
		before := k
		if label != nil {
			k.Label = *label
		}
		if owner != nil {
			k.OwnerPerson = *owner
		}
		if expires != nil {
			k.ExpiresAt = *expires
		}
		if err := m.d.DB.UpsertKey(ctx, k); err != nil {
			return nil, err
		}
		m.d.Audit.Record(ctx, "ssh.key.update", k.User+" "+fp, before, k)
		out = append(out, k)
	}
	if len(out) == 0 {
		return nil, db.ErrNotFound
	}
	return out, nil
}

// expire removes keys whose expiry passed (§6.1 "an expiry date removes the key automatically").
func (m *Manager) expire(ctx context.Context) {
	rows, err := m.d.DB.ListKeys(ctx, m.d.ServerID, "")
	if err != nil {
		return
	}
	actx := audit.WithActor(ctx, "system:key-expiry", "")
	for _, k := range rows {
		if k.ExpiresAt.IsZero() || k.ExpiresAt.After(m.now()) {
			continue
		}
		if _, err := m.RemoveKey(actx, k.Fingerprint, k.User); err != nil {
			_ = m.d.DB.DeleteKey(ctx, k.ServerID, k.User, k.Fingerprint)
		}
	}
}

var ghUser = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,38})$`)

// KeySourceURL is overridable in tests.
var KeySourceURL = map[string]string{"github": "https://github.com/%s.keys", "gitlab": "https://gitlab.com/%s.keys"}

// ImportKeys fetches public keys for a GitHub/GitLab username and adds them for user.
func (m *Manager) ImportKeys(ctx context.Context, source, account, user, label string, expires time.Time) ([]db.SSHKey, error) {
	tmpl, ok := KeySourceURL[source]
	if !ok || !ghUser.MatchString(account) {
		return nil, fmt.Errorf("invalid %s username %q", source, account)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(tmpl, account), nil)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s keys for %s: %w", source, account, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s keys for %s: HTTP %d (check the username)", source, account, resp.StatusCode)
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if label == "" {
		label = source + ":" + account
	}
	var out []db.SSHKey
	for _, l := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		k, err := m.AddKey(ctx, user, l, label, expires)
		if err != nil {
			return out, err
		}
		out = append(out, k)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s user %s has no public keys", source, account)
	}
	return out, nil
}

// usersWithKeys returns users that have at least one valid authorized key.
func (m *Manager) usersWithKeys(ctx context.Context, settings map[string]string) map[string]bool {
	out := map[string]bool{}
	users, _ := Users()
	for _, u := range users {
		for _, f := range keyFiles(settings, u) {
			if b, err := m.d.Ex.ReadFile(f); err == nil && len(parseAuthorizedKeys(b)) > 0 {
				out[u.Name] = true
			}
		}
	}
	return out
}
