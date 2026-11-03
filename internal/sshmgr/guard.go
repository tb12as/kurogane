package sshmgr

import (
	"context"
	"errors"
	"path"
	"strconv"
	"strings"

	"github.com/serverkeeper/serverkeeper/internal/hostfs"
)

// groups returns each user's group names (primary + supplementary) from /etc/group.
func groups(users []User) map[string][]string {
	byGID := map[string]string{}
	out := map[string][]string{}
	lines, _ := hostfs.Lines("/etc/group")
	for _, l := range lines {
		f := strings.Split(l, ":")
		if len(f) < 4 {
			continue
		}
		byGID[f[2]] = f[0]
		for _, u := range strings.Split(f[3], ",") {
			if u != "" {
				out[u] = append(out[u], f[0])
			}
		}
	}
	for _, u := range users {
		if g, ok := byGID[strconv.Itoa(u.GID)]; ok {
			out[u.Name] = append(out[u.Name], g)
		}
	}
	return out
}

func matchAny(pats string, name string) bool {
	for _, p := range strings.Fields(pats) {
		u, _, _ := strings.Cut(p, "@")
		for _, alt := range strings.Split(u, ",") {
			neg := strings.HasPrefix(alt, "!")
			if ok, _ := path.Match(strings.TrimPrefix(alt, "!"), name); ok && !neg {
				return true
			}
		}
	}
	return false
}

// allowedUser applies DenyUsers, AllowUsers, DenyGroups, AllowGroups in sshd order.
func allowedUser(eff map[string]string, u string, gs []string) bool {
	if matchAny(eff["denyusers"], u) {
		return false
	}
	if a := eff["allowusers"]; a != "" && !matchAny(a, u) {
		return false
	}
	for _, g := range gs {
		if matchAny(eff["denygroups"], g) {
			return false
		}
	}
	if a := eff["allowgroups"]; a != "" {
		for _, g := range gs {
			if matchAny(a, g) {
				return true
			}
		}
		return false
	}
	return true
}

// loginPath describes how a user could still log in.
type loginPath struct {
	user  string
	admin bool // in sudo/wheel/admin
}

// loginPaths lists users that can log in under eff: allowed, valid shell, and a usable key or password.
func (m *Manager) loginPaths(ctx context.Context, eff map[string]string) []loginPath {
	users, _ := Users()
	gs := groups(users)
	keys := m.usersWithKeys(ctx, eff)
	pw := m.usersWithPassword()
	am := strings.ToLower(eff["authenticationmethods"])
	keyAllowed := !strings.EqualFold(eff["pubkeyauthentication"], "no") &&
		(am == "" || am == "any" || strings.Contains(am, "publickey"))
	passAllowed := (strings.EqualFold(eff["passwordauthentication"], "yes") ||
		strings.EqualFold(eff["kbdinteractiveauthentication"], "yes")) &&
		(am == "" || am == "any" || strings.Contains(am, "password") || strings.Contains(am, "keyboard-interactive"))
	var out []loginPath
	for _, u := range users {
		if !u.canLogin() || !allowedUser(eff, u.Name, gs[u.Name]) {
			continue
		}
		prl := strings.ToLower(eff["permitrootlogin"])
		root := u.UID == 0
		if root && prl == "no" {
			continue
		}
		ok := keyAllowed && keys[u.Name]
		if passAllowed && pw[u.Name] && (!root || prl == "yes") {
			ok = true
		}
		if !ok {
			continue
		}
		admin := root
		for _, g := range gs[u.Name] {
			if g == "sudo" || g == "wheel" || g == "admin" {
				admin = true
			}
		}
		out = append(out, loginPath{user: u.Name, admin: admin && !root})
	}
	return out
}

// usersWithPassword reads /etc/shadow (root only); unreadable means "unknown" and counts as no password.
func (m *Manager) usersWithPassword() map[string]bool {
	out := map[string]bool{}
	b, err := m.d.Ex.ReadFile("/etc/shadow")
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Split(l, ":")
		if len(f) > 1 && f[1] != "" && f[1][0] != '!' && f[1][0] != '*' {
			out[f[0]] = true
		}
	}
	return out
}

// guard refuses changes that would leave no working login path (SSH-4).
func (m *Manager) guard(ctx context.Context, cur, next map[string]string) error {
	before := m.loginPaths(ctx, cur)
	after := m.loginPaths(ctx, next)
	if len(after) == 0 && len(before) > 0 {
		if strings.EqualFold(next["passwordauthentication"], "no") && !strings.EqualFold(cur["passwordauthentication"], "no") {
			return errors.New("refusing to disable password authentication: no allowed user has a working SSH key. " +
				"Add a key first (`serverkeeper ssh keys add --user <name> --file key.pub`), log in with it, then retry")
		}
		return errors.New("refusing change: it would leave no user able to log in over SSH " +
			"(check AllowUsers/AllowGroups/DenyUsers and that at least one allowed user has a key)")
	}
	if strings.EqualFold(next["permitrootlogin"], "no") && !strings.EqualFold(cur["permitrootlogin"], "no") {
		for _, p := range after {
			if p.admin {
				return nil
			}
		}
		return errors.New("refusing to disable root login: no other user in sudo/wheel can log in over SSH. " +
			"Create one with a key and sudo rights first, log in as that user, then retry")
	}
	return nil
}
