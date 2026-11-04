package executor

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/tb12as/serverman/internal/hostfs"
)

// Web site toggling only moves files: it links or unlinks a sites-available file in sites-enabled (Debian), or
// renames X.conf to X.conf.disabled and back in conf.d. No operation here writes file contents, so a worker
// can switch existing sites on and off but can never put new configuration in front of nginx or Apache.

// linkDirs maps each sites-enabled directory to its sites-available directory.
var linkDirs = map[string]string{
	"/etc/nginx/sites-enabled":   "/etc/nginx/sites-available",
	"/etc/apache2/sites-enabled": "/etc/apache2/sites-available",
}

// renameDirs are the conf.d directories where sites are toggled by renaming.
var renameDirs = map[string]bool{"/etc/nginx/conf.d": true, "/etc/httpd/conf.d": true}

// siteFile is a plain file name: no slashes, no leading dot, no "..".
var siteFile = regexp.MustCompile(`^[A-Za-z0-9_@+-][A-Za-z0-9._@+-]*$`)

func plainName(p string) (dir, base string, err error) {
	if !path.IsAbs(p) || path.Clean(p) != p {
		return "", "", fmt.Errorf("%w: %q is not a clean absolute path", ErrDenied, p)
	}
	dir, base = path.Dir(p), path.Base(p)
	if !siteFile.MatchString(base) || strings.Contains(base, "..") {
		return "", "", fmt.Errorf("%w: %q is not a plain file name", ErrDenied, base)
	}
	return dir, base, nil
}

// LinkSite enables a Debian-layout site: link is <sites-enabled>/<name>, target <sites-available>/<name>.
// The link is created relative ("../sites-available/<name>"), as a2ensite does.
func (Local) LinkSite(target, link string) error {
	dir, base, err := plainName(link)
	if err != nil {
		return err
	}
	avail, ok := linkDirs[dir]
	if !ok {
		return fmt.Errorf("%w: link %s outside a sites-enabled directory", ErrDenied, link)
	}
	if target != avail+"/"+base {
		return fmt.Errorf("%w: link target must be %s/%s", ErrDenied, avail, base)
	}
	fi, err := os.Lstat(hostfs.P(target))
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrDenied, target)
	}
	if _, err := os.Lstat(hostfs.P(link)); err == nil {
		return fmt.Errorf("%s already exists", link)
	}
	slog.Info("executor link site", "link", link, "target", target)
	return os.Symlink("../"+path.Base(avail)+"/"+base, hostfs.P(link))
}

// UnlinkSite disables a Debian-layout site by removing its sites-enabled symlink (never a regular file).
func (Local) UnlinkSite(link string) error {
	dir, _, err := plainName(link)
	if err != nil {
		return err
	}
	if _, ok := linkDirs[dir]; !ok {
		return fmt.Errorf("%w: %s is not in a sites-enabled directory", ErrDenied, link)
	}
	fi, err := os.Lstat(hostfs.P(link))
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("%w: %s is not a symlink", ErrDenied, link)
	}
	slog.Info("executor unlink site", "link", link)
	return os.Remove(hostfs.P(link))
}

// ErrExists is returned when a rename or link destination already exists.
var ErrExists = errors.New("destination exists")

// RenameSite toggles a conf.d site between X.conf and X.conf.disabled in the same directory.
func (Local) RenameSite(from, to string) error {
	fdir, fbase, err := plainName(from)
	if err != nil {
		return err
	}
	tdir, tbase, err := plainName(to)
	if err != nil {
		return err
	}
	if fdir != tdir || !renameDirs[fdir] {
		return fmt.Errorf("%w: rename %s -> %s outside a conf.d directory", ErrDenied, from, to)
	}
	disable := strings.HasSuffix(fbase, ".conf") && tbase == fbase+".disabled"
	enable := strings.HasSuffix(tbase, ".conf") && fbase == tbase+".disabled"
	if !disable && !enable {
		return fmt.Errorf("%w: only X.conf <-> X.conf.disabled renames are allowed", ErrDenied)
	}
	fi, err := os.Lstat(hostfs.P(from))
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrDenied, from)
	}
	if _, err := os.Lstat(hostfs.P(to)); err == nil {
		return fmt.Errorf("%w: %s", ErrExists, to)
	}
	slog.Info("executor rename site", "from", from, "to", to)
	return os.Rename(hostfs.P(from), hostfs.P(to))
}

// LinkSite, UnlinkSite and RenameSite forward to the privileged parent.
func (r *Remote) LinkSite(target, link string) error {
	_, err := r.call(req{Op: "link-site", Path: link, To: target})
	return err
}
func (r *Remote) UnlinkSite(link string) error {
	_, err := r.call(req{Op: "unlink-site", Path: link})
	return err
}
func (r *Remote) RenameSite(from, to string) error {
	_, err := r.call(req{Op: "rename-site", Path: from, To: to})
	return err
}
