// Package executor is the only place ServerKeeper performs privileged actions. It exposes
// typed operations with an allowlist of writable paths and commands; there is no shell.
package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/tb12as/serverman/internal/hostfs"
)

// Executor performs privileged host operations. Paths are host paths (hostfs.Root applied inside).
type Executor interface {
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte, mode os.FileMode) error
	Chmod(path string, mode os.FileMode) error
	Remove(path string) error
	MkdirAll(path string, mode os.FileMode) error
	Chown(path string, uid, gid int) error
	Run(ctx context.Context, cmd string, args ...string) ([]byte, error)
	// Site toggles (sites.go): move files only, never write contents.
	LinkSite(target, link string) error
	UnlinkSite(link string) error
	RenameSite(from, to string) error
}

// ErrDenied is returned for operations outside the allowlist.
var ErrDenied = errors.New("executor: operation not allowlisted")

// writable path prefixes (host paths).
var writePrefixes = []string{
	"/etc/ssh/", "/etc/serverkeeper/", "/var/lib/serverkeeper/", "/etc/sysctl.d/", "/etc/sysctl.conf",
	"/root/.ssh/", "/home/", "/etc/systemd/journald.conf", "/etc/systemd/system/", "/etc/apt/apt.conf.d/",
	"/etc/security/limits.d/", "/etc/security/limits.conf", "/etc/login.defs", "/etc/shadow", "/etc/gshadow",
	"/etc/passwd", "/etc/group", "/etc/sudoers.d/", "/etc/sudoers", "/etc/nftables.conf", "/etc/logrotate.d/",
	"/etc/chrony.conf", "/etc/chrony/", "/etc/systemd/timesyncd.conf", "/etc/dnf/automatic.conf", "/etc/modprobe.d/",
	"/etc/systemd/coredump.conf", "/etc/crontab", "/etc/cron.d/", "/var/spool/cron/", "/etc/fstab",
	"/etc/profile.d/", "/var/log/journal/", "/etc/audit/", "/usr/local/bin/", "/etc/default/",
}

func writable(p string) bool {
	if strings.Contains(p, "..") || !filepath.IsAbs(p) {
		return false
	}
	dir := strings.HasSuffix(p, "/")
	p = filepath.Clean(p)
	if dir {
		p += "/"
	}
	for _, pre := range writePrefixes {
		if !strings.HasSuffix(pre, "/") {
			// file entries match exactly or their ".d/" drop-in dir
			if p == pre || strings.HasPrefix(p, pre+".d/") {
				return true
			}
			continue
		}
		if strings.HasPrefix(p, pre) || p+"/" == pre {
			if pre == "/home/" {
				return strings.Contains(p, "/.ssh/") || strings.HasSuffix(p, "/.ssh")
			}
			return true
		}
	}
	return false
}

var ownerSpec = regexp.MustCompile(`^[0-9]+:[0-9]+$`)

var safeArg = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./\-\*\[\]\{\}~ <>!#"';()|&$^?]*$`)

// commands maps an allowlisted command to permitted first arguments (nil = any safe args).
var commands = map[string][]string{
	"sshd":               {"-t", "-T"},
	"systemctl":          {"reload", "restart", "is-active", "is-enabled", "enable", "disable", "stop", "start", "show", "list-units", "list-unit-files", "mask", "daemon-reload", "status", "is-failed"},
	"sysctl":             {"-w", "-n", "--system", "-a", "-p"},
	"apt-get":            {"install", "update", "-y", "-s", "-qq"},
	"apt":                {"list"},
	"dnf":                {"install", "-y", "updateinfo", "check-update", "-q", "--security"},
	"nft":                {"list", "-j", "-f", "add", "delete", "flush"},
	"iptables":           nil,
	"ip6tables":          nil,
	"ufw":                {"status", "enable", "disable", "--force", "default", "allow", "deny", "reload", "prepend"},
	"firewall-cmd":       {"--state", "--list-all", "--get-default-zone", "--set-default-zone", "--add-service", "--add-port", "--reload", "--permanent", "--add-rich-rule", "--remove-rich-rule", "--list-ports", "--list-services"},
	"pkill":              {"-KILL", "-HUP", "-t"},
	"kill":               {"-TERM", "-KILL", "-HUP"},
	"loginctl":           {"list-sessions", "terminate-session", "show-session"},
	"timedatectl":        {"show", "set-ntp", "status"},
	"chronyc":            {"tracking", "-n"},
	"journalctl":         nil,
	"who":                nil,
	"needs-restarting":   {"-r"},
	"chage":              {"-l", "-M", "-m", "-W"},
	"passwd":             {"-l", "-S"},
	"usermod":            {"-L"},
	"auditctl":           {"-s", "-l"},
	"ss":                 {"-tanpH", "-tlnpH", "-uanpH", "-s", "-tanH"},
	"dpkg-query":         {"-W", "-s"},
	"rpm":                {"-q", "-qa"},
	"ssh-keygen":         {"-l", "-lf", "-y"},
	"mount":              {"-o"},
	"modprobe":           {"-n"},
	"unattended-upgrade": {"--dry-run"},
	"uname":              {"-r", "-a"},
	"chown":              {"-h"},
	"stat":               {"-c"},
	"systemd-run":        {UninstallArgs[0]},
	"nginx":              {"-t"},
	"apachectl":          {"configtest"},
}

// UninstallArgs is the only systemd-run the worker may ask for: a delayed transient unit outside
// serverkeeper.service, so `serverkeeper uninstall` survives stopping the agent. The binary path follows.
var UninstallArgs = []string{"--unit=serverkeeper-uninstall", "--collect", "--on-active=3"}

func uninstallCmd(args []string) bool {
	n := len(UninstallArgs)
	if len(args) < n+3 || len(args) > n+4 || !slices.Equal(args[:n], UninstallArgs) {
		return false
	}
	if bin := args[n]; bin != "/usr/bin/serverkeeper" && bin != "/usr/local/bin/serverkeeper" {
		return false
	}
	if args[n+1] != "uninstall" || args[n+2] != "--yes" {
		return false
	}
	return len(args) == n+3 || args[n+3] == "--purge"
}

// Allowed validates a command and its args against the allowlist.
func Allowed(cmd string, args []string) error {
	first, ok := commands[cmd]
	if !ok {
		return fmt.Errorf("%w: command %q", ErrDenied, cmd)
	}
	for _, a := range args {
		if !safeArg.MatchString(a) || strings.ContainsAny(a, "\x00\n") {
			return fmt.Errorf("%w: argument %q", ErrDenied, a)
		}
	}
	// chown only hands allowlisted paths (authorized_keys, ~/.ssh) to a numeric owner, never via symlinks
	if cmd == "chown" && (len(args) != 3 || args[0] != "-h" || !ownerSpec.MatchString(args[1]) ||
		!writable(args[2]) || !strings.Contains(args[2], "/.ssh")) {
		return fmt.Errorf("%w: chown %s", ErrDenied, strings.Join(args, " "))
	}
	if cmd == "systemd-run" && !uninstallCmd(args) {
		return fmt.Errorf("%w: systemd-run %s", ErrDenied, strings.Join(args, " "))
	}
	if first == nil || len(args) == 0 {
		return nil
	}
	for _, f := range first {
		if args[0] == f {
			return nil
		}
	}
	return fmt.Errorf("%w: %s %s", ErrDenied, cmd, args[0])
}

// userControlled reports whether p lies in a home directory whose owner could plant symlinks.
func userControlled(p string) bool {
	return strings.HasPrefix(p, "/home/") || strings.HasPrefix(p, "/root/")
}

// noSymlink refuses paths in user-controlled homes with a symlink component, so a user cannot point
// ~/.ssh at another directory and have root write or chown files there.
func noSymlink(p string) error {
	if !userControlled(p) {
		return nil
	}
	cur := ""
	for _, part := range strings.Split(strings.Trim(filepath.Clean(p), "/"), "/") {
		cur += "/" + part
		fi, err := os.Lstat(hostfs.P(cur))
		if err != nil {
			return nil // the rest does not exist yet
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s is a symlink (refusing to follow it in a user home)", ErrDenied, cur)
		}
	}
	return nil
}

// Local executes in-process; requires root for most writes.
type Local struct{}

func (Local) ReadFile(p string) ([]byte, error) { return os.ReadFile(hostfs.P(p)) }

func (Local) WriteFile(p string, data []byte, mode os.FileMode) error {
	if !writable(p) {
		return fmt.Errorf("%w: write %s", ErrDenied, p)
	}
	if err := noSymlink(p); err != nil {
		return err
	}
	real := hostfs.P(p)
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil { // #nosec G301 -- system config dirs (e.g. /etc/ssh/sshd_config.d) are 0755
		return err
	}
	// atomic replace so a crash never leaves a half-written config
	tmp := real + ".sk-tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	if st, err := os.Stat(real); err == nil {
		copyOwner(st, tmp)
	}
	slog.Info("executor write", "path", p, "bytes", len(data))
	return os.Rename(tmp, real)
}

func (Local) Chmod(p string, mode os.FileMode) error {
	if !writable(p) && !chmodable(p) {
		return fmt.Errorf("%w: chmod %s", ErrDenied, p)
	}
	if err := noSymlink(p); err != nil {
		return err
	}
	slog.Info("executor chmod", "path", p, "mode", fmt.Sprintf("%o", mode))
	return os.Chmod(hostfs.P(p), mode)
}

// chmodable allows permission tightening in system dirs (FILE-* checks).
func chmodable(p string) bool {
	for _, pre := range []string{"/etc/", "/usr/", "/bin/", "/sbin/", "/var/", "/opt/", "/tmp"} {
		if strings.HasPrefix(filepath.Clean(p), pre) {
			return true
		}
	}
	return false
}

func (Local) Remove(p string) error {
	if !writable(p) {
		return fmt.Errorf("%w: remove %s", ErrDenied, p)
	}
	if err := noSymlink(p); err != nil {
		return err
	}
	slog.Info("executor remove", "path", p)
	err := os.Remove(hostfs.P(p))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (Local) Chown(p string, uid, gid int) error {
	if !writable(p) && !writable(p+"/") {
		return fmt.Errorf("%w: chown %s", ErrDenied, p)
	}
	if err := noSymlink(p); err != nil {
		return err
	}
	return os.Lchown(hostfs.P(p), uid, gid)
}

func (Local) MkdirAll(p string, mode os.FileMode) error {
	if !writable(strings.TrimSuffix(p, "/") + "/") {
		return fmt.Errorf("%w: mkdir %s", ErrDenied, p)
	}
	if err := noSymlink(p); err != nil {
		return err
	}
	return os.MkdirAll(hostfs.P(p), mode)
}

func (Local) Run(ctx context.Context, cmd string, args ...string) ([]byte, error) {
	if err := Allowed(cmd, args); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, cmd, args...)
	c.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C",
		"DEBIAN_FRONTEND=noninteractive", "SYSTEMD_PAGER="}
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	err := c.Run()
	if err != nil {
		return out.Bytes(), &RunError{Cmd: cmd + " " + strings.Join(args, " "), Err: err, Stderr: strings.TrimSpace(errb.String())}
	}
	return out.Bytes(), nil
}

// RunError keeps stderr so callers can report cause and next step (§11.5).
type RunError struct {
	Cmd    string
	Err    error
	Stderr string
}

func (e *RunError) Error() string {
	if e.Stderr != "" {
		return fmt.Sprintf("%s failed: %s", e.Cmd, e.Stderr)
	}
	return fmt.Sprintf("%s failed: %v", e.Cmd, e.Err)
}

func (e *RunError) Unwrap() error { return e.Err }

// ExitCode returns the process exit code of a RunError, or -1.
func ExitCode(err error) int {
	var re *RunError
	if !errors.As(err, &re) {
		return -1
	}
	var ee *exec.ExitError
	if errors.As(re.Err, &ee) {
		return ee.ExitCode()
	}
	return -1
}
