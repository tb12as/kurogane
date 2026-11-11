package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"

	"github.com/tb12as/kurogane/internal/config"
	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/secret"
)

// WorkerFD is the inherited socket fd in the unprivileged worker.
const WorkerFD = 3

// RunPrivsep runs the agent. As root with privsep enabled and a `kurogane` user present, the root
// parent only serves allowlisted executor ops while an unprivileged worker runs everything else
// (PRD §11.1 least privilege). Otherwise the agent runs in-process.
func RunPrivsep(ctx context.Context, cfg *config.Config, cfgPath, version string) error {
	u, err := user.Lookup("kurogane")
	if os.Geteuid() != 0 || !cfg.Privsep || err != nil {
		if os.Geteuid() == 0 && cfg.Privsep {
			slog.Warn("privilege separation off: create a system user `kurogane` to enable it")
		}
		a, err := New(cfg, executor.Local{}, version)
		if err != nil {
			return err
		}
		return a.Run(ctx)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	// Lchown + skip symlinks: the unprivileged user owns this tree and could plant a link to e.g. /etc/shadow
	_ = filepath.Walk(cfg.DataDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		return os.Lchown(p, uid, gid) // #nosec G122 -- symlinks are skipped and Lchown never follows links
	})
	// the worker re-reads the config: keep it root-owned but group-readable by kurogane only
	if err := os.Chown(cfgPath, 0, gid); err == nil {
		_ = os.Chmod(cfgPath, 0o640) // #nosec G302 -- config is root:kurogane 0640 so the worker can read it
	}

	// the worker cannot read the root-only key file, so hand it the key via env
	key, err := os.ReadFile(cfg.SecretKey)
	if os.IsNotExist(err) {
		if _, err := secret.LoadOrCreate(cfg.SecretKey); err != nil {
			return err
		}
		key, err = os.ReadFile(cfg.SecretKey)
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", cfg.SecretKey, err)
	}

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	parent := os.NewFile(uintptr(fds[0]), "executor-parent")
	child := os.NewFile(uintptr(fds[1]), "executor-child")
	exe, _ := os.Executable()
	cmd := exec.CommandContext(ctx, exe, "agent", "worker", "--config", cfgPath)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{child}
	cmd.Env = append(os.Environ(), "KRGN_SECRET_KEY="+strings.TrimSpace(string(key)))
	cred := &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groupIDs(u)}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred, Pdeathsig: syscall.SIGTERM}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start worker: %w", err)
	}
	child.Close()
	conn, err := net.FileConn(parent)
	if err != nil {
		return err
	}
	parent.Close()
	slog.Info("privilege separation active", "worker_pid", cmd.Process.Pid, "user", "kurogane")
	go func() { _ = executor.Serve(conn, executor.Local{}) }()
	// the parent only proxies executor calls: keep its heap minimal (PRD §11.2 RSS budget)
	debug.SetGCPercent(10)
	debug.FreeOSMemory()
	return cmd.Wait()
}

// RunWorker is the unprivileged side; it talks to the root parent over fd 3.
func RunWorker(ctx context.Context, cfg *config.Config, version string) error {
	f := os.NewFile(WorkerFD, "executor")
	conn, err := net.FileConn(f)
	if err != nil {
		return fmt.Errorf("worker: no executor socket on fd %d: %w", WorkerFD, err)
	}
	a, err := New(cfg, executor.NewRemote(conn), version)
	if err != nil {
		return err
	}
	return a.Run(ctx)
}

// groupIDs returns the supplementary groups of u. The worker needs them (adm reads /var/log/apache2 and
// /var/log/nginx); a nil Credential.Groups would drop them all.
func groupIDs(u *user.User) []uint32 {
	ids, err := u.GroupIds()
	if err != nil {
		slog.Warn("cannot list groups of the kurogane user; the worker keeps only its primary group", "err", err)
		return nil
	}
	out := make([]uint32, 0, len(ids))
	for _, id := range ids {
		if g, err := strconv.ParseUint(id, 10, 32); err == nil {
			out = append(out, uint32(g))
		}
	}
	return out
}
