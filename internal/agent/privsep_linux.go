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
	"strconv"
	"strings"
	"syscall"

	"github.com/serverkeeper/serverkeeper/internal/config"
	"github.com/serverkeeper/serverkeeper/internal/executor"
	"github.com/serverkeeper/serverkeeper/internal/secret"
)

// WorkerFD is the inherited socket fd in the unprivileged worker.
const WorkerFD = 3

// RunPrivsep runs the agent. As root with privsep enabled and a `serverkeeper` user present, the root
// parent only serves allowlisted executor ops while an unprivileged worker runs everything else
// (PRD §11.1 least privilege). Otherwise the agent runs in-process.
func RunPrivsep(ctx context.Context, cfg *config.Config, cfgPath, version string) error {
	u, err := user.Lookup("serverkeeper")
	if os.Geteuid() != 0 || !cfg.Privsep || err != nil {
		if os.Geteuid() == 0 && cfg.Privsep {
			slog.Warn("privilege separation off: create a system user `serverkeeper` to enable it")
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
	_ = filepath.Walk(cfg.DataDir, func(p string, _ os.FileInfo, _ error) error { return os.Chown(p, uid, gid) })
	// the worker re-reads the config: keep it root-owned but group-readable by serverkeeper only
	if err := os.Chown(cfgPath, 0, gid); err == nil {
		_ = os.Chmod(cfgPath, 0o640)
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
	cmd.Env = append(os.Environ(), "SK_SECRET_KEY="+strings.TrimSpace(string(key)))
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
		Pdeathsig: syscall.SIGTERM}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start worker: %w", err)
	}
	child.Close()
	conn, err := net.FileConn(parent)
	if err != nil {
		return err
	}
	parent.Close()
	slog.Info("privilege separation active", "worker_pid", cmd.Process.Pid, "user", "serverkeeper")
	go func() { _ = executor.Serve(conn, executor.Local{}) }()
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
