package metricsdb

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/tb12as/serverman/internal/config"
)

// restartMin is the first restart delay; it doubles up to 30 s and resets after a minute of uptime.
var restartMin = time.Second

// Supervise runs VictoriaMetrics as a child process (vm.mode=child) until ctx is done, restarting it with backoff.
func Supervise(ctx context.Context, vm config.VM) error {
	args, err := Args(vm)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(vm.DataDir, 0o700); err != nil {
		return err
	}
	run(ctx, vm.Binary, args)
	return nil
}

func run(ctx context.Context, bin string, args []string) {
	delay := restartMin
	for ctx.Err() == nil {
		start := time.Now()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
		cmd.WaitDelay = 15 * time.Second
		err := cmd.Run()
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > time.Minute {
			delay = restartMin
		}
		slog.Warn("victoriametrics exited, restarting", "err", err, "in", delay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, 30*time.Second)
	}
}
