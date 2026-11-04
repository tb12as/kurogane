package collector

import (
	"bytes"
	"context"
	"log/slog"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/hostfs"
)

// sysCollector reports uptime, reboot-required and cached package update counts.
// Package manager calls run in loop(), never on a tick.
type sysCollector struct {
	ex executor.Executor

	mu        sync.Mutex
	info      SystemInfo
	rhel      bool
	rebootCmd bool // needs-restarting -r said yes
	checked   bool // updates counted at least once
}

func newSys(ex executor.Executor) *sysCollector {
	s := &sysCollector{ex: ex}
	s.refreshStatic()
	return s
}

func (s *sysCollector) refreshStatic() {
	d := hostfs.DetectDistro()
	host := hostfs.ReadString("/proc/sys/kernel/hostname")
	kern := hostfs.ReadString("/proc/sys/kernel/osrelease")
	s.mu.Lock()
	s.info.OS, s.info.Hostname, s.info.Kernel, s.info.Arch = d.Name, host, kern, runtime.GOARCH
	if s.info.OS == "" {
		s.info.OS = d.ID
	}
	s.rhel = d.Family == "rhel"
	s.mu.Unlock()
}

func (s *sysCollector) Collect(context.Context) ([]Sample, error) {
	b, err := hostfs.Read("/proc/uptime")
	if err != nil {
		return nil, err
	}
	up, _ := strconv.ParseFloat(string(b[:max(0, bytes.IndexByte(b, ' '))]), 64)
	reboot := hostfs.Exists("/var/run/reboot-required")

	s.mu.Lock()
	reboot = reboot || s.rebootCmd
	s.info.Uptime = up
	s.info.BootTime = now().Add(-time.Duration(up * float64(time.Second))).Truncate(time.Second)
	s.info.RebootRequired = reboot
	checked, sec, pend := s.checked, s.info.SecurityUpdates, s.info.PendingUpdates
	s.mu.Unlock()

	out := make([]Sample, 0, 4)
	out = add(out, "sys.uptime_s", up)
	rb := 0.0
	if reboot {
		rb = 1
	}
	out = add(out, "sys.reboot_required", rb)
	if checked {
		out = add(out, "sys.security_updates", float64(sec))
		out = add(out, "sys.pending_updates", float64(pend))
	}
	return out, nil
}

func (s *sysCollector) snapshot() SystemInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.info
}

// loop refreshes static info and the rhel reboot check hourly, package updates every 6h.
func (s *sysCollector) loop(ctx context.Context) {
	t := time.NewTimer(30 * time.Second) // let the agent settle before shelling out
	defer t.Stop()
	for n := 0; ; n++ {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.refreshStatic()
		s.checkReboot(ctx)
		if n%6 == 0 {
			s.checkUpdates(ctx)
		}
		t.Reset(time.Hour)
	}
}

func (s *sysCollector) checkReboot(ctx context.Context) {
	s.mu.Lock()
	rhel := s.rhel
	s.mu.Unlock()
	if !rhel || !hostfs.HasBinary("needs-restarting") {
		return
	}
	_, err := s.ex.Run(ctx, "needs-restarting", "-r")
	s.mu.Lock()
	s.rebootCmd = executor.ExitCode(err) == 1
	s.mu.Unlock()
}

func (s *sysCollector) checkUpdates(ctx context.Context) {
	d := hostfs.DetectDistro()
	var sec, pend int
	switch d.PkgMgr {
	case "apt":
		out, err := s.ex.Run(ctx, "apt", "list", "--upgradable")
		if err != nil {
			slog.Warn("update check failed", "err", err)
			return
		}
		pend, sec = countApt(out)
	case "dnf":
		// check-update exits 100 when updates exist; the output is still valid
		out, err := s.ex.Run(ctx, "dnf", "check-update", "-q")
		if err != nil && executor.ExitCode(err) != 100 {
			slog.Warn("update check failed", "err", err)
			return
		}
		pend = countDnf(out)
		out, err = s.ex.Run(ctx, "dnf", "updateinfo", "list", "--security", "-q")
		if err != nil {
			slog.Warn("security update check failed", "err", err)
		}
		sec = countDnf(out)
	default:
		return
	}
	s.mu.Lock()
	s.info.PendingUpdates, s.info.SecurityUpdates, s.checked = pend, sec, true
	s.mu.Unlock()
}

func countApt(out []byte) (pend, sec int) {
	for l := range bytes.Lines(out) {
		if !bytes.Contains(l, []byte("[upgradable from")) {
			continue
		}
		pend++
		if bytes.Contains(l, []byte("-security")) {
			sec++
		}
	}
	return pend, sec
}

// countDnf counts package rows, stopping at the "Obsoleting Packages" section.
func countDnf(out []byte) int {
	n := 0
	var f [][]byte
	for l := range bytes.Lines(out) {
		if bytes.HasPrefix(l, []byte("Obsoleting")) {
			break
		}
		f = fields(l, f)
		if len(f) >= 3 && !bytes.HasPrefix(l, []byte(" ")) && !bytes.HasPrefix(l, []byte("Last metadata")) {
			n++
		}
	}
	return n
}
