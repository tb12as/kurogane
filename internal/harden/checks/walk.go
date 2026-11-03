package checks

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/tb12as/serverman/internal/hostfs"
)

// walkDirs are the system dirs scanned for world-writable and SUID files.
var walkDirs = []string{"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt"}

type fsFinding struct {
	Path string
	Mode os.FileMode
}

type walkResult struct {
	WorldWritable []fsFinding
	SUID          []fsFinding
	Truncated     bool
}

const maxFindings = 200

// sysWalk walks walkDirs once per scan (shared by FILE-WORLD-WRITABLE and FILE-SUID-UNEXPECTED),
// staying on each dir's filesystem and skipping symlinked roots (/bin -> /usr/bin).
func sysWalk(ctx context.Context) walkResult {
	r, _ := memo(ctx, "walk", func() (walkResult, error) {
		var r walkResult
		root := filepath.Clean(hostfs.P("/"))
		for _, d := range walkDirs {
			real := hostfs.P(d)
			st, err := os.Lstat(real)
			if err != nil || !st.IsDir() {
				continue
			}
			dev := devOf(st)
			_ = filepath.WalkDir(real, func(p string, en fs.DirEntry, err error) error {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if err != nil || en.Type()&fs.ModeSymlink != 0 {
					return nil
				}
				info, err := en.Info()
				if err != nil {
					return nil
				}
				if en.IsDir() && devOf(info) != dev {
					return filepath.SkipDir
				}
				m := info.Mode()
				host := "/" + strings.TrimPrefix(strings.TrimPrefix(p, root), "/")
				if m.Perm()&0o002 != 0 && !(m.IsDir() && m&os.ModeSticky != 0) {
					if len(r.WorldWritable) < maxFindings {
						r.WorldWritable = append(r.WorldWritable, fsFinding{host, m.Perm()})
					} else {
						r.Truncated = true
					}
				}
				if m.IsRegular() && m&os.ModeSetuid != 0 && len(r.SUID) < maxFindings {
					r.SUID = append(r.SUID, fsFinding{host, m.Perm()})
				}
				return nil
			})
		}
		return r, ctx.Err()
	})
	return r
}

func devOf(fi os.FileInfo) uint64 {
	if s, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(s.Dev)
	}
	return 0
}
