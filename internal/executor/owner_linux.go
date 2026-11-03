package executor

import (
	"os"
	"syscall"
)

func copyOwner(st os.FileInfo, path string) {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(path, int(s.Uid), int(s.Gid))
	}
}
