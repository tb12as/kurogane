// Package backup implements `serverkeeper backup` / `restore` (PRD §9 backups, §11.4): SQLite VACUUM INTO, the
// agent's bbolt store and, on the central server, a VictoriaMetrics snapshot, copied into cfg.Server.Backup.Dest.
// Off-host copies are the operator's mount or rsync target.
package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tb12as/kurogane/internal/api"
	"github.com/tb12as/kurogane/internal/auth"
	"github.com/tb12as/kurogane/internal/config"
	"github.com/tb12as/kurogane/internal/db"
	"github.com/tb12as/kurogane/internal/metricsdb"
	bolt "go.etcd.io/bbolt"
)

const prefix = "serverkeeper-"

// Options selects what to back up; nil stores are skipped.
type Options struct {
	Cfg  *config.Config
	DB   db.Store
	Bolt *bolt.DB
	VM   *metricsdb.Client
	Dest string // default cfg.Server.Backup.Dest, else data_dir/backups
	Keep int    // 0 = keep all
}

// Manifest describes one backup directory.
type Manifest struct {
	CreatedAt  time.Time         `json:"created_at"`
	Server     string            `json:"server"`
	Files      map[string]string `json:"files"` // name -> sha256
	VMSnapshot string            `json:"vm_snapshot,omitempty"`
	VMBytes    int64             `json:"vm_bytes,omitempty"`
}

func init() {
	api.Register(func(s *api.Server) {
		s.Route("POST /backup", auth.ScopeAdmin, func(r *http.Request) (any, error) {
			var q struct {
				Dest string `json:"dest"`
			}
			if err := api.Decode(r, &q); err != nil {
				return nil, err
			}
			o := Options{Cfg: s.Cfg, DB: s.DB, Dest: q.Dest, Keep: s.Cfg.Server.Backup.Keep}
			if s.Store != nil {
				o.Bolt = s.Store.DB()
			}
			if s.Central {
				o.VM = metricsdb.New(s.Cfg.Server.VM.URL)
			}
			dir, m, err := Run(r.Context(), o)
			if err != nil {
				return nil, err
			}
			s.Audit.Record(r.Context(), "backup.create", dir, nil, m)
			return map[string]any{"path": dir, "manifest": m}, nil
		})
	})
}

// DefaultDest returns the configured backup destination.
func DefaultDest(cfg *config.Config) string {
	if cfg.Server.Backup.Dest != "" {
		return cfg.Server.Backup.Dest
	}
	return cfg.BackupDir()
}

// Run writes a new backup directory and prunes old ones beyond Keep.
func Run(ctx context.Context, o Options) (string, Manifest, error) {
	if o.Dest == "" {
		o.Dest = DefaultDest(o.Cfg)
	}
	m := Manifest{CreatedAt: time.Now().UTC(), Server: o.Cfg.ServerName, Files: map[string]string{}}
	final := filepath.Join(o.Dest, prefix+m.CreatedAt.Format("20060102-150405"))
	tmp := final + ".partial"
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return "", m, fmt.Errorf("create %s: %w (check backup.dest is mounted and writable)", tmp, err)
	}
	fail := func(err error) (string, Manifest, error) {
		os.RemoveAll(tmp)
		return "", m, err
	}
	if o.DB != nil {
		if err := o.DB.VacuumInto(ctx, filepath.Join(tmp, "serverkeeper.db")); err != nil {
			return fail(fmt.Errorf("sqlite VACUUM INTO: %w", err))
		}
	}
	if o.Bolt != nil {
		err := o.Bolt.View(func(tx *bolt.Tx) error { return tx.CopyFile(filepath.Join(tmp, "agent.db"), 0o600) })
		if err != nil {
			return fail(fmt.Errorf("bbolt copy: %w", err))
		}
	}
	for _, f := range []string{"serverkeeper.db", "agent.db"} {
		p := filepath.Join(tmp, f)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		_ = os.Chmod(p, 0o600)
		s, err := fileSHA(p)
		if err != nil {
			return fail(err)
		}
		m.Files[f] = s
	}
	if o.VM != nil {
		name, err := o.VM.Snapshot(ctx)
		if err != nil {
			return fail(err)
		}
		m.VMSnapshot = name
		src := filepath.Join(o.Cfg.Server.VM.DataDir, "snapshots", name)
		m.VMBytes, err = copyTree(src, filepath.Join(tmp, "vm"))
		_ = o.VM.DeleteSnapshot(context.WithoutCancel(ctx), name)
		if err != nil {
			return fail(fmt.Errorf("copy VictoriaMetrics snapshot %s: %w", src, err))
		}
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(tmp, "manifest.json"), b, 0o600); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fail(err)
	}
	if o.Keep > 0 {
		prune(o.Dest, o.Keep)
	}
	return final, m, nil
}

func prune(dest string, keep int) {
	ents, _ := os.ReadDir(dest)
	var dirs []string
	for _, e := range ents {
		if e.IsDir() && strings.HasPrefix(e.Name(), prefix) && !strings.HasSuffix(e.Name(), ".partial") {
			dirs = append(dirs, e.Name())
		}
	}
	sort.Strings(dirs) // timestamped names sort chronologically
	for len(dirs) > keep {
		os.RemoveAll(filepath.Join(dest, dirs[0]))
		dirs = dirs[1:]
	}
}

// RestoreOpts says where to restore to. Services must be stopped first (the caller checks).
type RestoreOpts struct {
	MetaDB  string // sqlite path
	AgentDB string // bbolt path
	VMDir   string // VictoriaMetrics storageDataPath
}

// Restore replaces the databases with the backup in dir. Existing files are kept as *.pre-restore-<ts>.
func Restore(dir string, o RestoreOpts) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("%s is not a serverkeeper backup (no manifest.json): %w", dir, err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("manifest.json: %w", err)
	}
	for f, want := range m.Files {
		got, err := fileSHA(filepath.Join(dir, f))
		if err != nil || got != want {
			return nil, fmt.Errorf("backup file %s is corrupt (checksum mismatch): use another backup", f)
		}
	}
	suffix := ".pre-restore-" + time.Now().Format("20060102-150405")
	var done []string
	for f, dst := range map[string]string{"serverkeeper.db": o.MetaDB, "agent.db": o.AgentDB} {
		if _, ok := m.Files[f]; !ok || dst == "" {
			continue
		}
		if err := os.Rename(dst, dst+suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return done, err
		}
		// stale WAL/SHM from the old database must not be replayed onto the restored file
		os.Remove(dst + "-wal")
		os.Remove(dst + "-shm")
		if err := copyFile(filepath.Join(dir, f), dst); err != nil {
			return done, err
		}
		done = append(done, dst)
	}
	if m.VMSnapshot != "" && o.VMDir != "" {
		// VM restores by copying the snapshot contents into storageDataPath while it is stopped
		src := filepath.Join(dir, "vm")
		ents, err := os.ReadDir(src)
		if err != nil {
			return done, err
		}
		for _, e := range ents {
			p := filepath.Join(o.VMDir, e.Name())
			if err := os.Rename(p, p+suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
				return done, err
			}
			if _, err := copyTree(filepath.Join(src, e.Name()), p); err != nil {
				return done, err
			}
		}
		done = append(done, o.VMDir)
	}
	return done, nil
}

func fileSHA(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// copyTree copies src into dst following symlinks (VM snapshot dirs are symlinks to hard-linked parts).
func copyTree(src, dst string) (int64, error) {
	st, err := os.Stat(src)
	if err != nil {
		return 0, err
	}
	if !st.IsDir() {
		return st.Size(), copyFile(src, dst)
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return 0, err
	}
	ents, err := os.ReadDir(src)
	if err != nil {
		return 0, err
	}
	var n int64
	for _, e := range ents {
		k, err := copyTree(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name()))
		if err != nil {
			return n, err
		}
		n += k
	}
	return n, nil
}
