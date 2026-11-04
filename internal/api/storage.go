package api

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tb12as/kurogane/internal/auth"
	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/store"
)

func init() {
	Register(func(s *Server) {
		s.Route("GET /storage", auth.ScopeRead, s.storage)
		s.Route("POST /storage/history/clear", auth.ScopeAdmin, s.clearHistory)
		s.Route("POST /uninstall", auth.ScopeAdmin, s.uninstall)
	})
}

// StorageEntry is one top-level item of data_dir (or the VictoriaMetrics dir) with its recursive size.
type StorageEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Dir   bool   `json:"dir"`
	Bytes int64  `json:"bytes"`
}

// StorageResponse is the body of GET /storage.
type StorageResponse struct {
	DataDir    string         `json:"data_dir"`
	TotalBytes int64          `json:"total_bytes"`
	Entries    []StorageEntry `json:"entries"`
	AgentStore *store.Stats   `json:"agent_store,omitempty"`
}

// dirSize sums regular files under p; unreadable parts are skipped.
func dirSize(p string) int64 {
	var n int64
	_ = filepath.WalkDir(p, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		if fi, err := d.Info(); err == nil {
			n += fi.Size()
		}
		return nil
	})
	return n
}

func (s *Server) storage(*http.Request) (any, error) {
	out := StorageResponse{DataDir: s.Cfg.DataDir, Entries: []StorageEntry{}}
	des, err := os.ReadDir(s.Cfg.DataDir)
	if err != nil {
		return nil, Errf(http.StatusInternalServerError, "read data_dir %s: %v", s.Cfg.DataDir, err)
	}
	for _, d := range des {
		p := filepath.Join(s.Cfg.DataDir, d.Name())
		out.Entries = append(out.Entries, StorageEntry{Name: d.Name(), Path: p, Dir: d.IsDir(), Bytes: dirSize(p)})
	}

	vm := s.Cfg.Server.VM.DataDir
	// a VM dir inside data_dir is already counted above
	if s.Central && vm != "" && !strings.HasPrefix(filepath.Clean(vm)+"/", filepath.Clean(s.Cfg.DataDir)+"/") {
		out.Entries = append(out.Entries, StorageEntry{Name: "victoriametrics", Path: vm, Dir: true, Bytes: dirSize(vm)})
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].Bytes > out.Entries[j].Bytes })
	for _, e := range out.Entries {
		out.TotalBytes += e.Bytes
	}

	if s.Store != nil {
		st, err := s.Store.Stats()
		if err != nil {
			return nil, err
		}
		out.AgentStore = &st
	}
	return out, nil
}

func (s *Server) clearHistory(r *http.Request) (any, error) {
	if s.Store == nil {
		return nil, Errf(http.StatusServiceUnavailable, "no local metrics store on this server: clear it on the agent")
	}
	var q struct {
		OlderThan string `json:"older_than"`
	}
	if err := Decode(r, &q); err != nil {
		return nil, err
	}
	var d time.Duration
	if q.OlderThan != "" && q.OlderThan != "0" {
		var err error
		if d, err = parseDur(q.OlderThan); err != nil || d < 0 {
			return nil, Errf(http.StatusBadRequest,
				"invalid older_than %q: use a duration like 6h or 7d, or 0 to delete all history", q.OlderThan)
		}
	}
	if err := s.Store.ClearHistory(d); err != nil {
		return nil, err
	}
	freed, err := s.Store.Compact()
	if err != nil {
		return nil, Errf(http.StatusInternalServerError,
			"history deleted but compaction failed: %v (free disk space and retry)", err)
	}
	st, _ := s.Store.Stats()
	res := map[string]any{"freed_bytes": freed, "file_bytes": st.FileBytes}
	s.Audit.Record(r.Context(), "storage.history.clear", "agent.db", nil,
		map[string]any{"older_than": d.String(), "freed_bytes": freed})
	return res, nil
}

func (s *Server) uninstall(r *http.Request) (any, error) {
	if s.Central || s.Ex == nil {
		return nil, Errf(http.StatusBadRequest, "uninstall from the UI is agent only: run sudo kurogane uninstall on the host")
	}
	var q struct {
		Purge   bool   `json:"purge"`
		Confirm string `json:"confirm"`
	}
	if err := Decode(r, &q); err != nil {
		return nil, err
	}
	if q.Confirm != s.Cfg.ServerName {
		return nil, Errf(http.StatusBadRequest, "type the server name %q to confirm", s.Cfg.ServerName)
	}
	bin, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if b, err := filepath.EvalSymlinks(bin); err == nil {
		bin = b
	}
	args := append(append([]string{}, executor.UninstallArgs...), bin, "uninstall", "--yes")
	if q.Purge {
		args = append(args, "--purge")
	}
	s.Audit.Record(r.Context(), "agent.uninstall", s.Cfg.ServerName, nil, map[string]any{"purge": q.Purge})
	if _, err := s.Ex.Run(r.Context(), "systemd-run", args...); err != nil {
		return nil, Errf(http.StatusInternalServerError,
			"start uninstall: %v (binary %s; run sudo kurogane uninstall on the host)", err, bin)
	}
	return map[string]any{"started": true, "purge": q.Purge}, nil
}
