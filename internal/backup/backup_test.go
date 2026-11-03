package backup

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/tb12as/serverman/internal/config"
	"github.com/tb12as/serverman/internal/db"
	"github.com/tb12as/serverman/internal/metricsdb"
	"github.com/tb12as/serverman/internal/store"
)

func TestBackupRestore(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{ServerName: "c1", DataDir: dir}
	cfg.Server.VM.DataDir = filepath.Join(dir, "vm")
	ctx := context.Background()

	meta, err := db.Open(cfg.MetaDB())
	if err != nil {
		t.Fatal(err)
	}
	if err := meta.SetKV(ctx, "k", "before"); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.AgentDB())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put("b", "k", "v1"); err != nil {
		t.Fatal(err)
	}

	// fake VM: snapshot dir with a symlinked data part like the real layout
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/snapshot/create":
			part := filepath.Join(cfg.Server.VM.DataDir, "data", "snapshots", "s1")
			os.MkdirAll(part, 0o700)
			os.WriteFile(filepath.Join(part, "part.bin"), []byte("series"), 0o600)
			snap := filepath.Join(cfg.Server.VM.DataDir, "snapshots", "s1")
			os.MkdirAll(snap, 0o700)
			os.Symlink("../../data/snapshots/s1", filepath.Join(snap, "data"))
			w.Write([]byte(`{"status":"ok","snapshot":"s1"}`))
		case "/snapshot/delete":
			w.Write([]byte(`{"status":"ok"}`))
		}
	}))
	defer vm.Close()

	dest := filepath.Join(dir, "backups")
	var last string
	for i := 0; i < 3; i++ {
		os.RemoveAll(filepath.Join(cfg.Server.VM.DataDir, "snapshots"))
		p, m, err := Run(ctx, Options{Cfg: cfg, DB: meta, Bolt: st.DB(), VM: metricsdb.New(vm.URL), Dest: dest, Keep: 2})
		if err != nil {
			t.Fatal(err)
		}
		if m.Files["serverkeeper.db"] == "" || m.Files["agent.db"] == "" || m.VMBytes != 6 {
			t.Fatalf("%+v", m)
		}
		if fi, _ := os.Stat(filepath.Join(p, "serverkeeper.db")); fi.Mode().Perm() != 0o600 {
			t.Fatalf("backup db mode %o", fi.Mode().Perm())
		}
		// distinct directory names need distinct seconds
		last = filepath.Join(dest, prefix+"2000010"+string(rune('1'+i))+"-000000")
		os.Rename(p, last)
	}
	ents, _ := os.ReadDir(dest)
	if len(ents) > 3 {
		t.Fatalf("keep not applied: %d", len(ents))
	}

	meta.SetKV(ctx, "k", "after")
	meta.Close()
	st.Close()
	done, err := Restore(last, RestoreOpts{MetaDB: cfg.MetaDB(), AgentDB: cfg.AgentDB(), VMDir: cfg.Server.VM.DataDir})
	if err != nil {
		t.Fatal(err, done)
	}
	meta, err = db.Open(cfg.MetaDB())
	if err != nil {
		t.Fatal(err)
	}
	defer meta.Close()
	if v, _ := meta.GetKV(ctx, "k"); v != "before" {
		t.Fatalf("restored kv = %q", v)
	}
	st, err = store.Open(cfg.AgentDB())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var v string
	if err := st.Get("b", "k", &v); err != nil || v != "v1" {
		t.Fatal(v, err)
	}
	if b, _ := os.ReadFile(filepath.Join(cfg.Server.VM.DataDir, "data", "part.bin")); string(b) != "series" {
		t.Fatal("vm data not restored")
	}

	// tampered backup is refused
	os.WriteFile(filepath.Join(last, "serverkeeper.db"), []byte("x"), 0o600)
	if _, err := Restore(last, RestoreOpts{MetaDB: cfg.MetaDB()}); err == nil {
		t.Fatal("corrupt backup accepted")
	}
}
