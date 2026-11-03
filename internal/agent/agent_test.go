package agent

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/serverkeeper/serverkeeper/internal/config"
	"github.com/serverkeeper/serverkeeper/internal/executor"
	"github.com/serverkeeper/serverkeeper/internal/hostfs"
)

func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// boots the whole agent on a fixture root with a fake executor and checks the CLI token works against the API
func TestAgentBootsAndServes(t *testing.T) {
	root := t.TempDir()
	old := hostfs.Root
	hostfs.Root = root
	defer func() { hostfs.Root = old }()
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc/passwd"), []byte("root:x:0:0::/root:/bin/bash\n"), 0o644)

	dir := t.TempDir()
	addr := freePort(t)
	p := filepath.Join(dir, "config.yaml")
	os.WriteFile(p, []byte("server_name: t\nlisten: "+addr+"\ndata_dir: "+dir+"/data\nsecret_key: "+dir+
		"/secret.key\ncollector: {interval: 1s}\n"), 0o600)
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg, executor.NewFake(), "test")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	var tok []byte
	for i := 0; i < 50; i++ {
		if tok, err = os.ReadFile(CLITokenPath(cfg)); err == nil && len(tok) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if st, err := os.Stat(CLITokenPath(cfg)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("cli token: %v", err)
	}
	var resp *http.Response
	for i := 0; i < 50; i++ {
		req, _ := http.NewRequest("GET", "http://"+addr+"/api/v1/status", nil)
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
		if resp, err = http.DefaultClient.Do(req); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("status: %v %v", err, resp)
	}
	resp.Body.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not stop")
	}
}
