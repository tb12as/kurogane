package metricsdb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tb12as/kurogane/internal/config"
	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/hostfs"
)

func TestAppendLine(t *testing.T) {
	b := AppendLine(nil, "cpu.total_pct", map[string]string{"server": "web-01", "mount": `a"b\`}, 12.5, 1000)
	want := `cpu.total_pct{mount="a\"b\\",server="web-01"} 12.5 1000` + "\n"
	if string(b) != want {
		t.Fatalf("got %q want %q", b, want)
	}
	if b := AppendLine(nil, "x\n{server=\"evil\"}", nil, 1, 1); len(b) != 0 {
		t.Fatalf("injection accepted: %q", b)
	}
	if b := AppendLine(nil, "x", map[string]string{"a b": "1"}, 1, 1); len(b) != 0 {
		t.Fatalf("bad label key accepted: %q", b)
	}
}

func TestClient(t *testing.T) {
	var imported string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/import/prometheus":
			b, _ := io.ReadAll(r.Body)
			imported = string(b)
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/query_range":
			if r.URL.Query().Get("query") != `cpu.total_pct{server="a"}` || r.URL.Query().Get("step") != "60s" {
				http.Error(w, "bad query "+r.URL.RawQuery, 400)
				return
			}
			w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[
				{"metric":{"__name__":"cpu.total_pct","server":"a"},"values":[[1700000000,"1.5"],[1700000060.5,"2"]]}]}}`))
		case "/snapshot/create":
			w.Write([]byte(`{"status":"ok","snapshot":"20261103-abc"}`))
		case "/health":
			w.Write([]byte("OK"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New(srv.URL)
	ctx := context.Background()
	if err := c.Import(ctx, AppendLine(nil, "m", nil, 1, 2)); err != nil || imported != "m 1 2\n" {
		t.Fatal(err, imported)
	}
	from, to := time.Unix(1700000000, 0), time.Unix(1700000100, 0)
	s, err := c.QueryRange(ctx, `cpu.total_pct{server="a"}`, from, to, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 1 || s[0].Labels["__name__"] != "cpu.total_pct" || len(s[0].Points) != 2 ||
		s[0].Points[1] != [2]float64{1700000060500, 2} {
		t.Fatalf("%+v", s)
	}
	if name, err := c.Snapshot(ctx); err != nil || name != "20261103-abc" {
		t.Fatal(name, err)
	}
	if !c.Healthy(ctx) {
		t.Fatal("not healthy")
	}
	if _, err := parseMatrix([]byte(`{"status":"error","error":"syntax error"}`)); err == nil ||
		!strings.Contains(err.Error(), "syntax error") {
		t.Fatal(err)
	}
}

func tgz(t *testing.T, name string, body []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write(body)
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func TestInstall(t *testing.T) {
	hostfs.Root = t.TempDir()
	defer func() { hostfs.Root = "" }()
	bin := []byte("#!/bin/sh\necho vm\n")
	arc := tgz(t, "victoria-metrics-prod", bin)
	old := Sums
	defer func() { Sums = old }()
	Sums = map[string]struct{ Tar, Bin string }{"amd64": {sha(arc), sha(bin)}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(arc) }))
	defer srv.Close()
	oldURL := DownloadURL
	defer func() { DownloadURL = oldURL }()
	DownloadURL = srv.URL + "/%s/%s/%s"

	vm := config.VM{URL: "http://127.0.0.1:8428", Mode: "systemd", Binary: "/usr/local/bin/victoria-metrics-prod",
		Retention: "90d", DataDir: "/var/lib/kurogane/vm"}
	ex := executor.NewFake()
	if err := Install(context.Background(), ex, InstallOpts{VM: vm, Arch: "amd64"}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(hostfs.P(vm.Binary))
	if !bytes.Equal(got, bin) {
		t.Fatal("binary not installed")
	}
	unit, _ := os.ReadFile(hostfs.P(UnitPath))
	if !strings.Contains(string(unit), "-httpListenAddr=127.0.0.1:8428 -storageDataPath=/var/lib/kurogane/vm "+
		"-retentionPeriod=90d") || !strings.Contains(string(unit), "StateDirectory=kurogane/vm") {
		t.Fatal(string(unit))
	}
	if !ex.Called("systemctl enable --now kurogane-vm") {
		t.Fatal(ex.String())
	}

	// offline bundle with a tampered binary is refused
	bad := filepath.Join(t.TempDir(), "vm.tgz")
	os.WriteFile(bad, tgz(t, "victoria-metrics-prod", []byte("evil")), 0o600)
	if err := Install(context.Background(), ex, InstallOpts{VM: vm, Arch: "amd64", Bundle: bad}); err == nil ||
		!strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatal(err)
	}
	// non-loopback VM listen is refused
	vm.URL = "http://0.0.0.0:8428"
	if _, err := Args(vm); err == nil {
		t.Fatal("non-loopback accepted")
	}
}

func TestSupervisorRestarts(t *testing.T) {
	restartMin = 10 * time.Millisecond
	defer func() { restartMin = time.Second }()
	f := filepath.Join(t.TempDir(), "runs")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	run(ctx, "/bin/sh", []string{"-c", "echo x >> " + f + "; exit 1"})
	b, _ := os.ReadFile(f)
	if n := strings.Count(string(b), "x"); n < 2 {
		t.Fatalf("restarted %d times", n)
	}
}
