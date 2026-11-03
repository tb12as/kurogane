package metricsdb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/tb12as/serverman/internal/config"
	"github.com/tb12as/serverman/internal/executor"
)

// Version is the pinned VictoriaMetrics single-node release.
const Version = "v1.154.1"

// Sums pins sha256 of the release tarball and of the victoria-metrics-prod binary inside it, per arch
// (from the release's *_checksums.txt).
var Sums = map[string]struct{ Tar, Bin string }{
	"amd64": {"8c40aec9f77be3a85fbe4b491238b80936af50497fef980b9434095d5076e424",
		"aee69bdf1b7776e2277435e3b0d60c399668a91cd064f5d8010ef9aab5c06851"},
	"arm64": {"9bbc27a62e7f16fbe4bf995c5c4975fcbdd5e856e302e9ec833eb963ce097d11",
		"f358815080bf3b016f0810e053bf41d876fc20c806028fa2f3eab6fc80affebd"},
}

// DownloadURL is the release asset URL template (version, arch, version).
var DownloadURL = "https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/" +
	"%s/victoria-metrics-linux-%s-%s.tar.gz"

// UnitPath is the systemd unit written for vm.mode=systemd.
const UnitPath = "/etc/systemd/system/serverkeeper-vm.service"

// InstallOpts configures Install.
type InstallOpts struct {
	VM     config.VM
	Arch   string // default runtime.GOARCH
	Bundle string // local release tarball (offline install) instead of downloading
	HC     *http.Client
}

// Args returns the VM command line; the listen address comes from vm.url and must be loopback (§11.1).
func Args(vm config.VM) ([]string, error) {
	u, err := url.Parse(vm.URL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("server.vm.url %q invalid: use http://127.0.0.1:8428", vm.URL)
	}
	host := u.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host += ":8428"
	}
	if !config.IsLoopback(host) {
		return nil, fmt.Errorf("server.vm.url %s is not loopback: VictoriaMetrics must listen on 127.0.0.1", vm.URL)
	}
	ret := vm.Retention
	if ret == "" {
		ret = "90d"
	}
	return []string{"-httpListenAddr=" + host, "-storageDataPath=" + vm.DataDir, "-retentionPeriod=" + ret}, nil
}

// Install fetches (or reads from Bundle) the pinned release, verifies its checksums, installs the binary to
// vm.Binary and, for mode systemd, writes and enables serverkeeper-vm.service.
func Install(ctx context.Context, ex executor.Executor, o InstallOpts) error {
	if o.Arch == "" {
		o.Arch = runtime.GOARCH
	}
	sum, ok := Sums[o.Arch]
	if !ok {
		return fmt.Errorf("no pinned VictoriaMetrics build for %s: supported amd64, arm64", o.Arch)
	}
	args, err := Args(o.VM)
	if err != nil {
		return err
	}
	var tgz []byte
	if o.Bundle != "" {
		if tgz, err = os.ReadFile(o.Bundle); err != nil {
			return fmt.Errorf("read bundle: %w", err)
		}
	} else {
		if tgz, err = download(ctx, o.HC, fmt.Sprintf(DownloadURL, Version, o.Arch, Version)); err != nil {
			return err
		}
		if got := sha(tgz); got != sum.Tar {
			return fmt.Errorf("VictoriaMetrics download checksum mismatch (got %s, want %s): retry, or use --bundle",
				got, sum.Tar)
		}
	}
	bin, err := extract(tgz, "victoria-metrics-prod")
	if err != nil {
		return err
	}
	if got := sha(bin); got != sum.Bin {
		return fmt.Errorf("victoria-metrics-prod checksum mismatch (got %s, want %s): the bundle must contain "+
			"VictoriaMetrics %s linux-%s", got, sum.Bin, Version, o.Arch)
	}
	if err := ex.WriteFile(o.VM.Binary, bin, 0o755); err != nil {
		return fmt.Errorf("install %s: %w", o.VM.Binary, err)
	}
	if o.VM.Mode != "systemd" {
		return nil
	}
	if err := ex.WriteFile(UnitPath, []byte(Unit(o.VM.Binary, o.VM.DataDir, args)), 0o644); err != nil {
		return err
	}
	if _, err := ex.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	_, err = ex.Run(ctx, "systemctl", "enable", "--now", "serverkeeper-vm")
	return err
}

// Unit renders serverkeeper-vm.service.
func Unit(bin, dataDir string, args []string) string {
	state := ""
	if rel, ok := strings.CutPrefix(path.Clean(dataDir), "/var/lib/"); ok {
		state = "StateDirectory=" + rel + "\n"
	}
	return `[Unit]
Description=VictoriaMetrics for the ServerKeeper central server
After=network.target

[Service]
Type=simple
User=serverkeeper
Group=serverkeeper
ExecStart=` + bin + " " + strings.Join(args, " ") + `
Restart=always
RestartSec=5
` + state + `ReadWritePaths=` + dataDir + `
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`
}

func download(ctx context.Context, hc *http.Client, u string) ([]byte, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w (no network? use `server init --bundle <tar.gz>`)", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", u, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 200<<20))
}

func extract(tgz []byte, name string) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return nil, fmt.Errorf("bundle is not a .tar.gz: %w", err)
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s not found in archive", name)
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag == tar.TypeReg && path.Base(h.Name) == name {
			return io.ReadAll(io.LimitReader(tr, 200<<20))
		}
	}
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
