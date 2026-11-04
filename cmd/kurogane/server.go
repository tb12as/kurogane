package main

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	_ "github.com/tb12as/kurogane/internal/agentlink" // agent side of the central link (agent.Hooks)
	"github.com/tb12as/kurogane/internal/auth"
	"github.com/tb12as/kurogane/internal/config"
	"github.com/tb12as/kurogane/internal/db"
	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/metricsdb"
	"github.com/tb12as/kurogane/internal/secret"
	"github.com/tb12as/kurogane/internal/server"
)

const serverSection = `
# v1 central server (kurogane server init)
server:
  grpc_listen: 0.0.0.0:9444      # agents connect here (mutual TLS)
  http_listen: 127.0.0.1:9443    # web UI / API (SSH tunnel or TLS)
  offline_after: 2m
  vm:
    url: http://127.0.0.1:8428
    mode: %s                # systemd | child
    binary: /usr/local/bin/victoria-metrics-prod
    retention: 90d
    data_dir: %s/vm
  backup:
    dest: %s/backups         # point at an off-host mount
    schedule: "30 2 * * *"
    keep: 7
`

// fleetClient talks to the central API (server.http_listen) unless --api / KRGN_API is given.
func fleetClient() (*client, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	base := flagAPI
	if base == "" && os.Getenv("KRGN_API") == "" {
		scheme := "http"
		if cfg.TLS.Cert != "" {
			scheme = "https"
		}
		base = scheme + "://" + cfg.Server.HTTPListen
	}
	return newClientFor(cfg, base)
}

func init() {
	srv := &cobra.Command{Use: "server", Short: "Central server for a fleet of agents (v1)"}

	var bundle, mode, adminUser, adminPass, dataDir string
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Set up the central server: config section, CA, database and VictoriaMetrics",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := context.Background()
			if mode != "systemd" && mode != "child" {
				return fmt.Errorf("--vm-mode %q: use systemd or child", mode)
			}
			if err := writeServerConfig(dataDir, mode); err != nil {
				return err
			}
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
				return fmt.Errorf("create %s: %w (run as root)", cfg.DataDir, err)
			}
			box, err := secret.LoadOrCreate(cfg.SecretKey)
			if err != nil {
				return err
			}
			if _, err := server.LoadOrCreateCA(filepath.Join(cfg.DataDir, "ca")); err != nil {
				return err
			}
			store, err := db.Open(cfg.MetaDB())
			if err != nil {
				return err
			}
			if adminPass != "" {
				_, url, err := auth.NewService(store, box, 0).CreateUser(ctx, adminUser, adminPass, "admin")
				if err != nil {
					fmt.Println("admin user not created:", err)
				} else {
					fmt.Println("Admin user created. Add this to your authenticator app (TOTP is mandatory):\n  " + url)
					printQR(url)
				}
			}
			store.Close()
			fmt.Printf("Installing VictoriaMetrics %s (%s mode)...\n", metricsdb.Version, cfg.Server.VM.Mode)
			o := metricsdb.InstallOpts{VM: cfg.Server.VM, Bundle: bundle}
			if err := metricsdb.Install(ctx, executor.Local{}, o); err != nil {
				return err
			}
			chownServer(cfg)
			fmt.Println("\nDone. Start the central server:  systemctl enable --now kurogane-server")
			fmt.Println("Enroll an agent:                 kurogane server token create --name web-01")
			return nil
		},
	}
	f := initCmd.Flags()
	f.StringVar(&bundle, "bundle", "", "offline VictoriaMetrics release tar.gz instead of downloading")
	f.StringVar(&mode, "vm-mode", "systemd", "run VictoriaMetrics as its own systemd unit or as a child process")
	f.StringVar(&adminUser, "admin-user", "admin", "admin username")
	f.StringVar(&adminPass, "admin-password", "", "create the admin user with this password")
	f.StringVar(&dataDir, "data-dir", "/var/lib/kurogane", "data directory (new config only)")

	run := &cobra.Command{
		Use:   "run",
		Short: "Run the central server in the foreground (used by kurogane-server.service)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			c, err := server.New(cfg, version)
			if err != nil {
				return err
			}
			ctx, cancel := signalCtx()
			defer cancel()
			return c.Run(ctx)
		},
	}

	var name string
	token := &cobra.Command{Use: "token", Short: "Agent enrollment tokens"}
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a one-time enrollment token (expires in 1 h)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := fleetClient()
			if err != nil {
				return err
			}
			var out struct {
				Token     string    `json:"token"`
				ExpiresAt time.Time `json:"expires_at"`
			}
			if err := c.do("POST", "/fleet/enrollment-tokens", map[string]string{"name": name}, &out); err != nil {
				return err
			}
			if flagJSON {
				printJSON(out)
				return nil
			}
			fmt.Printf("%s\n\nValid until %s, usable once. On the agent set in config.yaml:\n"+
				"  central:\n    addr: <this host>:9444\n    enrollment_token: %s\n", out.Token, ts(out.ExpiresAt), out.Token)
			return nil
		},
	}
	create.Flags().StringVar(&name, "name", "", "bind the token to this server name")
	token.AddCommand(create)
	srv.AddCommand(initCmd, run, token)
	rootCmd.AddCommand(srv)
}

// writeServerConfig creates a config with a server section, or appends the section to an existing config.
func writeServerConfig(dataDir, mode string) error {
	b, err := os.ReadFile(flagConfig)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		dd := dataDir
		if cfg, err := config.Load(flagConfig); err == nil {
			dd = cfg.DataDir
		}
		if strings.Contains("\n"+string(b), "\nserver:") {
			return nil
		}
		f, err := os.OpenFile(flagConfig, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			return fmt.Errorf("update %s: %w (run as root)", flagConfig, err)
		}
		defer f.Close()
		_, err = fmt.Fprintf(f, serverSection, mode, dd, dd)
		return err
	}
	host, _ := os.Hostname()
	body := fmt.Sprintf("# /etc/kurogane/config.yaml (central server)\nserver_name: %s\ndata_dir: %s\n"+
		"secret_key: %s\n", host, dataDir, filepath.Join(filepath.Dir(flagConfig), "secret.key")) +
		fmt.Sprintf(serverSection, mode, dataDir, dataDir)
	if err := os.MkdirAll(filepath.Dir(flagConfig), 0o755); err != nil { // #nosec G301 -- /etc/kurogane must be traversable
		return err
	}
	return os.WriteFile(flagConfig, []byte(body), 0o640) // #nosec G306 -- config is 0640 root:kurogane; secrets live in secret.key
}

// chownServer hands the data dir, secret key and config to the `kurogane` user the central unit runs as.
func chownServer(cfg *config.Config) {
	u, err := user.Lookup("kurogane")
	if os.Geteuid() != 0 || err != nil {
		return
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	// Lchown + skip symlinks: the unprivileged user owns this tree and could plant a link to e.g. /etc/shadow
	_ = filepath.Walk(cfg.DataDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		return os.Lchown(p, uid, gid) // #nosec G122 -- symlinks are skipped and Lchown never follows links
	})
	_ = os.Chown(cfg.SecretKey, uid, gid)
	_ = os.Chown(flagConfig, 0, gid)
}
