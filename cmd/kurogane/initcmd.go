package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/spf13/cobra"
	"github.com/tb12as/kurogane/deploy"
	"github.com/tb12as/kurogane/internal/auth"
	"github.com/tb12as/kurogane/internal/config"
	"github.com/tb12as/kurogane/internal/db"
	"github.com/tb12as/kurogane/internal/executor"
	"github.com/tb12as/kurogane/internal/secret"
)

const configTmpl = `# /etc/kurogane/config.yaml (written by kurogane init)
server_name: {{.Name}}
tags: [{{join .Tags ", "}}]
listen: {{.Listen}}
data_dir: {{.DataDir}}
secret_key: {{.SecretKey}}

collector:
  interval: 10s
  retention_raw: 24h
  retention_rollup: 7d
  watch_services: [{{join .Services ", "}}]

ssh:
  rollback_timeout: 120s
  bruteforce:
    enabled: true
    max_failures: 5
    window: 10m
    ban_for: 1h
    allowlist: []

harden:
  schedule: "0 3 * * *"
  ignore: []

alerts:
  channels:
{{- range .Channels}}
    - name: {{.Name}}
      type: {{.Type}}
      webhook_url: "{{.URL}}"   # encrypted with secret_key
{{- end}}
{{- if not .Channels}} []{{end}}
  rules: []
  repeat_interval: 30m

telemetry:
  enabled: {{.Telemetry}}
`

type initChannel struct{ Name, Type, URL string }

func init() {
	var nonInteractive bool
	var adminUser, adminPass, dataDir string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Interactive setup: writes /etc/kurogane/config.yaml, creates the admin user and systemd unit",
		RunE: func(cmd *cobra.Command, _ []string) error {
			in := bufio.NewReader(os.Stdin)
			ask := func(q, def string) string {
				if nonInteractive {
					return def
				}
				fmt.Printf("%s [%s]: ", q, def)
				s, _ := in.ReadString('\n')
				if s = strings.TrimSpace(s); s != "" {
					return s
				}
				return def
			}
			if _, err := os.Stat(flagConfig); err == nil && !nonInteractive {
				if ask("Config "+flagConfig+" exists. Overwrite? (y/N)", "n") != "y" {
					return fmt.Errorf("aborted: %s left unchanged", flagConfig)
				}
			}
			host, _ := os.Hostname()
			d := struct {
				Name, Listen, DataDir, SecretKey string
				Tags, Services                   []string
				Channels                         []initChannel
				Telemetry                        bool
			}{
				Name:      ask("Server name", host),
				Listen:    ask("Web UI/API listen address (keep 127.0.0.1, use an SSH tunnel)", "127.0.0.1:9443"),
				DataDir:   dataDir,
				SecretKey: filepath.Join(filepath.Dir(flagConfig), "secret.key"),
			}
			d.Tags = splitList(ask("Tags (comma separated)", ""))
			d.Services = splitList(ask("systemd services to watch", detectServices()))
			box, err := secret.LoadOrCreate(d.SecretKey)
			if err != nil {
				return err
			}
			for _, t := range []string{"slack", "discord"} {
				u := ask(strings.ToUpper(t[:1])+t[1:]+" incoming webhook URL (empty to skip)", "")
				if u == "" {
					continue
				}
				sealed, err := box.Seal(u)
				if err != nil {
					return err
				}
				d.Channels = append(d.Channels, initChannel{Name: t, Type: t, URL: sealed})
			}
			d.Telemetry = ask("Share anonymous onboarding timing (opt-in)? (y/N)", "n") == "y"

			t := template.Must(template.New("c").Funcs(template.FuncMap{"join": strings.Join}).Parse(configTmpl))
			var b strings.Builder
			if err := t.Execute(&b, d); err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(flagConfig), 0o755); err != nil { // #nosec G301 -- /etc/kurogane must be traversable
				return err
			}
			if err := os.WriteFile(flagConfig, []byte(b.String()), 0o640); err != nil { // #nosec G306 -- config is 0640 root:kurogane; secrets are sealed
				return fmt.Errorf("write %s: %w (run as root)", flagConfig, err)
			}
			cfg, err := config.Load(flagConfig)
			if err != nil {
				return fmt.Errorf("generated config invalid: %w", err)
			}
			if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
				return err
			}
			store, err := db.Open(cfg.MetaDB())
			if err != nil {
				return err
			}
			defer store.Close()
			ctx := context.Background()
			_ = store.SetKV(ctx, "telemetry.installed_at", time.Now().UTC().Format(time.RFC3339))

			adminUser = ask("Admin username", adminUser)
			if adminPass == "" && !nonInteractive {
				if adminPass, err = readPassword("Admin password (min 10 chars): "); err != nil {
					return err
				}
			}
			if adminPass != "" {
				a := auth.NewService(store, box, 0)
				if _, url, err := a.CreateUser(ctx, adminUser, adminPass, "admin"); err != nil {
					fmt.Println("admin user not created:", err)
				} else {
					fmt.Println("\nAdmin user created. Scan this in your authenticator app (TOTP is mandatory):")
					fmt.Println("  " + url)
				}
			}
			if err := installUnit(ctx); err != nil {
				fmt.Println("systemd unit not installed:", err)
			}
			fmt.Printf("\nDone. Open the dashboard through an SSH tunnel:\n  ssh -L 9443:%s <server>  then browse http://127.0.0.1:9443\n", cfg.Listen)
			return nil
		},
	}
	cmd.Flags().BoolVar(&nonInteractive, "yes", false, "non-interactive, accept defaults")
	cmd.Flags().StringVar(&adminUser, "admin-user", "admin", "admin username")
	cmd.Flags().StringVar(&adminPass, "admin-password", "", "admin password (prompted if empty)")
	cmd.Flags().StringVar(&dataDir, "data-dir", "/var/lib/kurogane", "data directory")
	rootCmd.AddCommand(cmd)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// detectServices proposes common units that exist on this host.
func detectServices() string {
	var found []string
	for _, u := range []string{"nginx", "apache2", "httpd", "mysql", "mariadb", "postgresql", "docker", "redis-server", "ssh", "sshd"} {
		for _, d := range []string{"/lib/systemd/system/", "/usr/lib/systemd/system/", "/etc/systemd/system/"} {
			if _, err := os.Stat(d + u + ".service"); err == nil {
				found = append(found, u)
				break
			}
		}
	}
	return strings.Join(found, ", ")
}

func installUnit(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("not root")
	}
	if _, err := os.Stat("/etc/systemd/system"); err != nil {
		return fmt.Errorf("systemd not found")
	}
	ex := executor.Local{}
	if err := ex.WriteFile("/etc/systemd/system/kurogane.service", deploy.AgentUnit, 0o644); err != nil {
		return err
	}
	if _, err := ex.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	_, err := ex.Run(ctx, "systemctl", "enable", "--now", "kurogane")
	return err
}
