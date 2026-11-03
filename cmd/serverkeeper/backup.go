package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/serverkeeper/serverkeeper/internal/backup"
	"github.com/serverkeeper/serverkeeper/internal/config"
	"github.com/serverkeeper/serverkeeper/internal/db"
	"github.com/serverkeeper/serverkeeper/internal/metricsdb"
	"github.com/serverkeeper/serverkeeper/internal/store"
	"github.com/spf13/cobra"
)

func init() {
	var dest string
	var central bool
	bk := &cobra.Command{
		Use:   "backup",
		Short: "Back up SQLite (VACUUM INTO), the agent store and, on the central server, a VictoriaMetrics snapshot",
		Long: "Runs inside the running agent/central server through the API; when none is running the files are " +
			"backed up directly. Backups land in server.backup.dest (mount an off-host target there).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			c, err := newClient()
			if central {
				c, err = fleetClient()
			}
			var out struct {
				Path string `json:"path"`
			}
			if err == nil {
				err = c.do("POST", "/backup", map[string]string{"dest": dest}, &out)
				var ne *net.OpError
				if err == nil || !errors.As(err, &ne) {
					if err == nil {
						fmt.Println("backup written to", out.Path)
					}
					return err
				}
			}
			// nothing running: back up the files directly
			p, err := offlineBackup(cfg, dest, central)
			if err != nil {
				return err
			}
			fmt.Println("backup written to", p)
			return nil
		},
	}
	bk.Flags().StringVar(&dest, "dest", "", "destination directory (default server.backup.dest)")
	bk.Flags().BoolVar(&central, "central", false, "back up the central server (adds the VictoriaMetrics snapshot)")

	var yes bool
	rs := &cobra.Command{
		Use:   "restore <backup-dir>",
		Args:  cobra.ExactArgs(1),
		Short: "Restore a backup; stop serverkeeper, serverkeeper-server and serverkeeper-vm first",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			for _, a := range []string{cfg.Listen, cfg.Server.HTTPListen} {
				if conn, err := net.DialTimeout("tcp", a, time.Second); err == nil {
					conn.Close()
					return fmt.Errorf("something is listening on %s: stop serverkeeper / serverkeeper-server first", a)
				}
			}
			if metricsdb.New(cfg.Server.VM.URL).Healthy(context.Background()) {
				return fmt.Errorf("VictoriaMetrics is running: `systemctl stop serverkeeper-vm` first")
			}
			if !yes {
				return fmt.Errorf("this replaces %s, %s and %s (old copies are kept as *.pre-restore-*): "+
					"re-run with --yes", cfg.MetaDB(), cfg.AgentDB(), cfg.Server.VM.DataDir)
			}
			done, err := backup.Restore(args[0], backup.RestoreOpts{MetaDB: cfg.MetaDB(), AgentDB: cfg.AgentDB(),
				VMDir: cfg.Server.VM.DataDir})
			for _, d := range done {
				fmt.Println("restored", d)
			}
			if err != nil {
				return err
			}
			fmt.Println("done: start the services again; data files must be owned by the serverkeeper user")
			return nil
		},
	}
	rs.Flags().BoolVar(&yes, "yes", false, "confirm replacing the current data")
	rootCmd.AddCommand(bk, rs)
}

func offlineBackup(cfg *config.Config, dest string, central bool) (string, error) {
	ctx := context.Background()
	meta, err := db.Open(cfg.MetaDB())
	if err != nil {
		return "", err
	}
	defer meta.Close()
	o := backup.Options{Cfg: cfg, DB: meta, Dest: dest, Keep: cfg.Server.Backup.Keep}
	if central {
		o.VM = metricsdb.New(cfg.Server.VM.URL)
		if !o.VM.Healthy(ctx) {
			o.VM = nil
			fmt.Println("VictoriaMetrics not running: metrics are not included")
		}
	} else if st, err := store.Open(cfg.AgentDB()); err == nil {
		defer st.Close()
		o.Bolt = st.DB()
	}
	p, _, err := backup.Run(ctx, o)
	return p, err
}
