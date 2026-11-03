package main

import (
	"fmt"

	"github.com/serverkeeper/serverkeeper/internal/db"
	"github.com/spf13/cobra"
)

func init() {
	c := &cobra.Command{Use: "db", Short: "Database maintenance (stop the agent first)"}
	c.AddCommand(&cobra.Command{
		Use:   "migrate-down",
		Short: "Roll back the last schema migration before downgrading one minor version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			s, err := db.Open(cfg.MetaDB())
			if err != nil {
				return err
			}
			defer s.Close()
			if err := s.MigrateDown(); err != nil {
				return fmt.Errorf("migrate down: %w", err)
			}
			fmt.Println("rolled back one migration; install the previous minor version now")
			return nil
		},
	})
	rootCmd.AddCommand(c)
}
