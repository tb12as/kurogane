package main

import (
	"github.com/spf13/cobra"
	"github.com/tb12as/serverman/internal/agent"
)

func init() {
	agentCmd := &cobra.Command{Use: "agent", Short: "Run the agent (used by the systemd unit)"}
	agentCmd.AddCommand(&cobra.Command{
		Use:   "run",
		Short: "Run the agent in the foreground",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			ctx, cancel := signalCtx()
			defer cancel()
			return agent.RunPrivsep(ctx, cfg, flagConfig, version)
		},
	}, &cobra.Command{
		Use:    "worker",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			ctx, cancel := signalCtx()
			defer cancel()
			return agent.RunWorker(ctx, cfg, version)
		},
	})
	rootCmd.AddCommand(agentCmd)
}
