// Command serverkeeper is the ServerKeeper agent, central server and CLI (PRD §10.1).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/tb12as/serverman/internal/config"
	"github.com/tb12as/serverman/internal/secret"
)

// version is set by -ldflags at release time.
var version = "dev"

var (
	flagConfig   string
	flagAPI      string
	flagToken    string
	flagInsecure bool
	flagJSON     bool
	flagVerbose  bool
)

var rootCmd = &cobra.Command{
	Use:           "serverkeeper",
	Short:         "Monitor, secure and harden a Linux server from one binary",
	SilenceUsage:  true,
	SilenceErrors: true,
	Version:       version,
	PersistentPreRun: func(cmd *cobra.Command, _ []string) {
		lvl := slog.LevelInfo
		if flagVerbose {
			lvl = slog.LevelDebug
		}
		secret.SetupLogging(lvl)
	},
}

func init() {
	pf := rootCmd.PersistentFlags()
	pf.StringVarP(&flagConfig, "config", "c", config.DefaultPath, "config file")
	pf.StringVar(&flagAPI, "api", "", "API base URL (default from config listen)")
	pf.StringVar(&flagToken, "token", "", "API token (default $SK_TOKEN or the local CLI token)")
	pf.BoolVar(&flagInsecure, "insecure", false, "skip TLS verification (self-signed certs)")
	pf.BoolVar(&flagJSON, "json", false, "print JSON")
	pf.BoolVarP(&flagVerbose, "verbose", "v", false, "debug logging")
}

func loadConfig() (*config.Config, error) { return config.Load(flagConfig) }

func signalCtx() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
