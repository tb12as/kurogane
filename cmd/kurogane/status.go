package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Health summary: metrics, hardening score, active alerts",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			var st struct {
				ServerName string             `json:"server_name"`
				Version    string             `json:"version"`
				Metrics    map[string]float64 `json:"metrics"`
				System     struct {
					OS              string  `json:"os"`
					Kernel          string  `json:"kernel"`
					Uptime          float64 `json:"uptime_s"`
					RebootRequired  bool    `json:"reboot_required"`
					SecurityUpdates int     `json:"security_updates"`
				} `json:"system"`
				Mounts []struct {
					Path    string  `json:"path"`
					UsedPct float64 `json:"used_pct"`
				} `json:"mounts"`
				Hardening *struct {
					Score float64 `json:"score"`
					Grade string  `json:"grade"`
				} `json:"hardening"`
				Alerts []struct {
					RuleID   string `json:"rule_id"`
					Severity string `json:"severity"`
					Summary  string `json:"summary"`
					State    string `json:"state"`
				} `json:"active_alerts"`
			}
			if flagJSON {
				var raw map[string]any
				if err := c.get("/status", nil, &raw); err != nil {
					return err
				}
				printJSON(raw)
				return nil
			}
			if err := c.get("/status", nil, &st); err != nil {
				return err
			}
			fmt.Printf("%s  (kurogane %s)\n", st.ServerName, st.Version)
			fmt.Printf("OS        %s, kernel %s, up %.1f days\n", st.System.OS, st.System.Kernel, st.System.Uptime/86400)
			fmt.Printf("CPU       %.1f%%   load %.2f\n", st.Metrics["cpu.total_pct"], st.Metrics["load.1"])
			fmt.Printf("Memory    %.1f%% available   swap %.1f%% used\n", st.Metrics["mem.available_pct"], st.Metrics["swap.used_pct"])
			for _, m := range st.Mounts {
				fmt.Printf("Disk      %-20s %.1f%% used\n", m.Path, m.UsedPct)
			}
			if st.System.RebootRequired || st.System.SecurityUpdates > 0 {
				fmt.Printf("Updates   %d security updates pending, reboot required: %v\n", st.System.SecurityUpdates, st.System.RebootRequired)
			}
			if st.Hardening != nil {
				fmt.Printf("Hardening %.0f/100 (grade %s)\n", st.Hardening.Score, st.Hardening.Grade)
			} else {
				fmt.Println("Hardening no scan yet: run `kurogane harden scan`")
			}
			fmt.Printf("Alerts    %d active\n", len(st.Alerts))
			for _, a := range st.Alerts {
				fmt.Printf("  [%s] %s %s (%s)\n", a.Severity, a.RuleID, a.Summary, a.State)
			}
			return nil
		},
	})
}
