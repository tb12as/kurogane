package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/tb12as/serverman/internal/collector"
)

func init() {
	cmd := &cobra.Command{Use: "redis", Short: "Redis instances monitored on this host"}
	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Health and stats per Redis instance; exits 1 when one is down or rejects the credentials",
		RunE: func(*cobra.Command, []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			var s collector.Snapshot
			if err := c.get("/metrics/current", nil, &s); err != nil {
				return err
			}
			if flagJSON {
				printJSON(s.Redis)
			} else {
				printRedis(os.Stdout, s.Redis)
			}
			if n := redisProblems(s.Redis); n > 0 {
				return fmt.Errorf("%d Redis instance(s) down or rejecting credentials", n)
			}
			return nil
		},
	})
	rootCmd.AddCommand(cmd)
}

func redisProblems(rs []collector.RedisInstance) int {
	n := 0
	for _, r := range rs {
		if r.Status == collector.RedisDown || r.Status == collector.RedisAuthFailed {
			n++
		}
	}
	return n
}

func printRedis(out io.Writer, rs []collector.RedisInstance) {
	if len(rs) == 0 {
		fmt.Fprintln(out, "no Redis monitored: none detected, or collector.redis.enabled is false")
		return
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "INSTANCE\tSTATUS\tVERSION\tROLE\tMEMORY\tOPS/S\tHITS\tCLIENTS\tLAST SAVE")
	var notes []string
	for _, r := range rs {
		if r.Status != collector.RedisUp {
			fmt.Fprintf(w, "%s\t%s\t-\t-\t-\t-\t-\t-\t-\n", r.Name, strings.ReplaceAll(r.Status, "_", " "))
			msg := r.Name + ": " + r.Addr
			if r.Error != "" {
				msg += ": " + r.Error
			}
			if r.Hint != "" {
				msg += ". " + r.Hint
			}
			notes = append(notes, msg)
			continue
		}
		mem := bytesShort(r.MemoryUsed)
		if r.MaxMemory > 0 {
			mem += fmt.Sprintf(" / %s (%.0f%%)", bytesShort(r.MaxMemory), 100*r.MemoryUsed/r.MaxMemory)
		}
		hits := "-"
		if r.HitRatio != nil {
			hits = fmt.Sprintf("%.1f%%", *r.HitRatio)
		}
		save := "never"
		if !r.LastSave.IsZero() {
			save = ts(r.LastSave)
		}
		if r.RDBStatus != "" && r.RDBStatus != "ok" {
			save += " (FAILED)"
		}
		role := r.Role
		if r.Role == "master" && r.Replicas > 0 {
			role += fmt.Sprintf(" (%d replicas)", r.Replicas)
		}
		if r.Role == "slave" {
			role = "replica (link " + r.MasterLink + ")"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%.0f\t%s\t%.0f\t%s\n", r.Name, r.Status, r.Version, role, mem, r.OpsPS, hits,
			r.Clients, save)
	}
	w.Flush()
	for _, n := range notes {
		fmt.Fprintln(out, "! "+n)
	}
}

func bytesShort(b float64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for b >= 1024 && i < len(units)-1 {
		b /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f B", b)
	}
	return fmt.Sprintf("%.1f %s", b, units[i])
}
