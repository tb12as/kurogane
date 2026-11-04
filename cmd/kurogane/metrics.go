package main

import (
	"fmt"
	"math"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/tb12as/kurogane/internal/collector"
	"github.com/tb12as/kurogane/internal/store"
	"github.com/tb12as/kurogane/internal/tui"
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "top",
		Short: "Live terminal dashboard: CPU, memory, disk, network, connections, processes",
		RunE: func(*cobra.Command, []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			return tui.Run(func() (*collector.Snapshot, error) {
				var s collector.Snapshot
				if err := c.get("/metrics/current", nil, &s); err != nil {
					return nil, err
				}
				return &s, nil
			})
		},
	})

	var since, until, step string
	get := &cobra.Command{
		Use:   "get <names>",
		Short: "Print metric history, e.g. `metrics get cpu,mem --since 6h --step 1m`",
		Args:  cobra.ExactArgs(1),
		Example: "  serverkeeper metrics get cpu.total_pct,load --since 24h\n" +
			"  serverkeeper metrics get net --since 1h --json",
		RunE: func(_ *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			q := url.Values{"names": {args[0]}, "from": {since}}
			if until != "" {
				q.Set("to", until)
			}
			if step != "" {
				q.Set("step", step)
			}
			if flagJSON {
				var raw map[string]any
				if err := c.get("/metrics/history", q, &raw); err != nil {
					return err
				}
				printJSON(raw)
				return nil
			}
			var h struct {
				Series []store.Series `json:"series"`
			}
			if err := c.get("/metrics/history", q, &h); err != nil {
				return err
			}
			if len(h.Series) == 0 {
				fmt.Printf("no data for %q since %s: check names (e.g. cpu, mem, disk, net) or widen --since\n", args[0], since)
				return nil
			}
			w := table("SERIES", "LAST", "AVG", "MAX", "POINTS")
			for _, s := range h.Series {
				if len(s.Points) == 0 {
					continue
				}
				sum, mx := 0.0, math.Inf(-1)
				for _, p := range s.Points {
					sum += p[1]
					mx = math.Max(mx, p[2])
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n", collector.SeriesKey(s.Metric, s.Labels), num(s.Points[len(s.Points)-1][1]),
					num(sum/float64(len(s.Points))), num(mx), len(s.Points))
			}
			return w.Flush()
		},
	}
	get.Flags().StringVar(&since, "since", "1h", "start: duration ago (6h, 7d), RFC3339 or unix seconds")
	get.Flags().StringVar(&until, "until", "", "end (default now), same formats as --since")
	get.Flags().StringVar(&step, "step", "", "bucket size, e.g. 10s, 1m, 1h (default: ~360 points)")
	m := &cobra.Command{Use: "metrics", Short: "Query current and historical metrics"}
	m.AddCommand(get)
	rootCmd.AddCommand(m)
}

// num prints large byte-ish values compactly and small ones with two decimals.
func num(v float64) string {
	if math.Abs(v) >= 1e6 {
		return fmt.Sprintf("%.3g", v)
	}
	return fmt.Sprintf("%.2f", v)
}
