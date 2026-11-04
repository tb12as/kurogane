package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/tb12as/kurogane/internal/api"
	"github.com/tb12as/kurogane/internal/certs"
)

func init() {
	cmd := &cobra.Command{Use: "certs", Short: "TLS certificates on this host: expiry, issuer and served state"}
	var warnDays float64
	list := &cobra.Command{
		Use:   "list",
		Short: "List certificates; exits 1 when one expires within --warn-days or is served stale",
		Example: "  kurogane certs list\n" +
			"  kurogane certs list --warn-days 30 --json",
		RunE: func(*cobra.Command, []string) error { return certsCmd("GET", "/certs", warnDays) },
	}
	list.Flags().Float64Var(&warnDays, "warn-days", 14, "exit 1 when a certificate has fewer days left")
	rescan := &cobra.Command{
		Use:   "rescan",
		Short: "Scan certificates now, e.g. right after a renewal",
		RunE:  func(*cobra.Command, []string) error { return certsCmd("POST", "/certs/rescan", warnDays) },
	}
	rescan.Flags().Float64Var(&warnDays, "warn-days", 14, "exit 1 when a certificate has fewer days left")
	cmd.AddCommand(list, rescan)
	rootCmd.AddCommand(cmd)
}

func certsCmd(method, path string, warnDays float64) error {
	c, err := newClient()
	if err != nil {
		return err
	}
	var r api.CertsResponse
	if err := c.do(method, path, nil, &r); err != nil {
		return err
	}
	if flagJSON {
		printJSON(r)
	} else {
		printCerts(os.Stdout, r)
	}
	if n := certProblems(r.Certs, warnDays); n > 0 {
		return fmt.Errorf("%d certificate(s) need attention", n)
	}
	return nil
}

func printCerts(out io.Writer, r api.CertsResponse) {
	switch {
	case !r.Enabled:
		fmt.Fprintln(out, "certificate monitoring is off: set collector.certs.enabled: true")
		return
	case r.ScannedAt.IsZero():
		fmt.Fprintln(out, "no scan yet: the first runs a few seconds after the agent starts, or run `kurogane certs rescan`")
		return
	case len(r.Certs) == 0:
		fmt.Fprintf(out, "no certificates found (scanned %s): add files to collector.certs.paths\n", ts(r.ScannedAt))
		return
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tDAYS LEFT\tEXPIRES\tISSUER\tORIGIN\tSERVED\tNOTE")
	for _, x := range r.Certs {
		if x.Error != "" {
			fmt.Fprintf(w, "%s\t-\t-\t-\t%s\t-\t%s: %s\n", x.Name, x.Origin, x.Path, x.Error)
			continue
		}
		served := "-"
		if x.ServedPort != 0 {
			served = fmt.Sprintf(":%d", x.ServedPort)
		}
		var note []string
		if x.Stale {
			note = append(note, "stale: reload the web server (served until "+ts(x.ServedNotAfter)+")")
		}
		if wk := x.Weak(); wk != "" {
			note = append(note, wk)
		}
		fmt.Fprintf(w, "%s\t%.1f\t%s\t%s\t%s\t%s\t%s\n", x.Name, x.DaysLeft, ts(x.NotAfter), x.Issuer, x.Origin, served,
			strings.Join(note, "; "))
	}
	w.Flush()
	fmt.Fprintf(out, "scanned %s\n", ts(r.ScannedAt))
}

// certProblems counts certificates that are expiring, stale or unreadable.
func certProblems(list []certs.Cert, warnDays float64) int {
	n := 0
	for _, x := range list {
		if x.Error != "" || x.Stale || x.DaysLeft < warnDays {
			n++
		}
	}
	return n
}
