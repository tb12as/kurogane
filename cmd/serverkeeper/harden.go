package main

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tb12as/serverman/internal/db"
	"github.com/tb12as/serverman/internal/harden"
	"github.com/tb12as/serverman/internal/harden/checks"
)

func clipS(s string, n int) string {
	r := []rune(strings.ReplaceAll(s, "\n", " "))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n-3]) + "..."
}

func confirm(q string) bool {
	fmt.Fprint(os.Stderr, q+" [y/N]: ")
	s, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "y" || s == "yes"
}

func printFixes(rs []harden.FixResult, applied bool) {
	for _, r := range rs {
		fmt.Printf("== %s ==\n", r.CheckID)
		switch {
		case r.Error != "":
			fmt.Println("error:", r.Error)
		case r.Skipped != "":
			fmt.Println("skipped:", r.Skipped)
		case applied && r.Fix != nil:
			v := "not run"
			if r.Verify != nil {
				v = r.Verify.Status + " (" + r.Verify.Evidence + ")"
			}
			fmt.Printf("applied as fix %s; verification: %s\nundo with: serverkeeper harden revert %s\n", r.Fix.ID, v, r.Fix.ID)
			if r.Diff.Note != "" {
				fmt.Println("note:", r.Diff.Note)
			}
		default:
			fmt.Print(r.Diff.Text)
		}
		fmt.Println()
	}
}

func init() {
	h := &cobra.Command{Use: "harden", Short: "Hardening scan, dry-run fixes, reverts and accepted risks"}

	var md bool
	var pdf string
	scan := &cobra.Command{Use: "scan", Short: "Run a read-only scan: results table plus score",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			var sc struct {
				db.Scan
				Results []checks.Result `json:"results"`
			}
			if err := c.do("POST", "/harden/scans", nil, &sc); err != nil {
				return err
			}
			if pdf != "" {
				b, err := c.raw("GET", "/harden/scans/"+sc.ID+"/report?format=pdf", nil)
				if err != nil {
					return err
				}
				if err := os.WriteFile(pdf, b, 0o600); err != nil {
					return err
				}
				fmt.Fprintln(os.Stderr, "wrote", pdf)
			}
			switch {
			case flagJSON:
				printJSON(sc)
				return nil
			case md:
				b, err := c.raw("GET", "/harden/scans/"+sc.ID+"/report?format=md", nil)
				if err == nil {
					os.Stdout.Write(b)
				}
				return err
			}
			w := table("STATUS", "SEVERITY", "CHECK", "TITLE", "EVIDENCE")
			n := map[string]int{}
			for _, r := range sc.Results {
				n[r.Status]++
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", strings.ToUpper(r.Status), r.Severity, r.CheckID, r.Title,
					clipS(r.Evidence, 70))
			}
			if err := w.Flush(); err != nil {
				return err
			}
			fmt.Printf("\nScore %.1f / 100, grade %s (%d pass, %d fail, %d n/a, %d ignored, %d error)\n", sc.Score,
				sc.Grade, n["pass"], n["fail"], n["na"], n["ignored"], n["error"])
			if n["fail"] > 0 {
				fmt.Println("Review a fix with `serverkeeper harden fix <check-id> --dry-run`.")
			}
			return nil
		}}
	scan.Flags().BoolVar(&md, "md", false, "print the Markdown report")
	scan.Flags().StringVar(&pdf, "pdf", "", "also write the PDF report to this file")

	var all, dry, yes bool
	var sev string
	fix := &cobra.Command{Use: "fix <check-id> | --all", Short: "Show the dry-run diff, confirm, apply, verify",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if (len(args) == 0) == !all {
				return fmt.Errorf("give one check id or --all (see `serverkeeper harden checks`)")
			}
			c, err := newClient()
			if err != nil {
				return err
			}
			body := map[string]any{"all": all, "severity": sev, "dry_run": true}
			if len(args) == 1 {
				body["check_id"] = args[0]
			}
			var rs []harden.FixResult
			if err := c.do("POST", "/harden/fixes", body, &rs); err != nil {
				return err
			}
			todo := 0
			for _, r := range rs {
				if r.Error == "" && r.Skipped == "" {
					todo++
				}
			}
			if flagJSON && (dry || todo == 0) {
				printJSON(rs)
				return nil
			}
			printFixes(rs, false)
			if todo == 0 {
				fmt.Println("Nothing to apply.")
				return nil
			}
			if dry {
				return nil
			}
			if !yes && !confirm(fmt.Sprintf("Apply %d fix(es) shown above?", todo)) {
				fmt.Println("Aborted; nothing was changed.")
				return nil
			}
			body["dry_run"], body["confirm"] = false, true
			rs = nil
			if err := c.do("POST", "/harden/fixes", body, &rs); err != nil {
				return err
			}
			if flagJSON {
				printJSON(rs)
				return nil
			}
			printFixes(rs, true)
			return nil
		}}
	fix.Flags().BoolVar(&all, "all", false, "fix every failing fixable check (firewall fixes need an explicit check id)")
	fix.Flags().StringVar(&sev, "severity", "", "with --all: only this severity and above (critical|high|medium|low)")
	fix.Flags().BoolVar(&dry, "dry-run", false, "only show the diff")
	fix.Flags().BoolVarP(&yes, "yes", "y", false, "apply without asking (the diff is still printed)")

	revert := &cobra.Command{Use: "revert <fix-id>", Short: "Restore a fix's backup", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			var f db.Fix
			if err := c.do("POST", "/harden/fixes/"+url.PathEscape(args[0])+"/revert", nil, &f); err != nil {
				return err
			}
			if flagJSON {
				printJSON(f)
				return nil
			}
			fmt.Printf("Reverted fix %s (%s). Run `serverkeeper harden scan` to see the current state.\n", f.ID, f.CheckID)
			return nil
		}}

	var reason string
	ignore := &cobra.Command{Use: "ignore <check-id> --reason \"...\"",
		Short: "Accept the risk of a check (reason required)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(reason) == "" {
				return fmt.Errorf("--reason is mandatory: say why this risk is accepted")
			}
			c, err := newClient()
			if err != nil {
				return err
			}
			var ig db.Ignore
			body := map[string]string{"check_id": args[0], "reason": reason}
			if err := c.do("POST", "/harden/ignores", body, &ig); err != nil {
				return err
			}
			if flagJSON {
				printJSON(ig)
				return nil
			}
			fmt.Printf("%s is now ignored: %s\n", ig.CheckID, ig.Reason)
			return nil
		}}
	ignore.Flags().StringVar(&reason, "reason", "", "why this risk is accepted (mandatory)")
	_ = ignore.MarkFlagRequired("reason")

	list := &cobra.Command{Use: "checks", Short: "List the check catalog",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			var cs []harden.CheckInfo
			if err := c.get("/harden/checks", nil, &cs); err != nil {
				return err
			}
			if flagJSON {
				printJSON(cs)
				return nil
			}
			w := table("CHECK", "SEVERITY", "CATEGORY", "CIS", "AUTO-FIX", "IGNORED", "TITLE")
			for _, x := range cs {
				ig := "-"
				if x.Ignored {
					ig = clipS(x.IgnoreReason, 30)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", x.ID, x.Severity, x.Category, x.CIS, x.AutoFix, ig, x.Title)
			}
			return w.Flush()
		}}

	fixes := &cobra.Command{Use: "fixes", Short: "List applied fixes",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			var fs []db.Fix
			if err := c.get("/harden/fixes", nil, &fs); err != nil {
				return err
			}
			if flagJSON {
				printJSON(fs)
				return nil
			}
			w := table("ID", "CHECK", "STATUS", "APPLIED", "BY", "REVERTED")
			for _, f := range fs {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", f.ID, f.CheckID, f.Status, ts(f.AppliedAt), f.AppliedBy,
					ts(f.RevertedAt))
			}
			return w.Flush()
		}}

	h.AddCommand(scan, fix, revert, ignore, list, fixes)
	rootCmd.AddCommand(h)
}
