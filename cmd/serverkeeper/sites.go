package main

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/tb12as/serverman/internal/api"
	"github.com/tb12as/serverman/internal/db"
	"github.com/tb12as/serverman/internal/sites"
	"github.com/tb12as/serverman/internal/webconf"
)

func init() {
	cmd := &cobra.Command{Use: "sites", Short: "nginx and Apache sites: list, enable or disable safely, test and reload"}

	list := &cobra.Command{
		Use:   "list",
		Short: "List web servers and their sites, enabled and disabled",
		RunE: func(*cobra.Command, []string) error {
			inv, err := fetchSites()
			if err != nil || flagJSON {
				if err == nil {
					printJSON(inv)
				}
				return err
			}
			printSites(os.Stdout, inv)
			return nil
		},
	}

	show := &cobra.Command{
		Use:   "show <name|id>",
		Short: "Show one site and the file that defines it",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			s, err := resolveSite(args[0])
			if err != nil {
				return err
			}
			if flagJSON {
				printJSON(s)
				return nil
			}
			printSite(os.Stdout, s)
			return nil
		},
	}

	var dryRun, yes bool
	toggle := func(enable bool) *cobra.Command {
		verb := map[bool]string{true: "enable", false: "disable"}[enable]
		c := &cobra.Command{
			Use:   verb + " <name|id>",
			Short: strings.ToUpper(verb[:1]) + verb[1:] + " a site: config test, reload, probe; undone automatically on failure",
			Example: "  serverkeeper sites " + verb + " shop.example.org --dry-run\n" +
				"  serverkeeper sites " + verb + " 'nginx:/etc/nginx/sites-enabled/shop#0' --yes",
			Args: cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				s, err := resolveSite(args[0])
				if err != nil {
					return err
				}
				c, err := newClient()
				if err != nil {
					return err
				}
				body := api.SiteToggle{ID: s.ID, Enabled: enable}
				var p sites.Plan
				if err := c.do("POST", "/sites/plan", body, &p); err != nil {
					return err
				}
				printPlan(os.Stdout, p)
				if dryRun {
					return nil
				}
				if !yes && !confirm(fmt.Sprintf("%s %s?", strings.ToUpper(verb[:1])+verb[1:], s.Name)) {
					return errors.New("cancelled")
				}
				var ch db.SiteChange
				if err := c.do("POST", "/sites/apply", body, &ch); err != nil {
					return err
				}
				fmt.Printf("%sd %s (%s)\n", verb, s.Name, ch.Ops)
				return nil
			},
		}
		c.Flags().BoolVar(&dryRun, "dry-run", false, "show what would change and stop")
		c.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask for confirmation")
		return c
	}

	test := &cobra.Command{
		Use:   "test",
		Short: "Run nginx -t / apachectl configtest now; exits 1 when one fails",
		RunE: func(*cobra.Command, []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			var inv api.SitesResponse
			if err := c.do("POST", "/sites/rescan", nil, &inv); err != nil {
				return err
			}
			bad := 0
			for _, w := range inv.Servers {
				if w.ConfigOK {
					fmt.Printf("%s: config ok\n", w.Kind)
					continue
				}
				bad++
				fmt.Printf("%s: config test FAILS: %s\n", w.Kind, w.ConfigError)
			}
			if len(inv.Servers) == 0 {
				fmt.Println("no nginx or Apache configuration found")
			}
			if bad > 0 {
				return fmt.Errorf("%d web server config test(s) fail", bad)
			}
			return nil
		},
	}

	reload := &cobra.Command{
		Use:       "reload nginx|apache",
		Short:     "Config test, then reload; refused while the test fails",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{webconf.Nginx, webconf.Apache},
		RunE: func(_ *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			if err := c.do("POST", "/web/"+url.PathEscape(args[0])+"/reload", nil, nil); err != nil {
				return err
			}
			fmt.Println(args[0], "reloaded")
			return nil
		},
	}

	changes := &cobra.Command{
		Use:   "changes",
		Short: "Site enable/disable history",
		RunE: func(*cobra.Command, []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			var cs []db.SiteChange
			if err := c.get("/sites/changes", nil, &cs); err != nil {
				return err
			}
			if flagJSON {
				printJSON(cs)
				return nil
			}
			w := table("TIME", "ACTOR", "SITE", "ACTION", "STATUS", "DETAIL")
			for _, x := range cs {
				detail := x.Ops
				if x.Error != "" {
					detail = x.Error
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", ts(x.TS), x.Actor, x.SiteName, x.Action, x.Status, detail)
			}
			w.Flush()
			return nil
		},
	}

	cmd.AddCommand(list, show, toggle(true), toggle(false), test, reload, changes)
	rootCmd.AddCommand(cmd)
}

func fetchSites() (api.SitesResponse, error) {
	var inv api.SitesResponse
	c, err := newClient()
	if err != nil {
		return inv, err
	}
	return inv, c.get("/sites", nil, &inv)
}

// resolveSite finds a site by id or by any of its names; several matches must be told apart by id.
func resolveSite(q string) (sites.Site, error) {
	inv, err := fetchSites()
	if err != nil {
		return sites.Site{}, err
	}
	return pickSite(inv, q)
}

func pickSite(inv api.SitesResponse, q string) (sites.Site, error) {
	if !inv.Enabled {
		return sites.Site{}, errors.New("site management is off on this agent: set web.enabled: true")
	}
	found := inv.Find(q)
	switch len(found) {
	case 0:
		return sites.Site{}, fmt.Errorf("no site named %q: run `serverkeeper sites list`", q)
	case 1:
		return found[0], nil
	}
	var ids []string
	for _, s := range found {
		ids = append(ids, "  "+s.ID)
	}
	return sites.Site{}, fmt.Errorf("%q matches %d sites; pass one id:\n%s", q, len(found), strings.Join(ids, "\n"))
}

func listenText(ls []webconf.Listen) string {
	var out []string
	for _, l := range ls {
		p := strconv.Itoa(l.Port)
		if l.TLS {
			p += "/tls"
		}
		out = append(out, p)
	}
	return strings.Join(out, ",")
}

func printSites(out io.Writer, inv api.SitesResponse) {
	if !inv.Enabled {
		fmt.Fprintln(out, "site management is off: set web.enabled: true")
		return
	}
	if len(inv.Servers) == 0 {
		fmt.Fprintln(out, "no nginx or Apache configuration found")
		return
	}
	for _, w := range inv.Servers {
		state := "active"
		if !w.Active {
			state = "NOT active"
		}
		test := "config ok"
		if !w.ConfigOK {
			test = "config test FAILS: " + w.ConfigError
		}
		fmt.Fprintf(out, "%s %s (unit %s %s) · %s\n", w.Kind, w.Version, w.Unit, state, test)
	}
	fmt.Fprintln(out)
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SERVER\tNAME\tLISTEN\tSTATE\tSERVES\tFILE")
	for _, s := range inv.Sites {
		state := "enabled"
		if !s.Enabled {
			state = "disabled"
		}
		if s.Toggle == "" {
			state += " (fixed)"
		}
		serves := s.Root
		if len(s.Upstreams) > 0 {
			serves = "-> " + strings.Join(s.Upstreams, ", ")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s:%d\n", s.Kind, s.Name, listenText(s.Listen), state, serves, s.File, s.Line)
	}
	w.Flush()
}

func printSite(out io.Writer, s sites.Site) {
	fmt.Fprintf(out, "id:        %s\nserver:    %s\nnames:     %s\nlisten:    %s\nenabled:   %v\n", s.ID, s.Kind,
		strings.Join(s.Names, " "), listenText(s.Listen), s.Enabled)
	if s.Root != "" {
		fmt.Fprintf(out, "root:      %s\n", s.Root)
	}
	if len(s.Upstreams) > 0 {
		fmt.Fprintf(out, "upstreams: %s\n", strings.Join(s.Upstreams, " "))
	}
	if len(s.Certs) > 0 {
		days := ""
		if s.CertDays != nil {
			days = fmt.Sprintf(" (%.1f days left)", *s.CertDays)
		}
		fmt.Fprintf(out, "certs:     %s%s\n", strings.Join(s.Certs, " "), days)
	}
	fmt.Fprintf(out, "file:      %s:%d (%d site(s) in the file)\n", s.File, s.Line, s.FileSites)
	if s.Toggle == "" {
		fmt.Fprintf(out, "toggle:    not managed: %s\n", s.NoToggle)
	} else {
		fmt.Fprintf(out, "toggle:    %s\n", s.Toggle)
	}
}

func printPlan(out io.Writer, p sites.Plan) {
	fmt.Fprintf(out, "%s %s\n\n%s\n", strings.ToUpper(p.Action[:1])+p.Action[1:], p.Site.Name, p.Diff)
	for _, i := range p.Impact {
		fmt.Fprintln(out, "- "+i)
	}
	for _, w := range p.Warnings {
		fmt.Fprintln(out, "! "+w)
	}
}
