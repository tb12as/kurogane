package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/serverkeeper/serverkeeper/internal/db"
	"github.com/spf13/cobra"
)

func init() {
	fl := &cobra.Command{Use: "fleet", Short: "Manage enrolled servers, people and fleet-wide SSH keys (central server)"}

	// fc runs f against the central API and prints its table, or JSON with --json.
	fc := func(f func(c *client) (any, func(any))) func(*cobra.Command, []string) error {
		return func(*cobra.Command, []string) error {
			c, err := fleetClient()
			if err != nil {
				return err
			}
			v, pr := f(c)
			if err, ok := v.(error); ok {
				return err
			}
			if flagJSON || pr == nil {
				printJSON(v)
				return nil
			}
			pr(v)
			return nil
		}
	}
	call := func(c *client, method, path string, body, out any) any {
		if err := c.do(method, path, body, out); err != nil {
			return err
		}
		return out
	}

	servers := &cobra.Command{Use: "servers", Short: "List servers with status, score and active alerts"}
	servers.RunE = fc(func(c *client) (any, func(any)) {
		var rows []struct {
			db.Server
			Connected    bool               `json:"connected"`
			ActiveAlerts int                `json:"active_alerts"`
			Latest       map[string]float64 `json:"latest"`
		}
		return call(c, "GET", "/fleet/overview", nil, &rows), func(any) {
			w := table("NAME", "ID", "STATUS", "LAST SEEN", "GRADE", "ALERTS", "CPU%", "MEM%", "DISK%", "TAGS")
			for _, r := range rows {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n", r.Name, r.ID, r.Status, ts(r.LastSeen),
					r.Grade, r.ActiveAlerts, pct(r.Latest, "cpu"), pct(r.Latest, "mem"), pct(r.Latest, "disk"),
					strings.Join(r.Tags, ","))
			}
			w.Flush()
		}
	})
	rm := &cobra.Command{Use: "remove <server>", Args: cobra.ExactArgs(1), Short: "Remove a server (revokes its cert)"}
	rm.RunE = func(_ *cobra.Command, args []string) error {
		c, err := fleetClient()
		if err != nil {
			return err
		}
		return c.do("DELETE", "/servers/"+url.PathEscape(args[0]), nil, nil)
	}

	people := &cobra.Command{Use: "people", Short: "People who own SSH keys"}
	var email string
	var groups []string
	add := &cobra.Command{Use: "add <name>", Args: cobra.ExactArgs(1), Short: "Add a person"}
	add.Flags().StringVar(&email, "email", "", "email")
	add.Flags().StringSliceVar(&groups, "group", nil, "groups (repeatable)")
	add.RunE = func(_ *cobra.Command, args []string) error {
		c, err := fleetClient()
		if err != nil {
			return err
		}
		var p db.Person
		if err := c.do("POST", "/fleet/people", map[string]any{"name": args[0], "email": email, "groups": groups},
			&p); err != nil {
			return err
		}
		fmt.Println("added", p.Name, p.ID)
		return nil
	}
	list := &cobra.Command{Use: "list", Short: "List people"}
	list.RunE = fc(func(c *client) (any, func(any)) {
		var ps []db.Person
		return call(c, "GET", "/fleet/people", nil, &ps), func(any) {
			w := table("NAME", "ID", "GROUPS", "KEYS")
			for _, p := range ps {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\n", p.Name, p.ID, strings.Join(p.Groups, ","), len(p.Keys))
			}
			w.Flush()
		}
	})
	del := &cobra.Command{Use: "delete <person>", Args: cobra.ExactArgs(1), Short: "Delete a person"}
	del.RunE = func(_ *cobra.Command, args []string) error {
		c, err := fleetClient()
		if err != nil {
			return err
		}
		return c.do("DELETE", "/fleet/people/"+url.PathEscape(args[0]), nil, nil)
	}
	var keyFile, loginUser string
	addKey := &cobra.Command{Use: "add-key <person>", Args: cobra.ExactArgs(1), Short: "Assign a public key to a person"}
	addKey.Flags().StringVar(&keyFile, "file", "", "public key file (id_ed25519.pub)")
	addKey.Flags().StringVar(&loginUser, "login-user", "", "default login user for pushes")
	addKey.RunE = func(_ *cobra.Command, args []string) error {
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("read --file: %w", err)
		}
		c, err := fleetClient()
		if err != nil {
			return err
		}
		var k db.PersonKey
		if err := c.do("POST", "/fleet/people/"+url.PathEscape(args[0])+"/keys",
			map[string]string{"public_key": strings.TrimSpace(string(b)), "login_user": loginUser}, &k); err != nil {
			return err
		}
		fmt.Println("added key", k.Fingerprint)
		return nil
	}
	var leave bool
	join := &cobra.Command{Use: "group <person> <group>", Args: cobra.ExactArgs(2), Short: "Add a person to a group"}
	join.Flags().BoolVar(&leave, "remove", false, "remove from the group instead")
	join.RunE = func(_ *cobra.Command, args []string) error {
		c, err := fleetClient()
		if err != nil {
			return err
		}
		return c.do("POST", "/fleet/people/"+url.PathEscape(args[0])+"/groups",
			map[string]any{"group": args[1], "member": !leave}, nil)
	}
	people.AddCommand(add, list, del, addKey, join)

	grps := &cobra.Command{Use: "groups", Short: "List groups and members"}
	grps.RunE = fc(func(c *client) (any, func(any)) {
		var g map[string][]string
		return call(c, "GET", "/fleet/groups", nil, &g), func(any) {
			w := table("GROUP", "MEMBERS")
			for k, v := range g {
				fmt.Fprintf(w, "%s\t%s\n", k, strings.Join(v, ","))
			}
			w.Flush()
		}
	})

	var person, group, loginAs, tag string
	push := &cobra.Command{Use: "push", Short: "Push a person's or group's keys to all servers (or --tag)"}
	push.Flags().StringVar(&person, "person", "", "person")
	push.Flags().StringVar(&group, "group", "", "group")
	push.Flags().StringVar(&loginAs, "user", "", "login user on the servers (default: each key's login user)")
	push.Flags().StringVar(&tag, "tag", "", "only servers with this tag")
	push.RunE = fc(func(c *client) (any, func(any)) {
		var out struct {
			Ops     []db.FleetOp `json:"ops"`
			Servers int          `json:"servers"`
			People  int          `json:"people"`
		}
		body := map[string]string{"person": person, "group": group, "user": loginAs, "tag": tag}
		return call(c, "POST", "/fleet/keys/push", body, &out), func(any) {
			fmt.Printf("queued %d key operations for %d people on %d servers (see `serverkeeper fleet ops`)\n",
				len(out.Ops), out.People, out.Servers)
		}
	})
	revoke := &cobra.Command{Use: "revoke <fingerprint>", Args: cobra.ExactArgs(1),
		Short: "Remove a key from every server and every person"}
	revoke.RunE = func(_ *cobra.Command, args []string) error {
		c, err := fleetClient()
		if err != nil {
			return err
		}
		var out struct {
			Servers int `json:"servers"`
		}
		if err := c.do("POST", "/fleet/keys/revoke", map[string]string{"fingerprint": args[0]}, &out); err != nil {
			return err
		}
		fmt.Printf("revoke queued on %d servers (offline servers get it on reconnect)\n", out.Servers)
		return nil
	}
	ops := &cobra.Command{Use: "ops", Short: "Recent fleet operations and their results"}
	ops.RunE = fc(func(c *client) (any, func(any)) {
		var l []db.FleetOp
		return call(c, "GET", "/fleet/ops", nil, &l), func(any) {
			w := table("ID", "SERVER", "KIND", "STATUS", "CREATED", "RESULT")
			for _, o := range l {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", o.ID, o.ServerID, o.Kind, o.Status, ts(o.CreatedAt), o.Result)
			}
			w.Flush()
		}
	})
	var scanTag string
	scan := &cobra.Command{Use: "scan", Short: "Run a hardening scan on all servers (or --tag)"}
	scan.Flags().StringVar(&scanTag, "tag", "", "only servers with this tag")
	scan.RunE = fc(func(c *client) (any, func(any)) {
		var out []db.FleetOp
		return call(c, "POST", "/fleet/scans", map[string]string{"tag": scanTag}, &out), func(any) {
			fmt.Printf("scan queued on %d servers\n", len(out))
		}
	})
	fl.AddCommand(servers, rm, people, grps, push, revoke, ops, scan)
	rootCmd.AddCommand(fl)
}

func pct(m map[string]float64, k string) string {
	v, ok := m[k]
	if !ok {
		return "-"
	}
	return fmt.Sprintf("%.0f", v)
}
