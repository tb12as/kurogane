package main

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	s, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(s), err
}

func init() {
	users := &cobra.Command{Use: "users", Short: "Manage web UI users (admin, operator, viewer)"}
	var role string
	add := &cobra.Command{
		Use:   "add <username>",
		Short: "Create a user; prints the TOTP enrollment URL (2FA is mandatory)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			pw, err := readPassword("Password: ")
			if err != nil {
				return err
			}
			var out struct {
				TOTPURL string `json:"totp_url"`
			}
			if err := c.do("POST", "/users", map[string]string{"username": args[0], "password": pw, "role": role}, &out); err != nil {
				return err
			}
			fmt.Println("User created. Add this to your authenticator app (TOTP is required to log in):")
			fmt.Println(out.TOTPURL)
			return nil
		},
	}
	add.Flags().StringVar(&role, "role", "viewer", "admin | operator | viewer")
	list := &cobra.Command{
		Use: "list", Short: "List users",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			var us []struct {
				Username    string `json:"username"`
				Role        string `json:"role"`
				TOTPEnabled bool   `json:"totp_enabled"`
			}
			if err := c.get("/users", nil, &us); err != nil {
				return err
			}
			if flagJSON {
				printJSON(us)
				return nil
			}
			w := table("USERNAME", "ROLE", "TOTP")
			for _, u := range us {
				fmt.Fprintf(w, "%s\t%s\t%v\n", u.Username, u.Role, u.TOTPEnabled)
			}
			return w.Flush()
		},
	}
	del := &cobra.Command{Use: "delete <username>", Args: cobra.ExactArgs(1), Short: "Delete a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			return c.do("DELETE", "/users/"+url.PathEscape(args[0]), nil, nil)
		}}
	unlock := &cobra.Command{Use: "unlock <username>", Args: cobra.ExactArgs(1), Short: "Clear a login lockout",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			return c.do("POST", "/users/"+url.PathEscape(args[0])+"/unlock", nil, nil)
		}}
	users.AddCommand(add, list, del, unlock)

	tokens := &cobra.Command{Use: "tokens", Short: "Manage scoped API tokens"}
	var scopes []string
	var ttl string
	create := &cobra.Command{Use: "create <name>", Args: cobra.ExactArgs(1), Short: "Create an API token (shown once)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			var out struct {
				Token string `json:"token"`
			}
			if err := c.do("POST", "/tokens", map[string]any{"name": args[0], "scopes": scopes, "ttl": ttl}, &out); err != nil {
				return err
			}
			fmt.Println(out.Token)
			return nil
		}}
	create.Flags().StringSliceVar(&scopes, "scopes", []string{"read"}, "read, ssh:write, harden:write, web:write, admin")
	create.Flags().StringVar(&ttl, "ttl", "", "expiry, e.g. 720h (default never)")
	tlist := &cobra.Command{Use: "list", Short: "List API tokens",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			var ts []map[string]any
			if err := c.get("/tokens", nil, &ts); err != nil {
				return err
			}
			if flagJSON {
				printJSON(ts)
				return nil
			}
			w := table("ID", "NAME", "SCOPES", "LAST USED")
			for _, t := range ts {
				fmt.Fprintf(w, "%v\t%v\t%v\t%v\n", t["id"], t["name"], t["scopes"], t["last_used_at"])
			}
			return w.Flush()
		}}
	revoke := &cobra.Command{Use: "revoke <id|name>", Args: cobra.ExactArgs(1), Short: "Revoke an API token",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			return c.do("DELETE", "/tokens/"+url.PathEscape(args[0]), nil, nil)
		}}
	tokens.AddCommand(create, tlist, revoke)

	var since, actor string
	auditCmd := &cobra.Command{Use: "audit", Short: "Show the audit log of every change",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			var es []struct {
				TS       string `json:"ts"`
				Actor    string `json:"actor"`
				Action   string `json:"action"`
				Target   string `json:"target"`
				SourceIP string `json:"source_ip"`
			}
			if err := c.get("/audit", url.Values{"since": {since}, "actor": {actor}}, &es); err != nil {
				return err
			}
			if flagJSON {
				printJSON(es)
				return nil
			}
			w := table("TIME", "ACTOR", "ACTION", "TARGET", "SOURCE")
			for _, e := range es {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", e.TS, e.Actor, e.Action, e.Target, e.SourceIP)
			}
			return w.Flush()
		}}
	auditCmd.Flags().StringVar(&since, "since", "", "e.g. 24h")
	auditCmd.Flags().StringVar(&actor, "actor", "", "filter by actor")
	rootCmd.AddCommand(users, tokens, auditCmd)
}
