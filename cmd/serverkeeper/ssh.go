package main

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func confirmPrompt(q string) bool {
	fmt.Print(q + " [y/N]: ")
	s, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(s), "y")
}

func init() {
	sshCmd := &cobra.Command{Use: "ssh", Short: "SSH keys, sshd_config, sessions and logins"}

	keys := &cobra.Command{Use: "keys", Short: "Authorized key inventory"}
	var kUser string
	kList := &cobra.Command{Use: "list", Short: "List authorized keys for every user", RunE: func(cmd *cobra.Command, _ []string) error {
		c, err := newClient()
		if err != nil {
			return err
		}
		var ks []struct {
			User        string   `json:"user"`
			Fingerprint string   `json:"fingerprint"`
			Type        string   `json:"type"`
			Bits        int      `json:"bits"`
			Label       string   `json:"label"`
			Comment     string   `json:"comment"`
			ExpiresAt   string   `json:"expires_at"`
			LastUsedAt  string   `json:"last_used_at"`
			Flags       []string `json:"flags"`
		}
		if err := c.get("/ssh/keys", url.Values{"user": {kUser}}, &ks); err != nil {
			return err
		}
		if flagJSON {
			printJSON(ks)
			return nil
		}
		w := table("USER", "FINGERPRINT", "TYPE", "LABEL", "EXPIRES", "LAST USED", "FLAGS")
		short := func(s string) string {
			if strings.HasPrefix(s, "0001-") || s == "" {
				return "-"
			}
			return s[:10]
		}
		for _, k := range ks {
			label := k.Label
			if label == "" {
				label = k.Comment
			}
			fmt.Fprintf(w, "%s\t%s\t%s-%d\t%s\t%s\t%s\t%s\n", k.User, k.Fingerprint, k.Type, k.Bits, label,
				short(k.ExpiresAt), short(k.LastUsedAt), strings.Join(k.Flags, ","))
		}
		return w.Flush()
	}}
	kList.Flags().StringVar(&kUser, "user", "", "only this user")

	var aUser, aFile, aLabel, aExpires, aGitHub, aGitLab string
	kAdd := &cobra.Command{Use: "add", Short: "Add a key from a file, GitHub or GitLab", RunE: func(cmd *cobra.Command, _ []string) error {
		c, err := newClient()
		if err != nil {
			return err
		}
		b := map[string]string{"user": aUser, "label": aLabel, "expires_at": aExpires, "github": aGitHub, "gitlab": aGitLab}
		if aFile != "" {
			pk, err := os.ReadFile(aFile)
			if err != nil {
				return err
			}
			b["public_key"] = string(pk)
		}
		var out any
		if err := c.do("POST", "/ssh/keys", b, &out); err != nil {
			return err
		}
		printJSON(out)
		return nil
	}}
	kAdd.Flags().StringVar(&aUser, "user", "", "login user (required)")
	kAdd.Flags().StringVar(&aFile, "file", "", "public key file, e.g. id_ed25519.pub")
	kAdd.Flags().StringVar(&aLabel, "label", "", `owner label, e.g. "budi laptop"`)
	kAdd.Flags().StringVar(&aExpires, "expires", "", "expiry date YYYY-MM-DD (key is removed automatically)")
	kAdd.Flags().StringVar(&aGitHub, "github", "", "import keys of a GitHub user")
	kAdd.Flags().StringVar(&aGitLab, "gitlab", "", "import keys of a GitLab user")
	_ = kAdd.MarkFlagRequired("user")

	var rUser string
	var rAll bool
	kRevoke := &cobra.Command{Use: "revoke <fingerprint>", Args: cobra.ExactArgs(1), Short: "Remove a key (all users, or --user)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			if rAll {
				// fleet-wide revoke runs on the central server API (--api https://central:9443)
				var out any
				if err := c.do("POST", "/fleet/keys/revoke", map[string]string{"fingerprint": args[0]}, &out); err != nil {
					return err
				}
				printJSON(out)
				return nil
			}
			var out struct {
				Removed int `json:"removed"`
			}
			if err := c.do("DELETE", "/ssh/keys/"+url.PathEscape(args[0])+"?"+url.Values{"user": {rUser}}.Encode(), nil, &out); err != nil {
				return err
			}
			fmt.Printf("removed %d key line(s)\n", out.Removed)
			return nil
		}}
	kRevoke.Flags().StringVar(&rUser, "user", "", "only from this user")
	kRevoke.Flags().BoolVar(&rAll, "all-servers", false, "revoke on every server (central server API)")
	keys.AddCommand(kList, kAdd, kRevoke)

	cfgCmd := &cobra.Command{Use: "config", Short: "sshd_config: current vs recommended, safe changes"}
	cfgShow := &cobra.Command{Use: "show", Short: "Current vs recommended settings", RunE: func(cmd *cobra.Command, _ []string) error {
		c, err := newClient()
		if err != nil {
			return err
		}
		var out struct {
			Settings []struct {
				Name        string `json:"name"`
				Current     string `json:"current"`
				Recommended string `json:"recommended"`
				OK          bool   `json:"ok"`
				Notes       string `json:"notes"`
			} `json:"settings"`
			Pending *struct {
				ID       string `json:"id"`
				Setting  string `json:"setting"`
				Deadline string `json:"deadline"`
			} `json:"pending"`
		}
		if err := c.get("/ssh/config", nil, &out); err != nil {
			return err
		}
		if flagJSON {
			printJSON(out)
			return nil
		}
		w := table("SETTING", "CURRENT", "RECOMMENDED", "STATUS", "NOTES")
		for _, s := range out.Settings {
			st := "ok"
			if !s.OK {
				st = "CHANGE"
			}
			cur := s.Current
			if len(cur) > 40 {
				cur = cur[:37] + "..."
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.Name, cur, s.Recommended, st, s.Notes)
		}
		w.Flush()
		if out.Pending != nil {
			fmt.Printf("\nPending change %s (%s) rolls back at %s unless confirmed.\n", out.Pending.ID, out.Pending.Setting,
				out.Pending.Deadline)
		}
		return nil
	}}
	var rollback string
	var yes bool
	cfgSet := &cobra.Command{Use: "set <Setting> <value> [<Setting> <value>...]", Short: "Safe-apply sshd settings with auto rollback",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 || len(args)%2 != 0 {
				return fmt.Errorf("give setting/value pairs, e.g. PasswordAuthentication no")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			set := map[string]string{}
			for i := 0; i < len(args); i += 2 {
				set[args[i]] = args[i+1]
			}
			var plan struct {
				Diff   string   `json:"diff"`
				Mode   string   `json:"mode"`
				Impact []string `json:"impact"`
			}
			if err := c.do("PATCH", "/ssh/config", map[string]any{"set": set, "dry_run": true}, &plan); err != nil {
				return err
			}
			fmt.Printf("Dry run (%s):\n%s\nImpact:\n", plan.Mode, plan.Diff)
			for _, l := range plan.Impact {
				fmt.Println("  - " + l)
			}
			if !yes && !confirmPrompt("Apply with a "+rollback+" rollback timer?") {
				return fmt.Errorf("aborted, nothing changed")
			}
			var ch struct {
				ID       string `json:"id"`
				Deadline string `json:"deadline"`
			}
			body := map[string]any{"set": set, "rollback": rollback, "ssh_connection": os.Getenv("SSH_CONNECTION")}
			if err := c.do("PATCH", "/ssh/config", body, &ch); err != nil {
				return err
			}
			fmt.Printf("\nApplied change %s; sshd reloaded.\nNOW open a NEW SSH session and run `serverkeeper ssh confirm` "+
				"before %s, otherwise the previous config is restored automatically.\n", ch.ID, ch.Deadline)
			return nil
		}}
	cfgSet.Flags().StringVar(&rollback, "rollback", "120s", "rollback timeout")
	cfgSet.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	cfgCmd.AddCommand(cfgShow, cfgSet)

	confirm := &cobra.Command{Use: "confirm", Short: "Confirm the pending sshd change (run from a NEW ssh session)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			var ch struct {
				ID      string `json:"id"`
				Setting string `json:"setting"`
			}
			if err := c.do("POST", "/ssh/config/confirm", map[string]string{"ssh_connection": os.Getenv("SSH_CONNECTION")}, &ch); err != nil {
				return err
			}
			fmt.Printf("change %s (%s) confirmed\n", ch.ID, ch.Setting)
			return nil
		}}

	var kill int
	sessions := &cobra.Command{Use: "sessions", Short: "Active sessions (--kill <pid> ends one)", RunE: func(cmd *cobra.Command, _ []string) error {
		c, err := newClient()
		if err != nil {
			return err
		}
		if kill > 0 {
			return c.do("DELETE", fmt.Sprintf("/ssh/sessions/%d", kill), nil, nil)
		}
		var ss []struct {
			User    string `json:"user"`
			TTY     string `json:"tty"`
			From    string `json:"from"`
			Started string `json:"started"`
			PID     int    `json:"pid"`
		}
		if err := c.get("/ssh/sessions", nil, &ss); err != nil {
			return err
		}
		if flagJSON {
			printJSON(ss)
			return nil
		}
		w := table("PID", "USER", "TTY", "FROM", "STARTED")
		for _, s := range ss {
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", s.PID, s.User, s.TTY, s.From, s.Started)
		}
		return w.Flush()
	}}
	sessions.Flags().IntVar(&kill, "kill", 0, "pid of the session to terminate")

	var since string
	logins := &cobra.Command{Use: "logins", Short: "Login history and top failing IPs/users", RunE: func(cmd *cobra.Command, _ []string) error {
		c, err := newClient()
		if err != nil {
			return err
		}
		var s struct {
			Success int `json:"success"`
			Failed  int `json:"failed"`
			TopIPs  []struct {
				Key   string
				Count int
			} `json:"top_failing_ips"`
			TopUsers []struct {
				Key   string
				Count int
			} `json:"top_failing_users"`
			Logins []map[string]any `json:"logins"`
		}
		if err := c.get("/ssh/logins", url.Values{"since": {since}}, &s); err != nil {
			return err
		}
		if flagJSON {
			printJSON(s)
			return nil
		}
		fmt.Printf("successful %d, failed %d (last %s)\n\nTop failing IPs:\n", s.Success, s.Failed, since)
		for _, x := range s.TopIPs {
			fmt.Printf("  %-40s %d\n", x.Key, x.Count)
		}
		fmt.Println("Top failing users:")
		for _, x := range s.TopUsers {
			fmt.Printf("  %-40s %d\n", x.Key, x.Count)
		}
		return nil
	}}
	logins.Flags().StringVar(&since, "since", "24h", "window")

	var unban string
	bans := &cobra.Command{Use: "bans", Short: "Brute-force bans (--unban ip)", RunE: func(cmd *cobra.Command, _ []string) error {
		c, err := newClient()
		if err != nil {
			return err
		}
		if unban != "" {
			return c.do("DELETE", "/ssh/bans/"+url.PathEscape(unban), nil, nil)
		}
		var out any
		if err := c.get("/ssh/bans", nil, &out); err != nil {
			return err
		}
		printJSON(out)
		return nil
	}}
	bans.Flags().StringVar(&unban, "unban", "", "IP to unban")

	ca := &cobra.Command{Use: "ca", Short: "SSH certificate authority (short-lived certs)"}
	ca.AddCommand(&cobra.Command{Use: "init", Short: "Create the CA and trust it in sshd (safe-apply)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			var out map[string]string
			if err := c.do("POST", "/ssh/ca/init", nil, &out); err != nil {
				return err
			}
			fmt.Println(out["ca_public_key"])
			fmt.Println("sshd now trusts this CA; confirm the change with `serverkeeper ssh confirm` from a new session")
			return nil
		}})
	var pubFile, ttl string
	var principals []string
	sign := &cobra.Command{Use: "sign", Short: "Sign a user key; prints the certificate", RunE: func(cmd *cobra.Command, _ []string) error {
		c, err := newClient()
		if err != nil {
			return err
		}
		pk, err := os.ReadFile(pubFile)
		if err != nil {
			return err
		}
		var out map[string]string
		if err := c.do("POST", "/ssh/ca/sign", map[string]any{"public_key": string(pk), "principals": principals, "ttl": ttl}, &out); err != nil {
			return err
		}
		fmt.Println(out["certificate"])
		return nil
	}}
	sign.Flags().StringVar(&pubFile, "pubkey", "", "public key file")
	sign.Flags().StringSliceVar(&principals, "principals", nil, "login users")
	sign.Flags().StringVar(&ttl, "ttl", "8h", "validity")
	ca.AddCommand(sign)

	sshCmd.AddCommand(keys, cfgCmd, confirm, sessions, logins, bans, ca)
	rootCmd.AddCommand(sshCmd)
}
