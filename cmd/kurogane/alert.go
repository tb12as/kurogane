package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func init() {
	al := &cobra.Command{Use: "alert", Short: "Alert rules, channels, silences and history"}

	rules := &cobra.Command{Use: "rules", Short: "Manage alert rules"}
	var id, expr, dur, sev, name string
	var chans []string
	var enabled bool
	ruleFlags := func(c *cobra.Command) {
		c.Flags().StringVar(&id, "id", "", "rule id")
		c.Flags().StringVar(&expr, "expr", "", `expression, e.g. "mem.available_pct < 10"`)
		c.Flags().StringVar(&dur, "for", "", "duration the condition must hold, e.g. 5m")
		c.Flags().StringVar(&sev, "severity", "", "info | warning | critical")
		c.Flags().StringVar(&name, "name", "", "human title")
		c.Flags().StringSliceVar(&chans, "channels", nil, "channel names")
		c.Flags().BoolVar(&enabled, "enabled", true, "enable the rule")
	}
	body := func(c *cobra.Command) map[string]any {
		b := map[string]any{"id": id}
		set := func(flag, key string, v any) {
			if c.Flags().Changed(flag) {
				b[key] = v
			}
		}
		set("expr", "expr", expr)
		set("for", "for", dur)
		set("severity", "severity", sev)
		set("name", "name", name)
		set("channels", "channels", chans)
		set("enabled", "enabled", enabled)
		return b
	}
	list := &cobra.Command{Use: "list", Short: "List rules", RunE: func(cmd *cobra.Command, _ []string) error {
		c, err := newClient()
		if err != nil {
			return err
		}
		var rs []struct {
			ID       string   `json:"id"`
			Expr     string   `json:"expr"`
			For      int64    `json:"for"`
			Severity string   `json:"severity"`
			Channels []string `json:"channels"`
			Enabled  bool     `json:"enabled"`
			Builtin  bool     `json:"builtin"`
		}
		if err := c.get("/alerts/rules", nil, &rs); err != nil {
			return err
		}
		if flagJSON {
			printJSON(rs)
			return nil
		}
		w := table("ID", "EXPR", "FOR", "SEVERITY", "CHANNELS", "ENABLED", "BUILTIN")
		for _, r := range rs {
			e := r.Expr
			if e == "" {
				e = "(event)"
			}
			fmt.Fprintf(w, "%s\t%s\t%ds\t%s\t%s\t%v\t%v\n", r.ID, e, r.For/1e9, r.Severity, strings.Join(r.Channels, ","),
				r.Enabled, r.Builtin)
		}
		return w.Flush()
	}}
	add := &cobra.Command{Use: "add", Short: "Add a rule", RunE: func(cmd *cobra.Command, _ []string) error {
		c, err := newClient()
		if err != nil {
			return err
		}
		return c.do("POST", "/alerts/rules", body(cmd), nil)
	}}
	edit := &cobra.Command{Use: "edit", Short: "Edit a rule (only the flags given change)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			return c.do("PUT", "/alerts/rules/"+url.PathEscape(id), body(cmd), nil)
		}}
	del := &cobra.Command{Use: "delete <id>", Args: cobra.ExactArgs(1), Short: "Delete a custom rule",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			return c.do("DELETE", "/alerts/rules/"+url.PathEscape(args[0]), nil, nil)
		}}
	ruleFlags(add)
	ruleFlags(edit)
	rules.AddCommand(list, add, edit, del)

	channels := &cobra.Command{Use: "channels", Short: "Manage notification channels"}
	var chName, webhook, env, chatID, smtp, smtpUser, from string
	var to []string
	chAdd := &cobra.Command{Use: "add <slack|discord|telegram|email|pagerduty|webhook>", Args: cobra.ExactArgs(1),
		Short: "Add a channel (the webhook URL is stored encrypted)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			if chName == "" {
				chName = args[0]
			}
			b := map[string]any{"name": chName, "type": args[0], "webhook_url": webhook, "webhook_url_env": env,
				"chat_id": chatID, "smtp_addr": smtp, "smtp_user": smtpUser, "from": from, "to": to}
			if err := c.do("POST", "/alerts/channels", b, nil); err != nil {
				return err
			}
			fmt.Printf("channel %s added; send a test with `serverkeeper alert test %s`\n", chName, chName)
			return nil
		}}
	chAdd.Flags().StringVar(&chName, "name", "", "channel name (default: type)")
	chAdd.Flags().StringVar(&webhook, "webhook", "", "webhook URL / bot URL / routing key / SMTP password")
	chAdd.Flags().StringVar(&env, "webhook-env", "", "read the secret from this environment variable instead")
	chAdd.Flags().StringVar(&chatID, "chat-id", "", "telegram chat id")
	chAdd.Flags().StringVar(&smtp, "smtp", "", "email: SMTP host:port")
	chAdd.Flags().StringVar(&smtpUser, "smtp-user", "", "email: SMTP user")
	chAdd.Flags().StringVar(&from, "from", "", "email: sender")
	chAdd.Flags().StringSliceVar(&to, "to", nil, "email: recipients")
	chList := &cobra.Command{Use: "list", Short: "List channels", RunE: func(cmd *cobra.Command, _ []string) error {
		c, err := newClient()
		if err != nil {
			return err
		}
		var cs []map[string]any
		if err := c.get("/alerts/channels", nil, &cs); err != nil {
			return err
		}
		if flagJSON {
			printJSON(cs)
			return nil
		}
		w := table("NAME", "TYPE", "SOURCE", "READY")
		for _, x := range cs {
			fmt.Fprintf(w, "%v\t%v\t%v\t%v\n", x["name"], x["type"], x["source"], x["ready"])
		}
		return w.Flush()
	}}
	chDel := &cobra.Command{Use: "delete <name>", Args: cobra.ExactArgs(1), Short: "Delete a channel",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			return c.do("DELETE", "/alerts/channels/"+url.PathEscape(args[0]), nil, nil)
		}}
	channels.AddCommand(chAdd, chList, chDel)

	test := &cobra.Command{Use: "test <channel>", Args: cobra.ExactArgs(1), Short: "Send a test message",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			if err := c.do("POST", "/alerts/channels/"+url.PathEscape(args[0])+"/test", nil, nil); err != nil {
				return err
			}
			fmt.Println("test message sent to", args[0])
			return nil
		}}

	var sRule, sServer, sTag, sFor, sReason string
	silence := &cobra.Command{Use: "silence", Short: "Silence alerts for a maintenance window",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			var out struct {
				ID     string `json:"id"`
				EndsAt string `json:"ends_at"`
			}
			b := map[string]string{"rule": sRule, "server": sServer, "tag": sTag, "for": sFor, "reason": sReason}
			if err := c.do("POST", "/alerts/silences", b, &out); err != nil {
				return err
			}
			fmt.Printf("silence %s active until %s\n", out.ID, out.EndsAt)
			return nil
		}}
	silence.Flags().StringVar(&sRule, "rule", "", "rule id")
	silence.Flags().StringVar(&sServer, "server", "", "server name")
	silence.Flags().StringVar(&sTag, "tag", "", "server or rule tag")
	silence.Flags().StringVar(&sFor, "for", "1h", "duration")
	silence.Flags().StringVar(&sReason, "reason", "", "why")
	silences := &cobra.Command{Use: "silences", Short: "List or delete silences"}
	silences.AddCommand(&cobra.Command{Use: "list", RunE: func(cmd *cobra.Command, _ []string) error {
		c, err := newClient()
		if err != nil {
			return err
		}
		var ss []map[string]any
		if err := c.get("/alerts/silences", nil, &ss); err != nil {
			return err
		}
		printJSON(ss)
		return nil
	}}, &cobra.Command{Use: "delete <id>", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		c, err := newClient()
		if err != nil {
			return err
		}
		return c.do("DELETE", "/alerts/silences/"+url.PathEscape(args[0]), nil, nil)
	}})

	var eState, eSince, eExport string
	events := &cobra.Command{Use: "events", Short: "Alert history (AL-7)", RunE: func(cmd *cobra.Command, _ []string) error {
		c, err := newClient()
		if err != nil {
			return err
		}
		q := url.Values{"state": {eState}, "since": {eSince}}
		if eExport != "" {
			q.Set("format", eExport)
			b, err := c.raw("GET", "/alerts/events/export?"+q.Encode(), nil)
			if err != nil {
				return err
			}
			_, err = os.Stdout.Write(b)
			return err
		}
		var es []struct {
			ID        string `json:"id"`
			RuleID    string `json:"rule_id"`
			Severity  string `json:"severity"`
			State     string `json:"state"`
			Summary   string `json:"summary"`
			StartedAt string `json:"started_at"`
		}
		if err := c.get("/alerts/events", q, &es); err != nil {
			return err
		}
		if flagJSON {
			printJSON(es)
			return nil
		}
		w := table("ID", "RULE", "SEVERITY", "STATE", "STARTED", "SUMMARY")
		for _, e := range es {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", e.ID, e.RuleID, e.Severity, e.State, e.StartedAt, e.Summary)
		}
		return w.Flush()
	}}
	events.Flags().StringVar(&eState, "state", "", "open | firing | acknowledged | resolved")
	events.Flags().StringVar(&eSince, "since", "", "e.g. 7d")
	events.Flags().StringVar(&eExport, "export", "", "csv | json (writes to stdout)")
	ack := &cobra.Command{Use: "ack <id>", Args: cobra.ExactArgs(1), Short: "Acknowledge a firing alert",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			return c.do("POST", "/alerts/events/"+url.PathEscape(args[0])+"/ack", nil, nil)
		}}
	noise := &cobra.Command{Use: "noise <id>", Args: cobra.ExactArgs(1), Short: "Mark an alert as noise",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}
			return c.do("POST", "/alerts/events/"+url.PathEscape(args[0])+"/noise", map[string]bool{"noise": true}, nil)
		}}

	al.AddCommand(rules, channels, test, silence, silences, events, ack, noise)
	rootCmd.AddCommand(al)
}
