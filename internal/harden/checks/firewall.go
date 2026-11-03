package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// fwState is a read-only probe of the active firewall (ufw > firewalld > nftables > iptables).
type fwState struct {
	Backend     string
	Active      bool
	DefaultDeny bool
	Target      string // firewalld zone target / ufw incoming default
	Evidence    string
}

var ufwDefault = regexp.MustCompile(`Default:\s*(\w+)\s*\(incoming\)`)

func firewall(ctx context.Context, e *Env) (fwState, error) {
	return memo(ctx, "fw", func() (fwState, error) {
		var errs []error
		if hasBin("ufw") {
			out, err := e.Ex.Run(ctx, "ufw", "status", "verbose")
			s := string(out)
			if err != nil {
				errs = append(errs, err)
			} else if strings.Contains(s, "Status: active") {
				st := fwState{Backend: "ufw", Active: true, Evidence: "ufw active"}
				if m := ufwDefault.FindStringSubmatch(s); m != nil {
					st.Target = m[1]
					st.DefaultDeny = m[1] == "deny" || m[1] == "reject"
					st.Evidence += ", default " + m[1] + " (incoming)"
				}
				return st, nil
			}
		}
		if hasBin("firewall-cmd") {
			out, _ := e.Ex.Run(ctx, "firewall-cmd", "--state")
			if strings.TrimSpace(string(out)) == "running" {
				st := fwState{Backend: "firewalld", Active: true, Evidence: "firewalld running"}
				all, err := e.Ex.Run(ctx, "firewall-cmd", "--list-all")
				if err != nil {
					errs = append(errs, err)
				}
				for _, l := range strings.Split(string(all), "\n") {
					if k, v, ok := strings.Cut(strings.TrimSpace(l), ":"); ok && k == "target" {
						st.Target = strings.TrimSpace(v)
					}
				}
				st.DefaultDeny = st.Target != "ACCEPT"
				st.Evidence += ", zone target " + st.Target
				return st, nil
			}
		}
		if hasBin("nft") {
			out, err := e.Ex.Run(ctx, "nft", "-j", "list", "ruleset")
			if err != nil {
				errs = append(errs, err)
			} else if st, ok := parseNft(out); ok {
				return st, nil
			}
		}
		if hasBin("iptables") {
			out, err := e.Ex.Run(ctx, "iptables", "-S", "INPUT")
			if err != nil {
				errs = append(errs, err)
			} else {
				s := string(out)
				deny := strings.Contains(s, "-P INPUT DROP") || strings.Contains(s, "-P INPUT REJECT")
				if deny || strings.Contains(s, "-A INPUT") {
					return fwState{Backend: "iptables", Active: true, DefaultDeny: deny,
						Evidence: "iptables INPUT rules present, default deny " + fmt.Sprint(deny)}, nil
				}
			}
		}
		if len(errs) > 0 {
			return fwState{}, fmt.Errorf("cannot query the firewall (run as root): %w", errors.Join(errs...))
		}
		return fwState{Evidence: "no active firewall (ufw, firewalld, nftables or iptables input rules)"}, nil
	})
}

// parseNft inspects `nft -j list ruleset` for input-hook chains.
func parseNft(b []byte) (fwState, bool) {
	var rs struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(b, &rs) != nil {
		return fwState{}, false
	}
	type ch struct{ Family, Table, Name, Hook, Policy string }
	input := map[string]bool{}
	deny, rules := false, 0
	for _, o := range rs.Nftables {
		if raw, ok := o["chain"]; ok {
			var c ch
			_ = json.Unmarshal(raw, &c)
			if c.Hook == "input" {
				input[c.Family+"/"+c.Table+"/"+c.Name] = true
				deny = deny || c.Policy == "drop"
			}
		}
		if raw, ok := o["rule"]; ok {
			var r struct{ Family, Table, Chain string }
			_ = json.Unmarshal(raw, &r)
			if input[r.Family+"/"+r.Table+"/"+r.Chain] {
				rules++
			}
		}
	}
	if !deny && rules == 0 {
		return fwState{}, false
	}
	return fwState{Backend: "nftables", Active: true, DefaultDeny: deny,
		Evidence: fmt.Sprintf("nftables input chains: %d rules, policy drop %v", rules, deny)}, true
}

const nftFile = "/etc/serverkeeper/nftables-harden.nft"

// fwPlan opens every listening port plus SSH, then enables (or default-denies) the firewall.
func fwPlan(ctx context.Context, e *Env, deny bool) (Diff, error) {
	st, err := firewall(ctx, e)
	if err != nil {
		return Diff{}, err
	}
	ports := keepOpen(ctx, e)
	d := Diff{Confirm: true, Note: "keeps open (listening now + SSH): " + strings.Join(ports, ", ")}
	switch {
	case hasBin("ufw"):
		for _, p := range ports {
			d.Cmds = append(d.Cmds, cmd("ufw", "allow", p))
		}
		if deny {
			d.Cmds = append(d.Cmds, cmd("ufw", "default", "deny", "incoming"))
			if st.Backend == "ufw" && st.Target != "" {
				d.Undo = append(d.Undo, cmd("ufw", "default", st.Target, "incoming"))
			} else {
				d.Undo = append(d.Undo, cmd("ufw", "disable"))
			}
		}
		if !st.Active || st.Backend != "ufw" {
			d.Cmds = append(d.Cmds, cmd("ufw", "--force", "enable"))
			if !deny {
				d.Undo = append(d.Undo, cmd("ufw", "disable"))
			}
		}
	case hasBin("firewall-cmd"):
		if st.Backend != "firewalld" {
			d.Cmds = append(d.Cmds, cmd("systemctl", "enable", "firewalld"), cmd("systemctl", "start", "firewalld"))
			d.Undo = append(d.Undo, cmd("systemctl", "stop", "firewalld"), cmd("systemctl", "disable", "firewalld"))
		}
		for _, p := range ports {
			d.Cmds = append(d.Cmds, cmd("firewall-cmd", "--permanent", "--add-port="+p))
		}
		if deny && st.Backend == "firewalld" && !st.DefaultDeny {
			d.Cmds = append(d.Cmds, cmd("firewall-cmd", "--permanent", "--set-target=default"))
			d.Undo = append([][]string{cmd("firewall-cmd", "--permanent", "--set-target="+st.Target),
				cmd("firewall-cmd", "--reload")}, d.Undo...)
		}
		d.Cmds = append(d.Cmds, cmd("firewall-cmd", "--reload"))
	case hasBin("nft"):
		d.Files = append(d.Files, FileEdit{Path: nftFile, New: nftRuleset(ports), Mode: 0o600})
		conf, _ := readFile("/etc/nftables.conf")
		inc := `include "` + nftFile + `"`
		if !strings.Contains(conf, inc) {
			if conf != "" && !strings.HasSuffix(conf, "\n") {
				conf += "\n"
			}
			d.Files = append(d.Files, FileEdit{Path: "/etc/nftables.conf", New: conf + inc + "\n", Mode: 0o755})
		}
		d.Cmds = append(d.Cmds, cmd("nft", "-f", nftFile), cmd("systemctl", "enable", "nftables"))
		d.Undo = append(d.Undo, cmd("nft", "delete", "table", "inet", "serverkeeper"))
	default:
		return Diff{}, errors.New("no firewall tool found: install ufw (Debian/Ubuntu) or firewalld (RHEL), then retry")
	}
	return d, nil
}

func nftRuleset(ports []string) string {
	var tcp, udp []string
	for _, p := range ports {
		n, proto, _ := strings.Cut(p, "/")
		if proto == "udp" {
			udp = append(udp, n)
		} else {
			tcp = append(tcp, n)
		}
	}
	var b strings.Builder
	b.WriteString("# managed by serverkeeper harden: default-deny inbound, keeps listening ports and SSH open\n")
	b.WriteString("table inet serverkeeper\ndelete table inet serverkeeper\ntable inet serverkeeper {\n")
	b.WriteString("\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n")
	b.WriteString("\t\tiif \"lo\" accept\n\t\tct state established,related accept\n")
	b.WriteString("\t\tmeta l4proto { icmp, ipv6-icmp } accept\n")
	if len(tcp) > 0 {
		b.WriteString("\t\ttcp dport { " + strings.Join(tcp, ", ") + " } accept\n")
	}
	if len(udp) > 0 {
		b.WriteString("\t\tudp dport { " + strings.Join(udp, ", ") + " } accept\n")
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}
