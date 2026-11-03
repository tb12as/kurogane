package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Info describes the host firewall for hardening checks.
type Info struct {
	Firewall       string   `json:"firewall"`        // ufw | firewalld | nftables | iptables | none
	Active         bool     `json:"active"`          // filtering inbound traffic (policy or rules)
	DefaultInbound string   `json:"default_inbound"` // accept | deny | drop | reject | ""
	OpenPorts      []string `json:"open_ports"`      // "22/tcp", or service names for firewalld/ufw apps
	BanBackend     string   `json:"ban_backend"`
}

// Detect inspects the active firewall front-end. It never changes the ruleset.
func (m *Manager) Detect(ctx context.Context) Info {
	in := Info{Firewall: "none", BanBackend: m.Backend()}
	if out, err := m.ex.Run(ctx, "firewall-cmd", "--state"); err == nil && strings.TrimSpace(string(out)) == "running" {
		out, _ = m.ex.Run(ctx, "firewall-cmd", "--list-all")
		in.Firewall, in.Active = "firewalld", true
		in.DefaultInbound, in.OpenPorts = parseFirewalld(string(out))
		return in
	}
	if out, err := m.ex.Run(ctx, "ufw", "status", "verbose"); err == nil && strings.Contains(string(out), "Status: active") {
		in.Firewall, in.Active = "ufw", true
		in.DefaultInbound, in.OpenPorts = parseUFW(string(out))
		return in
	}
	if out, err := m.ex.Run(ctx, "nft", "-j", "list", "ruleset"); err == nil && len(out) > 0 {
		if pol, ports, chains, err := parseNftJSON(out); err == nil && chains > 0 {
			in.Firewall, in.DefaultInbound, in.OpenPorts = "nftables", pol, ports
			in.Active = pol != "accept" || len(ports) > 0
			return in
		}
	}
	if out, err := m.ex.Run(ctx, "iptables", "-S"); err == nil && len(out) > 0 {
		pol, ports, rules := parseIptables(string(out))
		if pol != "accept" || rules > 0 {
			in.Firewall, in.DefaultInbound, in.OpenPorts = "iptables", pol, ports
			in.Active = true
			return in
		}
		in.DefaultInbound = pol
	}
	return in
}

func uniq(s []string) []string {
	sort.Strings(s)
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// parseUFW reads `ufw status verbose`.
func parseUFW(s string) (string, []string) {
	pol := ""
	var ports []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if v, ok := strings.CutPrefix(l, "Default:"); ok {
			for _, part := range strings.Split(v, ",") {
				if strings.Contains(part, "(incoming)") {
					pol = strings.Fields(part)[0]
				}
			}
			continue
		}
		f := strings.Fields(l)
		if len(f) < 2 || f[0] == "To" || strings.HasPrefix(f[0], "--") {
			continue
		}
		for i, w := range f {
			if w == "ALLOW" && (i+1 >= len(f) || f[i+1] != "OUT") {
				ports = append(ports, f[0])
				break
			}
		}
	}
	return pol, uniq(ports)
}

// parseFirewalld reads `firewall-cmd --list-all` for the default zone.
func parseFirewalld(s string) (string, []string) {
	pol := "reject"
	var ports []string
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), ":")
		if !ok {
			continue
		}
		switch k {
		case "target":
			switch strings.TrimSpace(v) {
			case "DROP":
				pol = "drop"
			case "ACCEPT":
				pol = "accept"
			}
		case "services", "ports":
			ports = append(ports, strings.Fields(v)...)
		}
	}
	return pol, uniq(ports)
}

// parseNftJSON reads `nft -j list ruleset`: input-hook policy and simple `tcp dport N accept` rules.
func parseNftJSON(b []byte) (string, []string, int, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return "", nil, 0, err
	}
	type chainKey struct{ fam, table, name string }
	inputs := map[chainKey]bool{}
	pol, chains := "accept", 0
	var rules []json.RawMessage
	for _, it := range doc.Nftables {
		if raw, ok := it["chain"]; ok {
			var c struct{ Family, Table, Name, Hook, Policy string }
			if json.Unmarshal(raw, &c) != nil || c.Hook != "input" || c.Table == "serverkeeper" {
				continue
			}
			chains++
			inputs[chainKey{c.Family, c.Table, c.Name}] = true
			if c.Policy == "drop" {
				pol = "drop"
			}
		}
		if raw, ok := it["rule"]; ok {
			rules = append(rules, raw)
		}
	}
	var ports []string
	for _, raw := range rules {
		var r struct {
			Family, Table, Chain string
			Expr                 []map[string]json.RawMessage
		}
		if json.Unmarshal(raw, &r) != nil || !inputs[chainKey{r.Family, r.Table, r.Chain}] {
			continue
		}
		var found []string
		accept := false
		for _, e := range r.Expr {
			if _, ok := e["accept"]; ok {
				accept = true
			}
			mraw, ok := e["match"]
			if !ok {
				continue
			}
			var mt struct {
				Left struct {
					Payload struct{ Protocol, Field string } `json:"payload"`
				} `json:"left"`
				Right json.RawMessage `json:"right"`
			}
			if json.Unmarshal(mraw, &mt) != nil || mt.Left.Payload.Field != "dport" {
				continue
			}
			var n int
			var set struct {
				Set []int `json:"set"`
			}
			if json.Unmarshal(mt.Right, &n) == nil {
				found = append(found, fmt.Sprintf("%d/%s", n, mt.Left.Payload.Protocol))
			} else if json.Unmarshal(mt.Right, &set) == nil {
				for _, p := range set.Set {
					found = append(found, fmt.Sprintf("%d/%s", p, mt.Left.Payload.Protocol))
				}
			}
		}
		if accept {
			ports = append(ports, found...)
		}
	}
	return pol, uniq(ports), chains, nil
}

// parseIptables reads `iptables -S`: INPUT policy and ACCEPT rules with --dport/--dports.
func parseIptables(s string) (string, []string, int) {
	pol, rules := "accept", 0
	var ports []string
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) >= 3 && f[0] == "-P" && f[1] == "INPUT" {
			pol = strings.ToLower(f[2])
			continue
		}
		if len(f) < 2 || f[0] != "-A" || f[1] != "INPUT" || strings.Contains(l, "-j "+chain) {
			continue
		}
		rules++
		proto, accept := "tcp", false
		var ps []string
		for i := 2; i+1 < len(f); i++ {
			switch f[i] {
			case "-p":
				proto = f[i+1]
			case "--dport":
				ps = append(ps, f[i+1])
			case "--dports":
				ps = append(ps, strings.Split(f[i+1], ",")...)
			case "-j":
				accept = f[i+1] == "ACCEPT"
			}
		}
		if accept {
			for _, p := range ps {
				ports = append(ports, p+"/"+proto)
			}
		}
	}
	return pol, uniq(ports), rules
}
