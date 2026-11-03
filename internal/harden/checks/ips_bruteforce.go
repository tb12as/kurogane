package checks

import (
	"context"
	"fmt"

	"gopkg.in/yaml.v3"
)

type ipsCheck struct{ *fnCheck }

func bruteforceOn(ctx context.Context, e *Env) (bool, string) {
	if e.Bruteforce != nil && e.Bruteforce() {
		return true, "built-in SSH brute-force ban (or fail2ban) active"
	}
	if active(ctx, e, "fail2ban") {
		return true, "fail2ban active"
	}
	return false, "neither fail2ban nor the built-in SSH ban is active"
}

// setBruteforce returns cfg with ssh.bruteforce.enabled set, keeping the rest of the document (and comments).
func setBruteforce(cfg string, on bool) (string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(cfg), &doc); err != nil {
		return "", fmt.Errorf("parse config: %w", err)
	}
	if doc.Kind == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
	}
	n := doc.Content[0]
	for _, k := range []string{"ssh", "bruteforce"} {
		n = mapChild(n, k, yaml.MappingNode)
	}
	v := mapChild(n, "enabled", yaml.ScalarNode)
	v.Tag, v.Value = "!!bool", fmt.Sprint(on)
	out, err := yaml.Marshal(&doc)
	return string(out), err
}

func mapChild(n *yaml.Node, key string, kind yaml.Kind) *yaml.Node {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	c := &yaml.Node{Kind: kind}
	n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: key}, c)
	return c
}

// AfterRevert re-reads the restored config so the in-memory flag matches the file.
func (c ipsCheck) AfterRevert(context.Context) error {
	if c.e.SetBruteforce == nil {
		return nil
	}
	var f struct {
		SSH struct {
			Bruteforce struct {
				Enabled bool `yaml:"enabled"`
			} `yaml:"bruteforce"`
		} `yaml:"ssh"`
	}
	s, _ := readFile(c.e.ConfigPath)
	err := yaml.Unmarshal([]byte(s), &f)
	c.e.SetBruteforce(f.SSH.Bruteforce.Enabled)
	return err
}

func (c ipsCheck) Fix(ctx context.Context, dryRun bool) (Diff, error) {
	d, err := c.fnCheck.Fix(ctx, dryRun)
	if err == nil && !dryRun && !d.Empty() && c.e.SetBruteforce != nil {
		// in-memory flag so the running SSH manager picks it up without an agent restart
		c.e.SetBruteforce(true)
	}
	return d, err
}

func init() {
	register(func(e *Env) Check {
		return ipsCheck{fn(Meta{ID: "IPS-BRUTEFORCE", Title: "SSH brute-force protection active",
			Category: "intrusion", Severity: High,
			Rationale: "Banning sources of repeated failed logins stops password guessing and cuts log noise.",
			Remediation: "Enable the built-in ban (`ssh.bruteforce.enabled: true` in config.yaml) or run fail2ban " +
				"with an sshd jail."}, e,
			func(ctx context.Context, c *fnCheck) Result {
				if ok, ev := bruteforceOn(ctx, c.e); ok {
					return c.res(Pass, ev)
				} else {
					return c.res(Fail, ev)
				}
			},
			func(ctx context.Context, c *fnCheck) (Diff, error) {
				if ok, _ := bruteforceOn(ctx, c.e); ok {
					return Diff{}, nil
				}
				if c.e.ConfigPath == "" {
					return Diff{}, fmt.Errorf("agent config path unknown: set ssh.bruteforce.enabled: true manually")
				}
				old, _ := readFile(c.e.ConfigPath)
				nw, err := setBruteforce(old, true)
				if err != nil {
					return Diff{}, err
				}
				return Diff{Files: []FileEdit{{Path: c.e.ConfigPath, New: nw, Mode: 0o600}}}, nil
			})}
	})
}
