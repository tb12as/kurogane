package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/serverkeeper/serverkeeper/internal/executor"
	"gopkg.in/yaml.v3"
)

// PackCheck is one entry of a YAML check pack (HD-8). Example:
//
//	checks:
//	  - id: CUSTOM-IP-FORWARD
//	    type: sysctl            # file_mode | file_contains | file_not_contains | sysctl |
//	    severity: medium        # service_active | service_inactive | command_output
//	    title: IP forwarding off
//	    rationale: ...
//	    remediation: ...
//	    key: net.ipv4.ip_forward
//	    value: "0"
//	    fix: true               # sysctl and file_mode only
type PackCheck struct {
	Meta    `yaml:",inline"`
	Type    string   `yaml:"type"`
	Path    string   `yaml:"path"`
	Mode    string   `yaml:"mode"`    // file_mode: max permitted bits, octal
	Pattern string   `yaml:"pattern"` // file_contains / file_not_contains / command_output regex
	Key     string   `yaml:"key"`
	Value   string   `yaml:"value"`
	Unit    string   `yaml:"unit"`
	Command []string `yaml:"command"` // command_output: allowlisted executor command + args
	Fix     bool     `yaml:"fix"`
}

// LoadPacks reads every *.yaml / *.yml in dirs; ids must not collide with existing ones.
func LoadPacks(e *Env, dirs []string, existing map[string]bool) ([]Check, error) {
	var out []Check
	for _, dir := range dirs {
		files, _ := filepath.Glob(filepath.Join(dir, "*.y*ml"))
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				return out, err
			}
			var p struct {
				Checks []PackCheck `yaml:"checks"`
			}
			if err := yaml.Unmarshal(b, &p); err != nil {
				return out, fmt.Errorf("%s: %w", f, err)
			}
			for i, pc := range p.Checks {
				c, err := pc.build(e)
				if err == nil && existing[pc.ID] {
					err = fmt.Errorf("duplicate check id %q", pc.ID)
				}
				if err != nil {
					return out, fmt.Errorf("%s: check %d (%s): %w", f, i+1, pc.ID, err)
				}
				existing[pc.ID] = true
				out = append(out, c)
			}
		}
	}
	return out, nil
}

func (p PackCheck) build(e *Env) (Check, error) {
	m := p.Meta
	if m.ID == "" || m.Title == "" {
		return nil, fmt.Errorf("id and title are required")
	}
	if Rank(m.Severity) == 0 {
		return nil, fmt.Errorf("severity must be critical, high, medium or low")
	}
	if m.Category == "" {
		m.Category = "custom"
	}
	m.AutoFix = FixReport
	if p.Fix && (p.Type == "sysctl" || p.Type == "file_mode") {
		m.AutoFix = FixYes
	}
	var re *regexp.Regexp
	if p.Pattern != "" {
		r, err := regexp.Compile(p.Pattern)
		if err != nil {
			return nil, fmt.Errorf("pattern: %w", err)
		}
		re = r
	}
	need := func(ok bool, what string) error {
		if !ok {
			return fmt.Errorf("type %s needs %s", p.Type, what)
		}
		return nil
	}
	switch p.Type {
	case "sysctl":
		if err := need(p.Key != "" && p.Value != "", "key and value"); err != nil {
			return nil, err
		}
		return &sysctlCheck{base: base{m, e}, want: []kv{{p.Key, p.Value}}, fixable: p.Fix}, nil
	case "file_mode":
		mode, err := strconv.ParseUint(p.Mode, 8, 32)
		if err := need(p.Path != "" && err == nil, "path and an octal mode"); err != nil {
			return nil, err
		}
		return &fileModeCheck{base: base{m, e}, path: p.Path, max: os.FileMode(mode), fixable: p.Fix}, nil
	case "file_contains", "file_not_contains":
		if err := need(p.Path != "" && re != nil, "path and pattern"); err != nil {
			return nil, err
		}
		must := p.Type == "file_contains"
		return fn(m, e, func(_ context.Context, c *fnCheck) Result {
			s, ok := readFile(p.Path)
			hit := ok && re.MatchString(s)
			if hit == must {
				return c.res(Pass, fmt.Sprintf("%s: pattern %q matched %v", p.Path, p.Pattern, hit))
			}
			if !ok {
				return c.res(Fail, p.Path+" not found")
			}
			return c.res(Fail, fmt.Sprintf("%s: pattern %q matched %v (want %v)", p.Path, p.Pattern, hit, must))
		}, nil), nil
	case "service_active", "service_inactive":
		if err := need(p.Unit != "", "unit"); err != nil {
			return nil, err
		}
		want := p.Type == "service_active"
		return fn(m, e, func(ctx context.Context, c *fnCheck) Result {
			st := unitStates(ctx, c.e, p.Unit)[p.Unit]
			if (st == "active") == want {
				return c.res(Pass, p.Unit+" "+st)
			}
			return c.res(Fail, p.Unit+" "+st)
		}, nil), nil
	case "command_output":
		if err := need(len(p.Command) > 0 && re != nil, "command and pattern"); err != nil {
			return nil, err
		}
		if err := executor.Allowed(p.Command[0], p.Command[1:]); err != nil {
			return nil, err
		}
		return fn(m, e, func(ctx context.Context, c *fnCheck) Result {
			out, err := c.e.Ex.Run(ctx, p.Command[0], p.Command[1:]...)
			s := strings.TrimSpace(string(out))
			if re.MatchString(s) {
				return c.res(Pass, "output matches "+p.Pattern)
			}
			if err != nil {
				return c.res(Fail, err.Error())
			}
			return c.res(Fail, "output does not match "+p.Pattern+": "+short(strings.Split(s, "\n"), 5))
		}, nil), nil
	}
	return nil, fmt.Errorf("unknown type %q", p.Type)
}
