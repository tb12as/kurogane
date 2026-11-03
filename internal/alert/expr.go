package alert

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/tb12as/serverman/internal/collector"
)

// Rule expressions:
//
//	expr = and { ("or" | "||") and }
//	and  = term { ("and" | "&&") term }
//	term = "(" expr ")" | metric [ "{" key "=" "\"val\"" { "," ... } "}" ] op number
//	op   = > >= < <= == !=
//
// Evaluation yields one instance per label set; a label-less side applies to every label set of the other.

// inst is the result for one label set.
type inst struct {
	labels map[string]string
	ok     bool
	v      float64
}

type node interface {
	eval(ss []collector.Sample) map[string]inst
}

type cmp struct {
	metric string
	labels map[string]string
	op     string
	val    float64
}

func (c *cmp) test(v float64) bool {
	switch c.op {
	case ">":
		return v > c.val
	case ">=":
		return v >= c.val
	case "<":
		return v < c.val
	case "<=":
		return v <= c.val
	case "==":
		return v == c.val
	}
	return v != c.val
}

func (c *cmp) eval(ss []collector.Sample) map[string]inst {
	out := map[string]inst{}
outer:
	for _, x := range ss {
		if x.Metric != c.metric {
			continue
		}
		for k, v := range c.labels {
			if x.Labels[k] != v {
				continue outer
			}
		}
		out[collector.SeriesKey("", x.Labels)] = inst{labels: x.Labels, ok: c.test(x.Value), v: x.Value}
	}
	return out
}

type bin struct {
	and  bool
	l, r node
}

func (b *bin) eval(ss []collector.Sample) map[string]inst {
	l, r := b.l.eval(ss), b.r.eval(ss)
	out := make(map[string]inst, len(l)+len(r))
	join := func(a, c map[string]inst, left bool) {
		for k, x := range a {
			if _, done := out[k]; done {
				continue
			}
			// a label-less side is already folded into each label set of the other side
			if _, both := c[""]; k == "" && !both && len(c) > 0 {
				continue
			}
			y, ok := c[k]
			if !ok {
				y, ok = c[""]
			}
			if !ok {
				if !b.and {
					out[k] = x
				}
				continue
			}
			lv, rv := x, y
			if !left {
				lv, rv = y, x
			}
			z := inst{labels: x.labels, v: lv.v}
			if len(z.labels) == 0 {
				z.labels = y.labels
			}
			if b.and {
				z.ok = x.ok && y.ok
			} else {
				z.ok = x.ok || y.ok
				if !lv.ok && rv.ok {
					z.v = rv.v
				}
			}
			out[k] = z
		}
	}
	join(l, r, true)
	join(r, l, false)
	return out
}

type parser struct {
	s string
	i int
}

func parse(s string) (node, error) {
	p := &parser{s: s}
	n, err := p.or()
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i < len(p.s) {
		return nil, p.errf("unexpected %q", p.s[p.i:])
	}
	return n, nil
}

func (p *parser) errf(f string, a ...any) error {
	return fmt.Errorf("expr %q at column %d: %s (example: disk.used_pct{mount=\"/\"} > 85 and cpu.total_pct > 50)",
		p.s, p.i+1, fmt.Sprintf(f, a...))
}

func (p *parser) ws() {
	for p.i < len(p.s) && strings.IndexByte(" \t\r\n", p.s[p.i]) >= 0 {
		p.i++
	}
}

func identChar(c byte, first bool) bool {
	if c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
		return true
	}
	return !first && (c >= '0' && c <= '9' || c == '.')
}

// kw consumes a keyword ("and") or symbol ("&&").
func (p *parser) kw(words ...string) bool {
	p.ws()
	for _, w := range words {
		if !strings.HasPrefix(p.s[p.i:], w) {
			continue
		}
		j := p.i + len(w)
		if identChar(w[0], true) && j < len(p.s) && identChar(p.s[j], false) {
			continue
		}
		p.i = j
		return true
	}
	return false
}

func (p *parser) or() (node, error) {
	l, err := p.and()
	for err == nil && p.kw("or", "||") {
		var r node
		if r, err = p.and(); err == nil {
			l = &bin{l: l, r: r}
		}
	}
	return l, err
}

func (p *parser) and() (node, error) {
	l, err := p.term()
	for err == nil && p.kw("and", "&&") {
		var r node
		if r, err = p.term(); err == nil {
			l = &bin{and: true, l: l, r: r}
		}
	}
	return l, err
}

func (p *parser) ident() string {
	p.ws()
	j := p.i
	for j < len(p.s) && identChar(p.s[j], j == p.i) {
		j++
	}
	id := p.s[p.i:j]
	p.i = j
	return id
}

func (p *parser) term() (node, error) {
	if p.kw("(") {
		n, err := p.or()
		if err != nil {
			return nil, err
		}
		if !p.kw(")") {
			return nil, p.errf("missing )")
		}
		return n, nil
	}
	c := &cmp{metric: p.ident()}
	if c.metric == "" {
		return nil, p.errf("expected metric name")
	}
	if p.kw("{") {
		c.labels = map[string]string{}
		for !p.kw("}") {
			if len(c.labels) > 0 && !p.kw(",") {
				return nil, p.errf("expected , or }")
			}
			k := p.ident()
			if k == "" || !p.kw("=") || !p.kw(`"`) {
				return nil, p.errf(`expected label="value"`)
			}
			end := strings.IndexByte(p.s[p.i:], '"')
			if end < 0 {
				return nil, p.errf("unterminated string")
			}
			c.labels[k] = p.s[p.i : p.i+end]
			p.i += end + 1
		}
	}
	for _, op := range []string{">=", "<=", "==", "!=", ">", "<"} {
		if p.kw(op) {
			c.op = op
			break
		}
	}
	if c.op == "" {
		return nil, p.errf("expected comparison operator (> >= < <= == !=)")
	}
	p.ws()
	j := p.i
	for j < len(p.s) && strings.IndexByte("0123456789.eE+-", p.s[j]) >= 0 {
		j++
	}
	v, err := strconv.ParseFloat(p.s[p.i:j], 64)
	if err != nil {
		return nil, p.errf("expected number")
	}
	c.val, p.i = v, j
	return c, nil
}
