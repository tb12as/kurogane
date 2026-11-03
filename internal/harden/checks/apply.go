package checks

import (
	"context"
	"fmt"
	"strings"
)

// Apply performs a planned diff: files, modes, sshd settings (safe-apply), then commands.
func Apply(ctx context.Context, e *Env, d Diff) error {
	for _, f := range d.Files {
		var err error
		if f.Remove {
			err = e.Ex.Remove(f.Path)
		} else {
			mode := f.Mode
			if mode == 0 {
				mode = 0o644
			}
			err = e.Ex.WriteFile(f.Path, []byte(f.New), mode)
		}
		if err != nil {
			return fmt.Errorf("write %s: %w", f.Path, err)
		}
	}
	for _, m := range d.Modes {
		if err := e.Ex.Chmod(m.Path, m.New); err != nil {
			return fmt.Errorf("chmod %s: %w", m.Path, err)
		}
	}
	if len(d.SSH) > 0 {
		if e.SSHApply == nil {
			return fmt.Errorf("SSH manager unavailable: cannot safe-apply %v", d.SSH)
		}
		if err := e.SSHApply(ctx, d.SSH); err != nil {
			return fmt.Errorf("ssh safe-apply: %w", err)
		}
	}
	return RunCmds(ctx, e, d.Cmds)
}

// RunCmds runs commands in order, stopping at the first failure.
func RunCmds(ctx context.Context, e *Env, cmds [][]string) error {
	for _, c := range cmds {
		if _, err := e.Ex.Run(ctx, c[0], c[1:]...); err != nil {
			return err
		}
	}
	return nil
}

// Render produces the human-readable dry-run diff.
func (d Diff) Render() string {
	var b strings.Builder
	for _, f := range d.Files {
		old, _ := readFile(f.Path)
		if f.Remove {
			b.WriteString(Unified(f.Path, old, ""))
			continue
		}
		b.WriteString(Unified(f.Path, old, f.New))
	}
	for _, m := range d.Modes {
		fmt.Fprintf(&b, "chmod %04o -> %04o %s\n", m.Old, m.New, m.Path)
	}
	if len(d.SSH) > 0 {
		b.WriteString("--- sshd (effective)\n+++ sshd (safe-apply with rollback timer)\n")
		for _, k := range sortedKeys(d.SSH) {
			fmt.Fprintf(&b, "-%s %s\n+%s %s\n", k, d.SSHOld[k], k, d.SSH[k])
		}
	}
	for _, c := range d.Cmds {
		b.WriteString("$ " + strings.Join(c, " ") + "\n")
	}
	if d.Note != "" {
		b.WriteString("# " + d.Note + "\n")
	}
	return b.String()
}

// Unified returns a unified diff of two texts (LCS; config files are small).
func Unified(path, a, b string) string {
	if a == b {
		return ""
	}
	x, y := splitLines(a), splitLines(b)
	n, m := len(x), len(y)
	// lcs[i][j] = LCS length of x[i:], y[j:]
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if x[i] == y[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	type op struct {
		k    byte
		s    string
		i, j int
	}
	var ops []op
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && x[i] == y[j]:
			ops = append(ops, op{' ', x[i], i, j})
			i++
			j++
		case j < m && (i == n || lcs[i][j+1] >= lcs[i+1][j]):
			ops = append(ops, op{'+', y[j], i, j})
			j++
		default:
			ops = append(ops, op{'-', x[i], i, j})
			i++
		}
	}
	var out strings.Builder
	fmt.Fprintf(&out, "--- %s\n+++ %s\n", path, path)
	const ctxN = 3
	for k := 0; k < len(ops); {
		if ops[k].k == ' ' {
			k++
			continue
		}
		start := max(k-ctxN, 0)
		last, end := k, k
		// extend the hunk while changes are within 2*ctx lines of each other
		for ; end < len(ops); end++ {
			if ops[end].k != ' ' {
				last = end
			} else if end-last > 2*ctxN {
				break
			}
		}
		end = min(last+ctxN+1, len(ops))
		oa, ob, ca, cb := ops[start].i+1, ops[start].j+1, 0, 0
		for _, o := range ops[start:end] {
			if o.k != '+' {
				ca++
			}
			if o.k != '-' {
				cb++
			}
		}
		fmt.Fprintf(&out, "@@ -%d,%d +%d,%d @@\n", oa, ca, ob, cb)
		for _, o := range ops[start:end] {
			out.WriteByte(o.k)
			out.WriteString(o.s)
			out.WriteByte('\n')
		}
		k = end
	}
	return out.String()
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}
