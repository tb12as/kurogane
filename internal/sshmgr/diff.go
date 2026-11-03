package sshmgr

import "strings"

// Diff returns a unified-style line diff of a and b (LCS; config files are small).
func Diff(name, a, b string) string {
	if a == b {
		return ""
	}
	x, y := strings.Split(strings.TrimRight(a, "\n"), "\n"), strings.Split(strings.TrimRight(b, "\n"), "\n")
	if a == "" {
		x = nil
	}
	n, m := len(x), len(y)
	l := make([][]int, n+1)
	for i := range l {
		l[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if x[i] == y[j] {
				l[i][j] = l[i+1][j+1] + 1
			} else {
				l[i][j] = max(l[i+1][j], l[i][j+1])
			}
		}
	}
	var out strings.Builder
	out.WriteString("--- " + name + "\n+++ " + name + "\n")
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && x[i] == y[j]:
			i, j = i+1, j+1
		case j < m && (i == n || l[i][j+1] >= l[i+1][j]):
			out.WriteString("+" + y[j] + "\n")
			j++
		default:
			out.WriteString("-" + x[i] + "\n")
			i++
		}
	}
	return out.String()
}
