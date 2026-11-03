package collector

import (
	"bytes"
	"syscall"
	"time"
)

// now is overridden in tests to get deterministic rates.
var now = time.Now

const clkTck = 100 // USER_HZ is 100 on every Linux arch we ship

// atou parses leading decimal digits of b.
func atou(b []byte) uint64 {
	var n uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + uint64(c-'0')
	}
	return n
}

// hexu parses hex digits of b.
func hexu(b []byte) uint64 {
	var n uint64
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9':
			n = n<<4 | uint64(c-'0')
		case c >= 'a' && c <= 'f':
			n = n<<4 | uint64(c-'a'+10)
		case c >= 'A' && c <= 'F':
			n = n<<4 | uint64(c-'A'+10)
		default:
			return n
		}
	}
	return n
}

// fields splits b on spaces and tabs into dst, reusing its backing array.
func fields(b []byte, dst [][]byte) [][]byte {
	dst = dst[:0]
	for i := 0; i < len(b); {
		for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n') {
			i++
		}
		j := i
		for j < len(b) && b[j] != ' ' && b[j] != '\t' && b[j] != '\n' {
			j++
		}
		if j > i {
			dst = append(dst, b[i:j])
		}
		i = j
	}
	return dst
}

// rate returns (cur-prev)/dt; counter resets yield 0.
func rate(cur, prev uint64, dt float64) float64 {
	if cur < prev || dt <= 0 {
		return 0
	}
	return float64(cur-prev) / dt
}

func pct(part, whole float64) float64 {
	if whole <= 0 {
		return 0
	}
	return part / whole * 100
}

// readInto reads file p (real path) into buf without allocating.
func readInto(p string, buf []byte) ([]byte, error) {
	fd, err := syscall.Open(p, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	n := 0
	for n < len(buf) {
		k, err := syscall.Read(fd, buf[n:])
		if k <= 0 || err != nil {
			break
		}
		n += k
	}
	return buf[:n], nil
}

// labels caches immutable single-label maps so steady-state ticks do not allocate them.
type labels struct {
	k string
	m map[string]map[string]string
}

func newLabels(k string) *labels { return &labels{k: k, m: map[string]map[string]string{}} }

func (l *labels) get(v []byte) map[string]string {
	if x, ok := l.m[string(v)]; ok {
		return x
	}
	s := string(v)
	x := map[string]string{l.k: s}
	l.m[s] = x
	return x
}

func add(out []Sample, metric string, v float64) []Sample {
	return append(out, Sample{Metric: metric, Value: v})
}

func addL(out []Sample, metric string, l map[string]string, v float64) []Sample {
	return append(out, Sample{Metric: metric, Labels: l, Value: v})
}

func trimNL(b []byte) []byte { return bytes.TrimRight(b, "\n") }
