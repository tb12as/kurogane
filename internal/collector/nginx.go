package collector

import (
	"bytes"
	"context"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/serverkeeper/serverkeeper/internal/hostfs"
)

// nginxCollector tails an access log by offset and counts requests and 4xx/5xx statuses.
// Rotation is detected by inode change (rename) or the file shrinking (copytruncate).
type nginxCollector struct {
	path  string
	ino   uint64
	off   int64
	prevT time.Time
	rem   []byte // partial last line
	buf   []byte
}

func (c *nginxCollector) Collect(context.Context) ([]Sample, error) {
	p := hostfs.P(c.path)
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	var ino uint64
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		ino = s.Ino
	}
	t := now()
	if c.prevT.IsZero() {
		// start at the end: history is not a rate
		c.ino, c.off, c.prevT = ino, st.Size(), t
		return nil, nil
	}
	dt := t.Sub(c.prevT).Seconds()
	if dt <= 0 {
		return nil, nil
	}
	c.prevT = t
	if ino != c.ino || st.Size() < c.off {
		c.ino, c.off, c.rem = ino, 0, c.rem[:0]
	}
	var n, n4, n5 int
	if st.Size() > c.off {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if _, err := f.Seek(c.off, io.SeekStart); err != nil {
			return nil, err
		}
		if c.buf == nil {
			c.buf = make([]byte, 64*1024)
		}
		for {
			k, err := f.Read(c.buf)
			if k > 0 {
				c.off += int64(k)
				data := c.buf[:k]
				for {
					i := bytes.IndexByte(data, '\n')
					if i < 0 {
						c.rem = append(c.rem, data...)
						break
					}
					line := data[:i]
					if len(c.rem) > 0 {
						line = append(c.rem, line...)
						c.rem = c.rem[:0]
					}
					n++
					switch status(line) / 100 {
					case 4:
						n4++
					case 5:
						n5++
					}
					data = data[i+1:]
				}
			}
			if err != nil || k == 0 {
				break
			}
		}
		if len(c.rem) > 64*1024 {
			c.rem = c.rem[:0] // not a log line, do not grow forever
		}
	}
	out := make([]Sample, 0, 3)
	out = add(out, "http.rps", float64(n)/dt)
	out = add(out, "http.4xx_ps", float64(n4)/dt)
	out = add(out, "http.5xx_ps", float64(n5)/dt)
	return out, nil
}

// status extracts the code after the quoted request line in combined/common log format.
func status(l []byte) int {
	i := bytes.IndexByte(l, '"')
	if i < 0 {
		return 0
	}
	j := bytes.IndexByte(l[i+1:], '"')
	if j < 0 {
		return 0
	}
	s := l[i+j+2:]
	if len(s) < 4 || s[0] != ' ' {
		return 0
	}
	return int(atou(s[1:4]))
}
