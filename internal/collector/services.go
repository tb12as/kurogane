package collector

import (
	"bytes"
	"context"
	"log/slog"
	"time"

	"github.com/tb12as/serverman/internal/executor"
)

// svcCollector queries all watched units with one `systemctl show` call per tick.
type svcCollector struct {
	ex    executor.Executor
	units []string
	lbl   *labels
	prev  map[string]string
	state []ServiceState
}

func newSvc(ex executor.Executor, units []string) *svcCollector {
	return &svcCollector{ex: ex, units: units, lbl: newLabels("unit"), prev: map[string]string{}}
}

func (c *svcCollector) Collect(ctx context.Context) ([]Sample, error) {
	if len(c.units) == 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	args := append([]string{"show", "-p", "ActiveState,SubState", "--"}, c.units...)
	b, err := c.ex.Run(ctx, "systemctl", args...)
	if err != nil {
		return nil, err
	}
	st := parseShow(b, c.units)
	out := make([]Sample, 0, len(st))
	for _, s := range st {
		v := 0.0
		if s.Active == "active" {
			v = 1
		}
		out = addL(out, "service.active", c.lbl.get([]byte(s.Unit)), v)
		cur := s.Active + "/" + s.Sub
		if old, ok := c.prev[s.Unit]; ok && old != cur {
			slog.Info("service state changed", "unit", s.Unit, "from", old, "to", cur)
		}
		c.prev[s.Unit] = cur
	}
	c.state = st
	return out, nil
}

// parseShow splits systemctl show output into one blank-line separated block per unit, in argument order.
func parseShow(b []byte, units []string) []ServiceState {
	out := make([]ServiceState, 0, len(units))
	cur := ServiceState{}
	has := false
	flush := func() {
		if has && len(out) < len(units) {
			cur.Unit = units[len(out)]
			out = append(out, cur)
		}
		cur, has = ServiceState{}, false
	}
	for l := range bytes.Lines(b) {
		l = bytes.TrimSpace(l)
		if len(l) == 0 {
			flush()
			continue
		}
		k, v, ok := bytes.Cut(l, []byte("="))
		if !ok {
			continue
		}
		switch string(k) {
		case "ActiveState":
			cur.Active, has = string(v), true
		case "SubState":
			cur.Sub, has = string(v), true
		}
	}
	flush()
	return out
}
