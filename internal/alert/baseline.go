package alert

import (
	"encoding/json"
	"log/slog"
	"math"
	"time"

	"github.com/tb12as/kurogane/internal/collector"
)

// AL-5: baselined metrics and their absolute floors; anomalies below a floor never alert (idle servers).
var floors = map[string]float64{
	"net.rx_bps_total": 12.5e6, // 100 Mbit/s
	"net.tx_bps_total": 12.5e6,
	"net.rx_pps_total": 20000,
	"net.new_conns_ps": 200,
	"net.tcp.syn_recv": 100,
	"net.udp_pps":      10000,
	"http.5xx_ps":      10,
}

const (
	learnFor = 7 * 24 * time.Hour
	zLimit   = 4.0
	ewmaN    = 360  // ~1h of 10s samples
	weekN    = 2000 // per hour-of-week bucket, a few weeks
	minWeekN = 30   // bucket samples before it is trusted over the EWMA
)

// stat is a running mean/variance; once N reaches its cap it becomes exponentially weighted (rolling).
type stat struct {
	N    float64 `json:"n"`
	Mean float64 `json:"mean"`
	Var  float64 `json:"var"`
}

func (s *stat) add(x, maxN float64) {
	if s.N < maxN {
		s.N++
	}
	a := 1 / s.N
	d := x - s.Mean
	s.Mean += a * d
	s.Var = (1 - a) * (s.Var + a*d*d)
}

// baseline is the rolling EWMA plus a seasonal hour-of-week profile for one metric.
type baseline struct {
	First time.Time `json:"first"`
	EWMA  stat      `json:"ewma"`
	Week  [168]stat `json:"week"`
}

func hourOfWeek(t time.Time) int { return int(t.Weekday())*24 + t.Hour() }

func (b *baseline) ready(t time.Time) bool { return !b.First.IsZero() && t.Sub(b.First) >= learnFor }

// expect returns the expected mean and standard deviation for t.
func (b *baseline) expect(t time.Time) (float64, float64) {
	if w := b.Week[hourOfWeek(t)]; w.N >= minWeekN {
		return w.Mean, math.Sqrt(w.Var)
	}
	return b.EWMA.Mean, math.Sqrt(b.EWMA.Var)
}

// zscore guards against flat series: sd is at least 10% of the mean.
func zscore(x, mean, sd float64) float64 {
	sd = math.Max(sd, math.Max(math.Abs(mean)*0.1, 1e-9))
	return (x - mean) / sd
}

// anomalous: baseline learned, z > 4 and the absolute floor crossed.
func (e *Engine) anomalous(m string, x float64, t time.Time) (float64, bool) {
	b := e.base[m]
	if b == nil || !b.ready(t) {
		return 0, false
	}
	mean, sd := b.expect(t)
	z := zscore(x, mean, sd)
	return z, z > zLimit && x > floors[m]
}

// observe folds a snapshot into the baselines; anomalous samples are skipped so attacks don't poison them.
func (e *Engine) observe(s *collector.Snapshot, t time.Time) {
	for m := range floors {
		x, ok := s.Value(m, nil)
		if !ok {
			continue
		}
		b := e.base[m]
		if b == nil {
			b = &baseline{First: t}
			e.base[m] = b
		}
		if _, bad := e.anomalous(m, x, t); bad {
			continue
		}
		b.EWMA.add(x, ewmaN)
		b.Week[hourOfWeek(t)].add(x, weekN)
	}
}

func (e *Engine) loadBaselines() {
	if e.d.Store == nil {
		return
	}
	_ = e.d.Store.List(baseBucket, func(k string, raw []byte) error {
		var b baseline
		if json.Unmarshal(raw, &b) == nil {
			e.base[k] = &b
		}
		return nil
	})
}

func (e *Engine) saveBaselines() {
	if e.d.Store == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for m, b := range e.base {
		if err := e.d.Store.Put(baseBucket, m, b); err != nil {
			slog.Warn("alert baseline save failed", "metric", m, "err", err)
		}
	}
}
