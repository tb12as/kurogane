package api

import (
	"bufio"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/serverkeeper/serverkeeper/internal/auth"
	"github.com/serverkeeper/serverkeeper/internal/collector"
	"github.com/serverkeeper/serverkeeper/internal/store"
)

func init() {
	Register(func(s *Server) {
		s.Route("GET /metrics/current", auth.ScopeRead, s.metricsCurrent)
		s.Route("GET /metrics/history", auth.ScopeRead, s.metricsHistory)
		if s.Cfg != nil && s.Cfg.Collector.Prometheus {
			s.Raw("GET /metrics", auth.ScopeRead, s.prometheus)
		}
	})
}

func (s *Server) latest() (*collector.Snapshot, error) {
	if s.Metrics == nil {
		return nil, Errf(http.StatusServiceUnavailable, "no local collector on this server: query an agent instead")
	}
	snap := s.Metrics.Latest()
	if snap == nil {
		return nil, Errf(http.StatusServiceUnavailable,
			"no metrics collected yet: the first sample is taken a second after the agent starts, retry shortly")
	}
	return snap, nil
}

func (s *Server) metricsCurrent(*http.Request) (any, error) { return s.latest() }

// HistoryResponse is the body of GET /metrics/history.
type HistoryResponse struct {
	From   time.Time      `json:"from"`
	To     time.Time      `json:"to"`
	Step   string         `json:"step,omitempty"`
	Series []store.Series `json:"series"`
}

func (s *Server) metricsHistory(r *http.Request) (any, error) {
	if s.Store == nil {
		return nil, Errf(http.StatusServiceUnavailable, "no local metrics store on this server: query an agent instead")
	}
	q := r.URL.Query()
	t := time.Now()
	from, err := parseTime(q.Get("from"), t)
	if err != nil {
		return nil, err
	}
	to, err := parseTime(q.Get("to"), t)
	if err != nil {
		return nil, err
	}
	if to.IsZero() {
		to = t
	}
	if from.IsZero() {
		from = to.Add(-time.Hour)
	}
	if !from.Before(to) {
		return nil, Errf(http.StatusBadRequest, "from (%s) must be before to (%s)", from.Format(time.RFC3339),
			to.Format(time.RFC3339))
	}
	var step time.Duration
	if v := q.Get("step"); v != "" {
		if step, err = time.ParseDuration(v); err != nil || step <= 0 {
			return nil, Errf(http.StatusBadRequest, "invalid step %q: use a Go duration like 30s, 1m or 1h", v)
		}
	}
	var names []string
	for _, n := range strings.Split(q.Get("names"), ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	raw := 24 * time.Hour
	if s.Cfg != nil && s.Cfg.Collector.RetentionRaw > 0 {
		raw = s.Cfg.Collector.RetentionRaw
	}
	series, err := s.Store.Query(store.Query{Names: names, From: from, To: to, Step: step}, raw)
	if err != nil {
		return nil, err
	}
	out := HistoryResponse{From: from, To: to, Series: series}
	if step > 0 {
		out.Step = step.String()
	}
	return out, nil
}

// parseTime accepts RFC3339, unix seconds, or a duration meaning that long before now ("6h", "7d").
func parseTime(v string, now time.Time) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Unix(n, 0), nil
	}
	d, err := parseDur(strings.TrimPrefix(v, "-"))
	if err != nil || d < 0 {
		return time.Time{}, Errf(http.StatusBadRequest,
			"invalid time %q: use RFC3339 (2026-11-03T10:00:00Z), unix seconds, or a relative duration like 6h or 7d", v)
	}
	return now.Add(-d), nil
}

// parseDur extends time.ParseDuration with a "d" (24h) suffix.
func parseDur(v string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(v, "d"); ok {
		f, err := strconv.ParseFloat(n, 64)
		return time.Duration(f * float64(24*time.Hour)), err
	}
	return time.ParseDuration(v)
}

// prometheus writes the latest snapshot in Prometheus text format (PM-7).
func (s *Server) prometheus(w http.ResponseWriter, r *http.Request) {
	snap, err := s.latest()
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writeProm(w, snap.Samples)
}

func writeProm(w http.ResponseWriter, samples []collector.Sample) {
	idx := make([]int, len(samples))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return samples[idx[a]].Metric < samples[idx[b]].Metric })
	bw := bufio.NewWriter(w)
	last := ""
	var lk []string
	for _, i := range idx {
		x := samples[i]
		name := "serverkeeper_" + promIdent(x.Metric)
		if x.Metric != last {
			last = x.Metric
			bw.WriteString("# TYPE " + name + " gauge\n")
		}
		bw.WriteString(name)
		if len(x.Labels) > 0 {
			lk = lk[:0]
			for k := range x.Labels {
				lk = append(lk, k)
			}
			sort.Strings(lk)
			bw.WriteByte('{')
			for j, k := range lk {
				if j > 0 {
					bw.WriteByte(',')
				}
				bw.WriteString(promIdent(k) + `="` + promEscape(x.Labels[k]) + `"`)
			}
			bw.WriteByte('}')
		}
		bw.WriteByte(' ')
		bw.WriteString(strconv.FormatFloat(x.Value, 'g', -1, 64))
		bw.WriteByte('\n')
	}
	bw.Flush()
}

// promIdent maps "cpu.total_pct" to "cpu_total_pct".
func promIdent(m string) string {
	b := []byte(m)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			b[i] = '_'
		}
	}
	return string(b)
}

var promEsc = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func promEscape(v string) string { return promEsc.Replace(v) }
