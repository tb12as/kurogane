// Package metricsdb talks to the central VictoriaMetrics single-node (PRD §9 storage design): Prometheus text
// import, PromQL range queries and snapshots, plus the installer and the child-process supervisor.
package metricsdb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Client is a VictoriaMetrics HTTP client. VM listens on 127.0.0.1 only (§11.1).
type Client struct {
	URL string
	HC  *http.Client
}

// New returns a client for base URL u (e.g. http://127.0.0.1:8428).
func New(u string) *Client {
	return &Client{URL: strings.TrimRight(u, "/"), HC: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) do(req *http.Request) ([]byte, error) {
	resp, err := c.HC.Do(req)
	if err != nil {
		return nil, fmt.Errorf("victoriametrics at %s unreachable: %w (is serverkeeper-vm running?)", c.URL, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("victoriametrics %s: HTTP %d: %s", req.URL.Path, resp.StatusCode,
			strings.TrimSpace(string(b)))
	}
	return b, nil
}

// Import posts Prometheus text exposition lines to /api/v1/import/prometheus.
func (c *Client) Import(ctx context.Context, body []byte) error {
	if len(body) == 0 {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/api/v1/import/prometheus", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")
	_, err = c.do(req)
	return err
}

// AppendLine appends one exposition line `name{labels} value ts_ms`; labels are sorted for stable output.
// Lines with names or label keys outside [A-Za-z0-9_.:] are skipped: agent input must not inject series.
func AppendLine(b []byte, name string, labels map[string]string, v float64, tsMs int64) []byte {
	if !validName(name) {
		return b
	}
	ks := make([]string, 0, len(labels))
	for k := range labels {
		if !validName(k) || strings.ContainsAny(k, ".:") {
			return b
		}
		ks = append(ks, k)
	}
	sort.Strings(ks)
	b = append(b, name...)
	if len(ks) > 0 {
		b = append(b, '{')
		for i, k := range ks {
			if i > 0 {
				b = append(b, ',')
			}
			b = append(b, k...)
			b = append(b, '=', '"')
			for _, c := range []byte(labels[k]) {
				switch c {
				case '\\':
					b = append(b, '\\', '\\')
				case '"':
					b = append(b, '\\', '"')
				case '\n':
					b = append(b, '\\', 'n')
				default:
					b = append(b, c)
				}
			}
			b = append(b, '"')
		}
		b = append(b, '}')
	}
	b = append(b, ' ')
	b = strconv.AppendFloat(b, v, 'g', -1, 64)
	b = append(b, ' ')
	b = strconv.AppendInt(b, tsMs, 10)
	return append(b, '\n')
}

func validName(s string) bool {
	if s == "" || len(s) > 200 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == ':') {
			return false
		}
	}
	return true
}

// Series is one range-query result series; Points are [unix ms, value].
type Series struct {
	Labels map[string]string `json:"labels"`
	Points [][2]float64      `json:"points"`
}

// QueryRange runs a PromQL/MetricsQL range query.
func (c *Client) QueryRange(ctx context.Context, q string, from, to time.Time, step time.Duration) ([]Series, error) {
	v := url.Values{"query": {q}, "start": {unixStr(from)}, "end": {unixStr(to)},
		"step": {strconv.FormatInt(int64(step/time.Second), 10) + "s"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+"/api/v1/query_range?"+v.Encode(), nil)
	if err != nil {
		return nil, err
	}
	b, err := c.do(req)
	if err != nil {
		return nil, err
	}
	return parseMatrix(b)
}

func unixStr(t time.Time) string { return strconv.FormatFloat(float64(t.UnixMilli())/1000, 'f', 3, 64) }

func parseMatrix(b []byte) ([]Series, error) {
	var r struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Metric map[string]string `json:"metric"`
				Values [][2]any          `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("victoriametrics: bad query response: %w", err)
	}
	if r.Status != "success" {
		return nil, fmt.Errorf("victoriametrics query failed: %s", r.Error)
	}
	out := make([]Series, 0, len(r.Data.Result))
	for _, x := range r.Data.Result {
		s := Series{Labels: x.Metric, Points: make([][2]float64, 0, len(x.Values))}
		for _, p := range x.Values {
			t, ok := p[0].(float64)
			vs, ok2 := p[1].(string)
			if !ok || !ok2 {
				continue
			}
			v, err := strconv.ParseFloat(vs, 64)
			if err != nil {
				continue
			}
			s.Points = append(s.Points, [2]float64{float64(int64(t * 1000)), v})
		}
		out = append(out, s)
	}
	return out, nil
}

// Snapshot creates a VM snapshot and returns its name (under <storageDataPath>/snapshots/).
func (c *Client) Snapshot(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/snapshot/create", nil)
	if err != nil {
		return "", err
	}
	b, err := c.do(req)
	if err != nil {
		return "", err
	}
	var r struct {
		Status   string `json:"status"`
		Snapshot string `json:"snapshot"`
		Msg      string `json:"msg"`
	}
	if err := json.Unmarshal(b, &r); err != nil || r.Status != "ok" || r.Snapshot == "" {
		return "", fmt.Errorf("victoriametrics snapshot failed: %s", strings.TrimSpace(string(b)))
	}
	return r.Snapshot, nil
}

// DeleteSnapshot frees a snapshot once it has been copied.
func (c *Client) DeleteSnapshot(ctx context.Context, name string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.URL+"/snapshot/delete?snapshot="+url.QueryEscape(name), nil)
	if err != nil {
		return err
	}
	_, err = c.do(req)
	return err
}

// Healthy reports whether VM answers /health.
func (c *Client) Healthy(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+"/health", nil)
	if err != nil {
		return false
	}
	_, err = c.do(req)
	return err == nil
}
