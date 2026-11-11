// Package collector samples host metrics from /proc and /sys (PRD §5).
package collector

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/tb12as/kurogane/internal/certs"
)

// Sample is one metric value at a point in time (data model §10.4).
type Sample struct {
	Metric string            `json:"metric"`
	Labels map[string]string `json:"labels,omitempty"`
	TS     int64             `json:"ts"` // unix ms
	Value  float64           `json:"value"`
}

// Collector is the pluggable collection interface from PRD §9.
type Collector interface {
	Collect(ctx context.Context) ([]Sample, error)
}

// Key returns the canonical series key: metric{k="v",...} with sorted labels.
func (s Sample) Key() string { return SeriesKey(s.Metric, s.Labels) }

func SeriesKey(metric string, labels map[string]string) string {
	if len(labels) == 0 {
		return metric
	}
	ks := make([]string, 0, len(labels))
	for k := range labels {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	var b strings.Builder
	b.WriteString(metric)
	b.WriteByte('{')
	for i, k := range ks {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteString(`="`)
		b.WriteString(labels[k])
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

// ParseKey reverses SeriesKey.
func ParseKey(k string) (string, map[string]string) {
	i := strings.IndexByte(k, '{')
	if i < 0 || !strings.HasSuffix(k, "}") {
		return k, nil
	}
	labels := map[string]string{}
	for _, kv := range strings.Split(k[i+1:len(k)-1], `",`) {
		a, b, ok := strings.Cut(kv, `="`)
		if ok {
			labels[a] = strings.TrimSuffix(b, `"`)
		}
	}
	return k[:i], labels
}

// Snapshot is the latest full collection: numeric samples plus details for UI, TUI and alerts.
type Snapshot struct {
	TS       time.Time       `json:"ts"`
	Samples  []Sample        `json:"samples"`
	System   SystemInfo      `json:"system"`
	TopCPU   []Proc          `json:"top_cpu"`
	TopMem   []Proc          `json:"top_mem"`
	Conns    ConnInfo        `json:"conns"`
	Services []ServiceState  `json:"services"`
	Mounts   []Mount         `json:"mounts"`
	Certs    []certs.Cert    `json:"certs"`
	Redis    []RedisInstance `json:"redis"`
	Lag      time.Duration   `json:"lag_ns"`
}

// Value returns the first sample value for a metric/labels match (labels may be a subset).
func (s *Snapshot) Value(metric string, labels map[string]string) (float64, bool) {
	if s == nil {
		return 0, false
	}
outer:
	for _, x := range s.Samples {
		if x.Metric != metric {
			continue
		}
		for k, v := range labels {
			if x.Labels[k] != v {
				continue outer
			}
		}
		return x.Value, true
	}
	return 0, false
}

type SystemInfo struct {
	Hostname        string    `json:"hostname"`
	OS              string    `json:"os"`
	Kernel          string    `json:"kernel"`
	Arch            string    `json:"arch"`
	BootTime        time.Time `json:"boot_time"`
	Uptime          float64   `json:"uptime_s"`
	RebootRequired  bool      `json:"reboot_required"`
	SecurityUpdates int       `json:"security_updates"`
	PendingUpdates  int       `json:"pending_updates"`
	CPUs            int       `json:"cpus"`
	MemTotal        uint64    `json:"mem_total"`
}

type Proc struct {
	PID   int32   `json:"pid"`
	Name  string  `json:"name"`
	User  string  `json:"user"`
	CPU   float64 `json:"cpu_pct"`
	RSS   uint64  `json:"rss"`
	State string  `json:"state"`
	Cmd   string  `json:"cmd"`
}

type IPCount struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

type PortCount struct {
	Port  int `json:"port"`
	Count int `json:"count"`
}

type Listener struct {
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	Process string `json:"process,omitempty"`
}

// Flow is one source -> destination pair: "443/tcp" for sockets, "GET /login" for HTTP requests.
type Flow struct {
	IP         string `json:"ip"`
	Dest       string `json:"dest"`
	Count      int    `json:"count"`
	Cloudflare bool   `json:"cloudflare,omitempty"`
}

type ConnInfo struct {
	States     map[string]int `json:"states"`
	TopIPs     []IPCount      `json:"top_ips"`
	TopSubnets []IPCount      `json:"top_subnets"`
	// TopHTTPClients are real client IPs from the nginx access log (CF-Connecting-IP behind Cloudflare)
	TopHTTPClients []IPCount   `json:"top_http_clients,omitempty"`
	TopFlows       []Flow      `json:"top_flows"`                // source IP -> local port
	TopHTTPFlows   []Flow      `json:"top_http_flows,omitempty"` // client IP -> request, from the nginx log
	TopPorts       []PortCount `json:"top_ports"`
	Listening      []Listener  `json:"listening"`
	SynCookies     bool        `json:"syn_cookies"`
}

type ServiceState struct {
	Unit   string `json:"unit"`
	Active string `json:"active"`
	Sub    string `json:"sub"`
}

type Mount struct {
	Path    string  `json:"path"`
	Device  string  `json:"device"`
	FSType  string  `json:"fstype"`
	Opts    string  `json:"opts"`
	Total   uint64  `json:"total"`
	Used    uint64  `json:"used"`
	UsedPct float64 `json:"used_pct"`
}
