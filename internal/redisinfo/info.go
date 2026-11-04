package redisinfo

import (
	"sort"
	"strconv"
	"strings"
)

// Info is INFO output as key -> value; section headers are dropped (keys are unique across sections).
type Info map[string]string

// ParseInfo parses the text of an INFO reply.
func ParseInfo(s string) Info {
	out := Info{}
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || l[0] == '#' {
			continue
		}
		if k, v, ok := strings.Cut(l, ":"); ok {
			out[k] = v
		}
	}
	return out
}

// Float returns a numeric field and whether it was present and numeric.
func (i Info) Float(k string) (float64, bool) {
	v, ok := i[k]
	if !ok {
		return 0, false
	}
	f, err := strconv.ParseFloat(v, 64)
	return f, err == nil
}

// Num returns a numeric field or 0.
func (i Info) Num(k string) float64 {
	f, _ := i.Float(k)
	return f
}

// DB is one keyspace line (db0:keys=1,expires=0,avg_ttl=0).
type DB struct {
	Name    string `json:"name"`
	Keys    int64  `json:"keys"`
	Expires int64  `json:"expires"`
}

// Keyspace returns the databases holding keys, in order.
func (i Info) Keyspace() []DB {
	var out []DB
	for k, v := range i {
		if !strings.HasPrefix(k, "db") {
			continue
		}
		if _, err := strconv.Atoi(k[2:]); err != nil {
			continue
		}
		d := DB{Name: k}
		for _, kv := range strings.Split(v, ",") {
			a, b, _ := strings.Cut(kv, "=")
			n, _ := strconv.ParseInt(b, 10, 64)
			switch a {
			case "keys":
				d.Keys = n
			case "expires":
				d.Expires = n
			}
		}
		out = append(out, d)
	}
	sort.Slice(out, func(a, b int) bool {
		x, _ := strconv.Atoi(out[a].Name[2:])
		y, _ := strconv.Atoi(out[b].Name[2:])
		return x < y
	})
	return out
}
