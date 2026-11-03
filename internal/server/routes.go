package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/serverkeeper/serverkeeper/internal/api"
	"github.com/serverkeeper/serverkeeper/internal/audit"
	"github.com/serverkeeper/serverkeeper/internal/auth"
	"github.com/serverkeeper/serverkeeper/internal/db"
	"github.com/serverkeeper/serverkeeper/internal/store"
	"golang.org/x/crypto/ssh"
)

func (c *Central) routes(s *api.Server) {
	s.Route("GET /servers", auth.ScopeRead, func(r *http.Request) (any, error) { return c.DB.ListServers(r.Context()) })
	s.Route("GET /servers/{id}", auth.ScopeRead, func(r *http.Request) (any, error) {
		return c.server(r, r.PathValue("id"))
	})
	s.Route("DELETE /servers/{id}", auth.ScopeAdmin, c.deleteServer)
	s.Route("GET /servers/{id}/metrics/history", auth.ScopeRead, c.history)
	s.Route("GET /fleet/overview", auth.ScopeRead, c.overview)
	s.Route("POST /fleet/enrollment-tokens", auth.ScopeAdmin, func(r *http.Request) (any, error) {
		var q struct {
			Name string `json:"name"`
		}
		if err := api.Decode(r, &q); err != nil {
			return nil, err
		}
		raw, t, err := c.CreateEnrollToken(r.Context(), q.Name, audit.From(r.Context()).Actor)
		if err != nil {
			return nil, api.Errf(http.StatusBadRequest, "%s", err.Error())
		}
		return map[string]any{"token": raw, "name": t.ServerName, "expires_at": t.ExpiresAt}, nil
	})

	s.Route("GET /fleet/people", auth.ScopeRead, func(r *http.Request) (any, error) {
		return c.DB.ListPeople(r.Context())
	})
	s.Route("POST /fleet/people", auth.ScopeAdmin, c.createPerson)
	s.Route("DELETE /fleet/people/{id}", auth.ScopeAdmin, func(r *http.Request) (any, error) {
		p, err := c.DB.GetPerson(r.Context(), r.PathValue("id"))
		if err != nil {
			return nil, err
		}
		c.audit(r.Context(), "central", "fleet.person.delete", p.Name, nil)
		return nil, c.DB.DeletePerson(r.Context(), p.ID)
	})
	s.Route("POST /fleet/people/{id}/keys", auth.ScopeAdmin, c.addPersonKey)
	s.Route("DELETE /fleet/people/{id}/keys/{fp...}", auth.ScopeAdmin, func(r *http.Request) (any, error) {
		p, err := c.DB.GetPerson(r.Context(), r.PathValue("id"))
		if err != nil {
			return nil, err
		}
		c.audit(r.Context(), "central", "fleet.person.key.remove", p.Name, map[string]string{"fp": r.PathValue("fp")})
		return nil, c.DB.RemovePersonKey(r.Context(), p.ID, r.PathValue("fp"))
	})
	s.Route("POST /fleet/people/{id}/groups", auth.ScopeAdmin, func(r *http.Request) (any, error) {
		var q struct {
			Group  string `json:"group"`
			Member bool   `json:"member"`
		}
		if err := api.Decode(r, &q); err != nil {
			return nil, err
		}
		if !validName.MatchString(q.Group) {
			return nil, api.Errf(http.StatusBadRequest, "invalid group name %q", q.Group)
		}
		p, err := c.DB.GetPerson(r.Context(), r.PathValue("id"))
		if err != nil {
			return nil, err
		}
		c.audit(r.Context(), "central", "fleet.person.group", p.Name, q)
		return nil, c.DB.SetPersonGroup(r.Context(), p.ID, q.Group, q.Member)
	})
	s.Route("GET /fleet/groups", auth.ScopeRead, func(r *http.Request) (any, error) {
		return c.DB.ListGroups(r.Context())
	})
	s.Route("POST /fleet/keys/push", auth.ScopeAdmin, c.pushKeys)
	s.Route("POST /fleet/keys/revoke", auth.ScopeAdmin, c.revokeKey)
	s.Route("GET /fleet/ops", auth.ScopeRead, func(r *http.Request) (any, error) {
		n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		return c.DB.ListOps(r.Context(), n)
	})
	s.Route("POST /fleet/scans", auth.ScopeAdmin, func(r *http.Request) (any, error) {
		var q struct {
			Tag string `json:"tag"`
		}
		if err := api.Decode(r, &q); err != nil {
			return nil, err
		}
		srvs, err := c.targets(r.Context(), q.Tag)
		if err != nil {
			return nil, err
		}
		var ops []db.FleetOp
		for _, sv := range srvs {
			op, err := c.Enqueue(r.Context(), sv.ID, "run_scan", struct{}{})
			if err != nil {
				return nil, err
			}
			ops = append(ops, op)
		}
		return ops, nil
	})
}

// server resolves an id or name.
func (c *Central) server(r *http.Request, idOrName string) (db.Server, error) {
	s, err := c.DB.GetServer(r.Context(), idOrName)
	if errors.Is(err, db.ErrNotFound) {
		return c.DB.GetServerByName(r.Context(), idOrName)
	}
	return s, err
}

func (c *Central) deleteServer(r *http.Request) (any, error) {
	s, err := c.server(r, r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	if err := c.DB.DeleteServer(r.Context(), s.ID); err != nil {
		return nil, err
	}
	// its certificate is now rejected (identify finds no server); drop a live stream too
	c.mu.Lock()
	if ss := c.sessions[s.ID]; ss != nil {
		ss.cancel()
	}
	delete(c.latest, s.ID)
	c.mu.Unlock()
	c.audit(r.Context(), s.ID, "fleet.server.delete", s.Name, nil)
	return nil, nil
}

// parseTime accepts RFC 3339, unix seconds or a duration back from now ("6h").
func parseTime(v string, def time.Time) (time.Time, error) {
	if v == "" {
		return def, nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Unix(n, 0), nil
	}
	if d, err := time.ParseDuration(v); err == nil {
		return time.Now().Add(-d), nil
	}
	return def, api.Errf(http.StatusBadRequest, "invalid time %q: use RFC 3339, unix seconds or a duration like 6h", v)
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_.:]+$`)

// history answers in the agent's /metrics/history shape (points [ms, avg, max]) from VictoriaMetrics.
func (c *Central) history(r *http.Request) (any, error) {
	srv, err := c.server(r, r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	q := r.URL.Query()
	now := time.Now()
	to, err := parseTime(q.Get("to"), now)
	if err != nil {
		return nil, err
	}
	from, err := parseTime(q.Get("from"), to.Add(-time.Hour))
	if err != nil {
		return nil, err
	}
	step := max(10*time.Second, to.Sub(from)/300)
	if v := q.Get("step"); v != "" {
		if step, err = time.ParseDuration(v); err != nil || step < time.Second {
			return nil, api.Errf(http.StatusBadRequest, "invalid step %q: use a duration like 60s", v)
		}
	}
	// "cpu" selects cpu and cpu.*, like the agent store
	re := ".*"
	if names := q.Get("names"); names != "" {
		var parts []string
		for _, n := range strings.Split(names, ",") {
			n = strings.TrimSpace(n)
			if !nameRe.MatchString(n) {
				return nil, api.Errf(http.StatusBadRequest, "invalid metric name %q", n)
			}
			parts = append(parts, regexp.QuoteMeta(n)+`(\..*)?`)
		}
		re = strings.Join(parts, "|")
	}
	promql := `{__name__=~"` + strings.ReplaceAll(re, `\`, `\\`) + `",server="` + srv.Name + `"}`
	res, err := c.VM.QueryRange(r.Context(), promql, from, to, step)
	if err != nil {
		return nil, api.Errf(http.StatusBadGateway, "%s", err.Error())
	}
	out := make([]store.Series, 0, len(res))
	for _, s := range res {
		x := store.Series{Metric: s.Labels["__name__"], Points: make([]store.Point, len(s.Points))}
		delete(s.Labels, "__name__")
		delete(s.Labels, "server")
		if len(s.Labels) > 0 {
			x.Labels = s.Labels
		}
		for i, p := range s.Points {
			x.Points[i] = store.Point{p[0], p[1], p[1]}
		}
		out = append(out, x)
	}
	return api.HistoryResponse{From: from, To: to, Step: step.String(), Series: out}, nil
}

type overviewRow struct {
	db.Server
	Connected    bool               `json:"connected"`
	ActiveAlerts int                `json:"active_alerts"`
	Latest       map[string]float64 `json:"latest"`
}

func (c *Central) overview(r *http.Request) (any, error) {
	srvs, err := c.DB.ListServers(r.Context())
	if err != nil {
		return nil, err
	}
	evs, _ := c.DB.ListEvents(r.Context(), db.EventFilter{State: "open", Limit: 100000})
	open := map[string]int{}
	for _, e := range evs {
		open[e.ServerID]++
	}
	out := make([]overviewRow, 0, len(srvs))
	c.mu.Lock()
	for _, s := range srvs {
		out = append(out, overviewRow{Server: s, Connected: c.sessions[s.ID] != nil, ActiveAlerts: open[s.ID],
			Latest: c.latest[s.ID]})
	}
	c.mu.Unlock()
	return out, nil
}

func (c *Central) createPerson(r *http.Request) (any, error) {
	var q struct {
		Name   string   `json:"name"`
		Email  string   `json:"email"`
		Groups []string `json:"groups"`
	}
	if err := api.Decode(r, &q); err != nil {
		return nil, err
	}
	if !validName.MatchString(q.Name) {
		return nil, api.Errf(http.StatusBadRequest, "invalid person name %q: use letters, digits, '.', '_' or '-'", q.Name)
	}
	p := db.Person{ID: db.NewID(), Name: q.Name, Email: q.Email}
	if err := c.DB.CreatePerson(r.Context(), p); err != nil {
		return nil, api.Errf(http.StatusConflict, "person %q: %v", q.Name, err)
	}
	for _, g := range q.Groups {
		if err := c.DB.SetPersonGroup(r.Context(), p.ID, g, true); err != nil {
			return nil, err
		}
	}
	c.audit(r.Context(), "central", "fleet.person.create", p.Name, q)
	return c.DB.GetPerson(r.Context(), p.ID)
}

func (c *Central) addPersonKey(r *http.Request) (any, error) {
	var q struct {
		PublicKey string `json:"public_key"`
		LoginUser string `json:"login_user"`
	}
	if err := api.Decode(r, &q); err != nil {
		return nil, err
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(q.PublicKey))
	if err != nil {
		return nil, api.Errf(http.StatusBadRequest, "invalid public key: %v (paste one line of id_*.pub)", err)
	}
	p, err := c.DB.GetPerson(r.Context(), r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	k := db.PersonKey{Fingerprint: ssh.FingerprintSHA256(pk), PublicKey: strings.TrimSpace(q.PublicKey),
		LoginUser: q.LoginUser}
	if err := c.DB.AddPersonKey(r.Context(), p.ID, k); err != nil {
		return nil, err
	}
	c.audit(r.Context(), "central", "fleet.person.key.add", p.Name, map[string]string{"fp": k.Fingerprint})
	return k, nil
}

// targets returns all servers, or those carrying tag.
func (c *Central) targets(ctx context.Context, tag string) ([]db.Server, error) {
	all, err := c.DB.ListServers(ctx)
	if err != nil || tag == "" {
		return all, err
	}
	var out []db.Server
	for _, s := range all {
		for _, t := range s.Tags {
			if t == tag {
				out = append(out, s)
				break
			}
		}
	}
	return out, nil
}

// Enqueue queues a typed op for one server and wakes its stream if connected.
func (c *Central) Enqueue(ctx context.Context, serverID, kind string, payload any) (db.FleetOp, error) {
	b, _ := json.Marshal(payload)
	op := db.FleetOp{ID: db.NewID(), ServerID: serverID, Kind: kind, Payload: b, CreatedBy: audit.From(ctx).Actor}
	if err := c.DB.EnqueueOp(ctx, op); err != nil {
		return op, err
	}
	c.audit(ctx, serverID, "fleet.op.queue", kind, payload)
	c.kick(serverID)
	return op, nil
}

func (c *Central) pushKeys(r *http.Request) (any, error) {
	var q struct {
		Person string `json:"person"`
		Group  string `json:"group"`
		User   string `json:"user"`
		Tag    string `json:"tag"`
	}
	if err := api.Decode(r, &q); err != nil {
		return nil, err
	}
	var people []db.Person
	switch {
	case q.Person != "":
		p, err := c.DB.GetPerson(r.Context(), q.Person)
		if err != nil {
			return nil, err
		}
		people = []db.Person{p}
	case q.Group != "":
		ms, err := c.DB.GroupMembers(r.Context(), q.Group)
		if err != nil {
			return nil, err
		}
		// members may come without keys; reload each fully
		for _, m := range ms {
			p, err := c.DB.GetPerson(r.Context(), m.ID)
			if err != nil {
				return nil, err
			}
			people = append(people, p)
		}
	default:
		return nil, api.Errf(http.StatusBadRequest, `set "person" or "group"`)
	}
	srvs, err := c.targets(r.Context(), q.Tag)
	if err != nil {
		return nil, err
	}
	var ops []db.FleetOp
	for _, p := range people {
		for _, k := range p.Keys {
			user := q.User
			if user == "" {
				user = k.LoginUser
			}
			if user == "" {
				return nil, api.Errf(http.StatusBadRequest, "no login user for %s's key %s: pass \"user\"", p.Name,
					k.Fingerprint)
			}
			for _, sv := range srvs {
				o := addKeyOp{User: user, PublicKey: k.PublicKey, Label: p.Name}
				op, err := c.Enqueue(r.Context(), sv.ID, "add_key", o)
				if err != nil {
					return nil, err
				}
				ops = append(ops, op)
			}
		}
	}
	return map[string]any{"ops": ops, "servers": len(srvs), "people": len(people)}, nil
}

// revokeKey removes a fingerprint from every server (all users) and from every person.
func (c *Central) revokeKey(r *http.Request) (any, error) {
	var q struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := api.Decode(r, &q); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(q.Fingerprint, "SHA256:") {
		return nil, api.Errf(http.StatusBadRequest, "fingerprint must look like SHA256:... (ssh-keygen -lf key.pub)")
	}
	people, err := c.DB.ListPeople(r.Context())
	if err != nil {
		return nil, err
	}
	for _, p := range people {
		full, err := c.DB.GetPerson(r.Context(), p.ID)
		if err != nil {
			continue
		}
		for _, k := range full.Keys {
			if k.Fingerprint == q.Fingerprint {
				_ = c.DB.RemovePersonKey(r.Context(), p.ID, k.Fingerprint)
			}
		}
	}
	srvs, err := c.targets(r.Context(), "")
	if err != nil {
		return nil, err
	}
	var ops []db.FleetOp
	for _, sv := range srvs {
		op, err := c.Enqueue(r.Context(), sv.ID, "remove_key", removeKeyOp{Fingerprint: q.Fingerprint})
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	return map[string]any{"ops": ops, "servers": len(srvs)}, nil
}
