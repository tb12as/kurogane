package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/tb12as/serverman/internal/audit"
	"github.com/tb12as/serverman/internal/auth"
	"github.com/tb12as/serverman/internal/collector"
	"github.com/tb12as/serverman/internal/db"
	"github.com/tb12as/serverman/internal/metricsdb"
	"github.com/tb12as/serverman/internal/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

type fleetSrv struct {
	pb.UnimplementedFleetServer
	c *Central
}

var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// CreateEnrollToken issues a one-time token "<secret>.<ca pin>" valid for 1 h; only the secret's hash is stored.
func (c *Central) CreateEnrollToken(ctx context.Context, name, by string) (string, db.EnrollToken, error) {
	if name != "" && !validName.MatchString(name) {
		return "", db.EnrollToken{}, errors.New("invalid server name: use letters, digits, '.', '_' or '-'")
	}
	raw := auth.RandomToken(24)
	t := db.EnrollToken{Hash: auth.HashToken(raw), ServerName: name, CreatedBy: by, CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(TokenTTL)}
	if err := c.DB.CreateEnrollToken(ctx, t); err != nil {
		return "", t, err
	}
	c.audit(ctx, "central", "fleet.token.create", name, map[string]any{"expires_at": t.ExpiresAt})
	return raw + "." + c.CA.Pin(), t, nil
}

func (f *fleetSrv) Enroll(ctx context.Context, req *pb.EnrollRequest) (*pb.EnrollResponse, error) {
	c := f.c
	secret, _, _ := strings.Cut(req.GetToken(), ".")
	if secret == "" {
		return nil, status.Error(codes.InvalidArgument, "enrollment token required: set central.enrollment_token")
	}
	tok, err := c.DB.UseEnrollToken(ctx, auth.HashToken(secret), time.Now())
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	blk, _ := pem.Decode(req.GetCsrPem())
	if blk == nil {
		return nil, status.Error(codes.InvalidArgument, "csr_pem is not PEM")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err == nil {
		err = csr.CheckSignature()
	}
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "bad CSR: %v", err)
	}
	name := tok.ServerName
	if name == "" {
		name = req.GetName()
	}
	if !validName.MatchString(name) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid server name %q: set server_name in config.yaml", name)
	}
	srv, err := c.DB.GetServerByName(ctx, name)
	if errors.Is(err, db.ErrNotFound) {
		srv = db.Server{ID: db.NewID(), Name: name, Tags: req.GetTags(), Status: "offline", Score: -1}
	} else if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	cert, fp, err := c.CA.SignClient(csr.PublicKey, srv.ID)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	srv.CertFingerprint, srv.EnrolledAt = fp, time.Now()
	if err := c.DB.UpsertServer(ctx, srv); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	ip := ""
	if p, ok := peer.FromContext(ctx); ok {
		ip = p.Addr.String()
	}
	c.audit(audit.WithActor(ctx, "enroll:"+tok.CreatedBy, ip), srv.ID, "fleet.enroll", name, map[string]any{"cert": fp})
	slog.Info("agent enrolled", "server", name, "id", srv.ID)
	return &pb.EnrollResponse{ServerId: srv.ID, Name: name, CertPem: cert, CaPem: c.CA.PEM}, nil
}

// identify maps the verified client certificate to an enrolled server.
func (c *Central) identify(ctx context.Context) (db.Server, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return db.Server{}, status.Error(codes.Unauthenticated, "no peer")
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.VerifiedChains) == 0 {
		return db.Server{}, status.Error(codes.Unauthenticated, "client certificate required: enroll the agent first")
	}
	leaf := ti.State.VerifiedChains[0][0]
	srv, err := c.DB.GetServer(ctx, leaf.Subject.CommonName)
	if err != nil {
		return db.Server{}, status.Error(codes.PermissionDenied,
			"server not enrolled (removed?): delete data_dir/central and re-enroll with a new token")
	}
	if srv.CertFingerprint != Fingerprint(leaf.Raw) {
		return db.Server{}, status.Error(codes.PermissionDenied, "certificate superseded by a newer enrollment")
	}
	return srv, nil
}

func (f *fleetSrv) Connect(st grpc.BidiStreamingServer[pb.AgentMessage, pb.CentralMessage]) error {
	c := f.c
	srv, err := c.identify(st.Context())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(st.Context())
	defer cancel()
	s := &session{id: srv.ID, kick: make(chan struct{}, 1), cancel: cancel}
	c.mu.Lock()
	if old := c.sessions[srv.ID]; old != nil {
		old.cancel()
	}
	c.sessions[srv.ID] = s
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		if c.sessions[srv.ID] == s {
			delete(c.sessions, srv.ID)
		}
		c.mu.Unlock()
	}()
	slog.Info("agent connected", "server", srv.Name)

	errc := make(chan error, 1)
	go func() {
		for {
			m, err := st.Recv()
			if err != nil {
				errc <- err
				return
			}
			c.handle(ctx, srv.ID, srv.Name, m)
		}
	}()
	sent := map[string]bool{}
	for {
		if err := c.deliver(ctx, srv.ID, st, sent); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return status.Error(codes.Aborted, "session replaced or server shutting down")
		case err := <-errc:
			slog.Info("agent disconnected", "server", srv.Name, "err", err)
			return nil
		case <-s.kick:
		}
	}
}

// deliver sends queued typed ops not yet sent on this stream (pending and previously sent ones on reconnect).
type stream = grpc.BidiStreamingServer[pb.AgentMessage, pb.CentralMessage]

func (c *Central) deliver(ctx context.Context, id string, st stream, sent map[string]bool) error {
	ops, err := c.DB.PendingOps(ctx, id)
	if err != nil {
		return err
	}
	for _, op := range ops {
		if sent[op.ID] {
			continue
		}
		m, err := toPB(op)
		if err != nil {
			_ = c.DB.UpdateOp(ctx, op.ID, "failed", err.Error())
			continue
		}
		// mark sent first so a fast OpResult is not overwritten
		if err := c.DB.UpdateOp(ctx, op.ID, "sent", ""); err != nil {
			return err
		}
		if err := st.Send(&pb.CentralMessage{Msg: &pb.CentralMessage_Op{Op: m}}); err != nil {
			return err
		}
		sent[op.ID] = true
	}
	return nil
}

// op payloads stored in fleet_ops.
type addKeyOp struct {
	User      string    `json:"user"`
	PublicKey string    `json:"public_key"`
	Label     string    `json:"label"`
	ExpiresAt time.Time `json:"expires_at"`
}

type setSiteOp struct {
	SiteID  string `json:"site_id"`
	Enabled bool   `json:"enabled"`
}

type removeKeyOp struct {
	Fingerprint string `json:"fingerprint"`
	User        string `json:"user"`
}

func toPB(op db.FleetOp) (*pb.Op, error) {
	m := &pb.Op{Id: op.ID}
	switch op.Kind {
	case "add_key":
		var p addKeyOp
		if err := json.Unmarshal(op.Payload, &p); err != nil {
			return nil, err
		}
		var exp int64
		if !p.ExpiresAt.IsZero() {
			exp = p.ExpiresAt.Unix()
		}
		m.Kind = &pb.Op_AddKey{AddKey: &pb.AddKey{User: p.User, PublicKey: p.PublicKey, Label: p.Label, ExpiresAt: exp}}
	case "remove_key":
		var p removeKeyOp
		if err := json.Unmarshal(op.Payload, &p); err != nil {
			return nil, err
		}
		m.Kind = &pb.Op_RemoveKey{RemoveKey: &pb.RemoveKey{Fingerprint: p.Fingerprint, User: p.User}}
	case "run_scan":
		m.Kind = &pb.Op_RunScan{RunScan: &pb.RunScan{}}
	case "set_site":
		var p setSiteOp
		if err := json.Unmarshal(op.Payload, &p); err != nil {
			return nil, err
		}
		m.Kind = &pb.Op_SetSite{SetSite: &pb.SetSite{SiteId: p.SiteID, Enabled: p.Enabled}}
	default:
		return nil, errors.New("unknown op kind " + op.Kind)
	}
	return m, nil
}

func (c *Central) handle(ctx context.Context, id, name string, m *pb.AgentMessage) {
	now := time.Now()
	switch x := m.Msg.(type) {
	case *pb.AgentMessage_Hello:
		h := x.Hello
		srv, err := c.DB.GetServer(ctx, id)
		if err != nil {
			return
		}
		was := srv.Status
		if h.Tags != nil {
			srv.Tags = h.Tags
		}
		srv.OS, srv.Kernel, srv.AgentVersion, srv.LastSeen, srv.Status = h.Os, h.Kernel, h.AgentVersion, now, "online"
		if err := c.DB.UpsertServer(ctx, srv); err != nil {
			slog.Error("server upsert", "err", err)
		}
		if was == "offline" {
			c.resolveOffline(ctx, srv)
		}
	case *pb.AgentMessage_Heartbeat:
		c.touch(ctx, id, now)
	case *pb.AgentMessage_Samples:
		c.samples(id, name, x.Samples)
	case *pb.AgentMessage_Alert:
		c.agentAlert(ctx, id, x.Alert)
	case *pb.AgentMessage_Audit:
		a := x.Audit
		err := c.DB.AppendAudit(ctx, db.AuditEntry{Actor: a.Actor, Action: a.Action, Target: a.Target, Before: a.Before,
			After: a.After, TS: time.Unix(a.Ts, 0), SourceIP: a.SourceIp, ServerID: id})
		if err != nil {
			slog.Warn("agent audit", "err", err)
		}
	case *pb.AgentMessage_OpResult:
		c.opResult(ctx, id, x.OpResult)
	case *pb.AgentMessage_Sites:
		b, err := protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}.Marshal(x.Sites)
		if err == nil {
			err = c.DB.SaveFleetSites(ctx, db.FleetSites{ServerID: id, Data: b, UpdatedAt: now})
		}
		if err != nil {
			slog.Warn("save fleet sites", "server", name, "err", err)
		}
	case *pb.AgentMessage_Scan:
		s := x.Scan
		srv, err := c.DB.GetServer(ctx, id)
		if err != nil {
			return
		}
		srv.Score, srv.Grade = s.Score, s.Grade
		_ = c.DB.UpsertServer(ctx, srv)
		sum, _ := json.Marshal(map[string]int32{"passed": s.Passed, "failed": s.Failed})
		_ = c.DB.SaveScan(ctx, db.Scan{ID: id + ":" + s.Id, ServerID: id, StartedAt: time.Unix(s.StartedAt, 0),
			FinishedAt: now, Score: s.Score, Grade: s.Grade, Results: sum})
	}
}

func (c *Central) touch(ctx context.Context, id string, now time.Time) {
	srv, err := c.DB.GetServer(ctx, id)
	if err != nil {
		return
	}
	_ = c.DB.TouchServer(ctx, id, now, "online")
	if srv.Status == "offline" {
		c.resolveOffline(ctx, srv)
	}
}

// samples converts a collection into VM import lines labelled server="<name>" and keeps overview values.
func (c *Central) samples(id, name string, s *pb.Samples) {
	if len(s.Keys) != len(s.Values) {
		return
	}
	var b []byte
	ov := map[string]float64{}
	for i, k := range s.Keys {
		metric, labels := collector.ParseKey(k)
		if labels == nil {
			labels = map[string]string{}
		}
		labels["server"] = name
		v := s.Values[i]
		b = metricsdb.AppendLine(b, metric, labels, v, s.TsMs)
		switch metric {
		case "cpu.total_pct":
			ov["cpu"] = v
		case "mem.used_pct":
			ov["mem"] = v
		case "disk.used_pct":
			ov["disk"] = max(ov["disk"], v)
		case "cert.days_left":
			if d, ok := ov["cert_days"]; !ok || v < d {
				ov["cert_days"] = v // soonest certificate expiry on the server
			}
		}
	}
	c.mu.Lock()
	c.latest[id] = ov
	c.mu.Unlock()
	c.vmMu.Lock()
	c.vmBuf = append(c.vmBuf, b...)
	c.vmMu.Unlock()
}

func (c *Central) opResult(ctx context.Context, id string, r *pb.OpResult) {
	ops, err := c.DB.PendingOps(ctx, id)
	if err != nil {
		return
	}
	var op *db.FleetOp
	for i := range ops {
		if ops[i].ID == r.OpId {
			op = &ops[i]
		}
	}
	if op == nil {
		return // not this server's op, or already finished
	}
	st, res := "done", r.Result
	if !r.Ok {
		st, res = "failed", r.Error
	}
	_ = c.DB.UpdateOp(ctx, op.ID, st, res)
	// keep the central key inventory in step for fleet revoke and the UI
	if r.Ok && op.Kind == "add_key" {
		var k db.SSHKey
		if json.Unmarshal([]byte(r.Result), &k) == nil && k.Fingerprint != "" {
			k.ServerID = id
			_ = c.DB.UpsertKey(ctx, k)
		}
	}
	if r.Ok && op.Kind == "remove_key" {
		var p removeKeyOp
		_ = json.Unmarshal(op.Payload, &p)
		keys, _ := c.DB.FindKeys(ctx, p.Fingerprint)
		for _, k := range keys {
			if k.ServerID == id && (p.User == "" || k.User == p.User) {
				_ = c.DB.DeleteKey(ctx, id, k.User, k.Fingerprint)
			}
		}
	}
	c.audit(audit.WithActor(ctx, "agent", ""), id, "fleet.op."+st, op.Kind, map[string]string{"op": op.ID, "result": res})
}
