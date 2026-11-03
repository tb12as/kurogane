// Package agentlink is the agent side of the central link (PRD §9, §11.1): one-time token enrollment, then a
// mutual-TLS gRPC stream with Hello/Heartbeat, samples, alert events, audit entries, scan summaries and typed op
// results. Everything is buffered (bounded) while disconnected; the agent keeps working fully offline (§11.4).
//
// Import for side effects: init registers an agent.Hook active when central.addr is set.
package agentlink

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tb12as/serverman/internal/agent"
	"github.com/tb12as/serverman/internal/collector"
	"github.com/tb12as/serverman/internal/config"
	"github.com/tb12as/serverman/internal/db"
	"github.com/tb12as/serverman/internal/hostfs"
	"github.com/tb12as/serverman/internal/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/keepalive"
)

// ServerName must match the central gRPC certificate SAN (server.ServerName).
const ServerName = "serverkeeper-central"

const (
	maxQueue   = 5000 // alerts, audit, op results, scans
	maxSamples = 60   // 10 min of 10 s collections; older samples are dropped while offline
)

// HeartbeatEvery is the Hello/Heartbeat interval.
var HeartbeatEvery = 30 * time.Second

func init() {
	agent.Hooks = append(agent.Hooks, func(a *agent.Agent) error {
		if a.Cfg.Central.Addr == "" {
			return nil
		}
		l := &Link{Cfg: a.Cfg, DB: a.DB, Version: a.Version, AddKey: a.SSH.AddKey, RemoveKey: a.SSH.RemoveKey,
			Scan: a.Harden.Scan}
		a.OnSnapshot = append(a.OnSnapshot, l.OnSnapshot)
		prev := a.Audit.Forward
		a.Audit.Forward = func(e db.AuditEntry) {
			if prev != nil {
				prev(e)
			}
			l.ForwardAudit(e)
		}
		a.Extra = append(a.Extra, l.Run)
		return nil
	})
}

// Link maintains the stream to the central server.
type Link struct {
	Cfg     *config.Config
	DB      db.Store
	Version string

	AddKey    func(ctx context.Context, user, pubkey, label string, expires time.Time) (db.SSHKey, error)
	RemoveKey func(ctx context.Context, fingerprint, user string) (int, error)
	Scan      func(ctx context.Context) (db.Scan, error)

	mu      sync.Mutex
	out     []*pb.AgentMessage
	samples []*pb.AgentMessage
	sys     collector.SystemInfo
	wake    chan struct{}
	alerts  map[string]string // event id -> forwarded state signature
	scanID  string
}

func (l *Link) init() {
	l.mu.Lock()
	if l.wake == nil {
		l.wake = make(chan struct{}, 1)
		l.alerts = map[string]string{}
	}
	l.mu.Unlock()
}

func (l *Link) push(m *pb.AgentMessage, sample bool) {
	l.init()
	l.mu.Lock()
	if sample {
		l.samples = append(l.samples, m)
		if len(l.samples) > maxSamples {
			l.samples = l.samples[len(l.samples)-maxSamples:]
		}
	} else {
		l.out = append(l.out, m)
		if len(l.out) > maxQueue {
			l.out = l.out[len(l.out)-maxQueue:]
		}
	}
	l.mu.Unlock()
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

// OnSnapshot queues one compact Samples batch per collection (~10 s).
func (l *Link) OnSnapshot(s *collector.Snapshot) {
	m := &pb.Samples{TsMs: s.TS.UnixMilli(), Keys: make([]string, len(s.Samples)), Values: make([]float64, len(s.Samples))}
	for i, x := range s.Samples {
		m.Keys[i], m.Values[i] = x.Key(), x.Value
	}
	l.mu.Lock()
	l.sys = s.System
	l.mu.Unlock()
	l.push(&pb.AgentMessage{Msg: &pb.AgentMessage_Samples{Samples: m}}, true)
}

// ForwardAudit queues a local audit entry for central (set as audit.Logger.Forward).
func (l *Link) ForwardAudit(e db.AuditEntry) {
	ts := e.TS
	if ts.IsZero() {
		ts = time.Now()
	}
	l.push(&pb.AgentMessage{Msg: &pb.AgentMessage_Audit{Audit: &pb.AuditEntry{Actor: e.Actor, Action: e.Action,
		Target: e.Target, Before: e.Before, After: e.After, Ts: ts.Unix(), SourceIp: e.SourceIP}}}, false)
}

// Run keeps the link up with reconnect and backoff until ctx is done.
func (l *Link) Run(ctx context.Context) {
	l.init()
	go l.poll(ctx)
	delay := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := l.session(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > time.Minute {
			delay = time.Second
		}
		slog.Warn("central link down, retrying", "addr", l.Cfg.Central.Addr, "err", err, "in", delay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, time.Minute)
	}
}

// poll forwards alert state changes and new scan results from the local database.
// shortcut: polls db events every 10 s because internal/alert has no event callback; switch to one when it exists.
func (l *Link) poll(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		l.PollOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// PollOnce forwards alert events changed since the last call and the latest scan if new.
func (l *Link) PollOnce(ctx context.Context) {
	l.init()
	evs, err := l.DB.ListEvents(ctx, db.EventFilter{Since: time.Now().Add(-24 * time.Hour), Limit: 500})
	if err == nil {
		keep := map[string]string{}
		for _, e := range evs {
			sig := e.State + "|" + e.ResolvedAt.String()
			keep[e.ID] = sig
			l.mu.Lock()
			same := l.alerts[e.ID] == sig
			l.mu.Unlock()
			if same {
				continue
			}
			l.push(&pb.AgentMessage{Msg: &pb.AgentMessage_Alert{Alert: &pb.AlertEvent{Id: e.ID, Rule: e.RuleID,
				Fingerprint: e.Fingerprint, State: e.State, Severity: e.Severity, Summary: e.Summary,
				StartedAt: unix(e.StartedAt), ResolvedAt: unix(e.ResolvedAt), Payload: string(e.Payload)}}}, false)
		}
		l.mu.Lock()
		l.alerts = keep
		l.mu.Unlock()
	}
	sc, err := l.DB.GetScan(ctx, "latest")
	if err != nil || sc.ID == "" || !l.newScan(sc.ID) {
		return
	}
	l.push(scanMsg(sc), false)
}

func (l *Link) newScan(id string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if id == l.scanID {
		return false
	}
	l.scanID = id
	return true
}

func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func scanMsg(sc db.Scan) *pb.AgentMessage {
	m := &pb.ScanResult{Id: sc.ID, Score: sc.Score, Grade: sc.Grade, StartedAt: unix(sc.StartedAt)}
	var rs []struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(sc.Results, &rs)
	for _, r := range rs {
		switch r.Status {
		case "pass", "passed":
			m.Passed++
		case "fail", "failed":
			m.Failed++
		}
	}
	return &pb.AgentMessage{Msg: &pb.AgentMessage_Scan{Scan: m}}
}

func (l *Link) hello() *pb.AgentMessage {
	l.mu.Lock()
	sys := l.sys
	l.mu.Unlock()
	if sys.OS == "" {
		sys.OS = hostfs.DetectDistro().Name
	}
	if sys.Kernel == "" {
		sys.Kernel = hostfs.ReadString("/proc/sys/kernel/osrelease")
	}
	return &pb.AgentMessage{Msg: &pb.AgentMessage_Hello{Hello: &pb.Hello{Name: l.Cfg.ServerName, Tags: l.Cfg.Tags,
		Os: sys.OS, Kernel: sys.Kernel, AgentVersion: l.Version}}}
}

func (l *Link) session(ctx context.Context) error {
	tc, err := l.credentials(ctx)
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(l.Cfg.Central.Addr, grpc.WithTransportCredentials(credentials.NewTLS(tc)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 60 * time.Second, Timeout: 20 * time.Second}))
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := pb.NewFleetClient(conn).Connect(ctx, grpc.UseCompressor(gzip.Name))
	if err != nil {
		return err
	}
	if err := st.Send(l.hello()); err != nil {
		return err
	}
	slog.Info("connected to central server", "addr", l.Cfg.Central.Addr)

	errc := make(chan error, 1)
	go func() {
		for {
			m, err := st.Recv()
			if err != nil {
				errc <- err
				return
			}
			if op := m.GetOp(); op != nil {
				l.push(l.exec(ctx, op), false)
			}
		}
	}()
	hb := time.NewTicker(HeartbeatEvery)
	defer hb.Stop()
	for {
		if err := l.drain(st); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errc:
			return err
		case <-hb.C:
			if err := st.Send(&pb.AgentMessage{Msg: &pb.AgentMessage_Heartbeat{
				Heartbeat: &pb.Heartbeat{TsMs: time.Now().UnixMilli()}}}); err != nil {
				return err
			}
		case <-l.wake:
		}
	}
}

// drain sends queued messages; a message is removed only after a successful send.
func (l *Link) drain(st grpc.BidiStreamingClient[pb.AgentMessage, pb.CentralMessage]) error {
	for {
		l.mu.Lock()
		var m *pb.AgentMessage
		q := &l.out
		if len(l.out) == 0 {
			q = &l.samples
		}
		if len(*q) > 0 {
			m = (*q)[0]
		}
		l.mu.Unlock()
		if m == nil {
			return nil
		}
		if err := st.Send(m); err != nil {
			return err
		}
		l.mu.Lock()
		if len(*q) > 0 && (*q)[0] == m {
			*q = (*q)[1:]
		}
		l.mu.Unlock()
	}
}

// exec runs one typed op; there is no op that executes arbitrary commands (§11.1).
func (l *Link) exec(ctx context.Context, op *pb.Op) *pb.AgentMessage {
	r := &pb.OpResult{OpId: op.Id}
	var res any
	var err error
	switch k := op.Kind.(type) {
	case *pb.Op_AddKey:
		var exp time.Time
		if k.AddKey.ExpiresAt > 0 {
			exp = time.Unix(k.AddKey.ExpiresAt, 0)
		}
		res, err = l.AddKey(ctx, k.AddKey.User, k.AddKey.PublicKey, k.AddKey.Label, exp)
	case *pb.Op_RemoveKey:
		var n int
		n, err = l.RemoveKey(ctx, k.RemoveKey.Fingerprint, k.RemoveKey.User)
		res = map[string]int{"removed": n}
	case *pb.Op_RunScan:
		var sc db.Scan
		if sc, err = l.Scan(ctx); err == nil {
			res = map[string]any{"id": sc.ID, "score": sc.Score, "grade": sc.Grade}
			if l.newScan(sc.ID) {
				l.push(scanMsg(sc), false)
			}
		}
	default:
		err = errors.New("unsupported op: upgrade the agent")
	}
	if err != nil {
		r.Error = err.Error()
		return &pb.AgentMessage{Msg: &pb.AgentMessage_OpResult{OpResult: r}}
	}
	b, _ := json.Marshal(res)
	r.Ok, r.Result = true, string(b)
	return &pb.AgentMessage{Msg: &pb.AgentMessage_OpResult{OpResult: r}}
}

func (l *Link) dir() string { return filepath.Join(l.Cfg.DataDir, "central") }

// credentials returns the mTLS config, enrolling first if no certificate is stored yet.
func (l *Link) credentials(ctx context.Context) (*tls.Config, error) {
	d := l.dir()
	cert, err := tls.LoadX509KeyPair(filepath.Join(d, "client.crt"), filepath.Join(d, "client.key"))
	if errors.Is(err, os.ErrNotExist) {
		if err := l.Enroll(ctx); err != nil {
			return nil, err
		}
		cert, err = tls.LoadX509KeyPair(filepath.Join(d, "client.crt"), filepath.Join(d, "client.key"))
	}
	if err != nil {
		return nil, fmt.Errorf("central client cert in %s: %w (delete the directory and re-enroll)", d, err)
	}
	ca, err := os.ReadFile(filepath.Join(d, "ca.crt"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("%s/ca.crt: no certificate", d)
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: ServerName, RootCAs: pool,
		Certificates: []tls.Certificate{cert}}, nil
}

// Enroll trades central.enrollment_token and a fresh CSR for a client certificate stored under data_dir/central.
// The central CA is verified against central.ca_file or the CA pin embedded in the token ("<secret>.<sha256>").
func (l *Link) Enroll(ctx context.Context) error {
	tok := strings.TrimSpace(l.Cfg.Central.EnrollmentToken)
	if tok == "" {
		return errors.New("not enrolled and central.enrollment_token is empty: run `serverkeeper server token create " +
			"--name " + l.Cfg.ServerName + "` on the central server and put the token in config.yaml")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: ServerName}
	_, pin, _ := strings.Cut(tok, ".")
	switch {
	case l.Cfg.Central.CAFile != "":
		b, err := os.ReadFile(l.Cfg.Central.CAFile)
		if err != nil {
			return err
		}
		tc.RootCAs = x509.NewCertPool()
		if !tc.RootCAs.AppendCertsFromPEM(b) {
			return fmt.Errorf("central.ca_file %s: no certificate", l.Cfg.Central.CAFile)
		}
	case pin != "":
		// default verification is replaced by the CA pin from the token; VerifyConnection also runs on resumption
		tc.InsecureSkipVerify = true // #nosec G402 -- pinned CA is verified in VerifyConnection
		verify := pinVerify(pin)
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			raw := make([][]byte, len(cs.PeerCertificates))
			for i, c := range cs.PeerCertificates {
				raw[i] = c.Raw
			}
			return verify(raw, nil)
		}
	default:
		return errors.New("enrollment token has no CA pin and central.ca_file is not set: copy the full token")
	}
	conn, err := grpc.NewClient(l.Cfg.Central.Addr, grpc.WithTransportCredentials(credentials.NewTLS(tc)))
	if err != nil {
		return err
	}
	defer conn.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: l.Cfg.ServerName}}, key)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := pb.NewFleetClient(conn).Enroll(ctx, &pb.EnrollRequest{Token: tok, Name: l.Cfg.ServerName,
		Tags: l.Cfg.Tags, CsrPem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})})
	if err != nil {
		return fmt.Errorf("enroll with %s: %w", l.Cfg.Central.Addr, err)
	}
	if pin != "" && l.Cfg.Central.CAFile == "" {
		blk, _ := pem.Decode(resp.CaPem)
		if blk == nil || fp(blk.Bytes) != pin {
			return errors.New("central returned a CA that does not match the token pin")
		}
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	d := l.dir()
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	for name, b := range map[string][]byte{"client.key": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY",
		Bytes: kd}), "client.crt": resp.CertPem, "ca.crt": resp.CaPem} {
		if err := os.WriteFile(filepath.Join(d, name), b, 0o600); err != nil {
			return err
		}
	}
	slog.Info("enrolled with central server", "name", resp.Name, "id", resp.ServerId)
	return nil
}

func fp(der []byte) string {
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

// pinVerify accepts the server chain only if it carries the pinned CA and the leaf is a valid server cert from it.
func pinVerify(pin string) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("central sent no certificate")
		}
		for _, r := range raw {
			if fp(r) != pin {
				continue
			}
			ca, err := x509.ParseCertificate(r)
			if err != nil {
				return err
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			pool := x509.NewCertPool()
			pool.AddCert(ca)
			_, err = leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: ServerName})
			return err
		}
		return errors.New("central CA does not match the enrollment token pin: wrong server or tampered connection")
	}
}
