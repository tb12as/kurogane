package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
)

type req struct {
	Op   string      `json:"op"`
	Path string      `json:"path,omitempty"`
	Data []byte      `json:"data,omitempty"`
	Mode os.FileMode `json:"mode,omitempty"`
	Cmd  string      `json:"cmd,omitempty"`
	Args []string    `json:"args,omitempty"`
	UID  int         `json:"uid,omitempty"`
	GID  int         `json:"gid,omitempty"`
}

type resp struct {
	Data   []byte `json:"data,omitempty"`
	Err    string `json:"err,omitempty"`
	Stderr string `json:"stderr,omitempty"`
	Code   int    `json:"code,omitempty"`
}

// Serve answers requests from an unprivileged worker over conn using ex (normally Local, as root).
// The worker can only ask for allowlisted typed operations; this is the privilege boundary.
func Serve(conn net.Conn, ex Executor) error {
	dec, enc := json.NewDecoder(conn), json.NewEncoder(conn)
	for {
		var r req
		if err := dec.Decode(&r); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		var out resp
		var err error
		switch r.Op {
		case "read":
			out.Data, err = ex.ReadFile(r.Path)
		case "write":
			err = ex.WriteFile(r.Path, r.Data, r.Mode)
		case "chmod":
			err = ex.Chmod(r.Path, r.Mode)
		case "remove":
			err = ex.Remove(r.Path)
		case "mkdir":
			err = ex.MkdirAll(r.Path, r.Mode)
		case "chown":
			err = ex.Chown(r.Path, r.UID, r.GID)
		case "run":
			out.Data, err = ex.Run(context.Background(), r.Cmd, r.Args...)
		default:
			err = ErrDenied
		}
		if err != nil {
			out.Err = err.Error()
			var re *RunError
			if errors.As(err, &re) {
				out.Stderr, out.Code = re.Stderr, ExitCode(err)
			}
			slog.Warn("executor op failed", "op", r.Op, "path", r.Path, "cmd", r.Cmd, "err", err)
		}
		if err := enc.Encode(out); err != nil {
			return err
		}
	}
}

// Remote forwards operations to a privileged Serve loop.
type Remote struct {
	mu  sync.Mutex
	enc *json.Encoder
	dec *json.Decoder
}

func NewRemote(conn net.Conn) *Remote {
	return &Remote{enc: json.NewEncoder(conn), dec: json.NewDecoder(conn)}
}

func (r *Remote) call(q req) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.enc.Encode(q); err != nil {
		return nil, err
	}
	var p resp
	if err := r.dec.Decode(&p); err != nil {
		return nil, err
	}
	if p.Err == "" {
		return p.Data, nil
	}
	if q.Op == "run" {
		return p.Data, &RunError{Cmd: q.Cmd, Err: errors.New(p.Err), Stderr: p.Stderr}
	}
	if p.Err == os.ErrNotExist.Error() || containsNotExist(p.Err) {
		return nil, &os.PathError{Op: q.Op, Path: q.Path, Err: os.ErrNotExist}
	}
	return nil, errors.New(p.Err)
}

func containsNotExist(s string) bool {
	return len(s) > 0 && (contains(s, "no such file or directory"))
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func (r *Remote) ReadFile(p string) ([]byte, error) { return r.call(req{Op: "read", Path: p}) }
func (r *Remote) WriteFile(p string, d []byte, m os.FileMode) error {
	_, err := r.call(req{Op: "write", Path: p, Data: d, Mode: m})
	return err
}
func (r *Remote) Chmod(p string, m os.FileMode) error {
	_, err := r.call(req{Op: "chmod", Path: p, Mode: m})
	return err
}
func (r *Remote) Remove(p string) error { _, err := r.call(req{Op: "remove", Path: p}); return err }
func (r *Remote) MkdirAll(p string, m os.FileMode) error {
	_, err := r.call(req{Op: "mkdir", Path: p, Mode: m})
	return err
}
func (r *Remote) Chown(p string, uid, gid int) error {
	_, err := r.call(req{Op: "chown", Path: p, UID: uid, GID: gid})
	return err
}

func (r *Remote) Run(_ context.Context, cmd string, args ...string) ([]byte, error) {
	if err := Allowed(cmd, args); err != nil {
		return nil, err
	}
	return r.call(req{Op: "run", Cmd: cmd, Args: args})
}
