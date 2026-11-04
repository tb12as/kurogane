// Package audit writes the append-only audit log for every mutating action (PRD §11.1).
package audit

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/tb12as/kurogane/internal/db"
	"github.com/tb12as/kurogane/internal/secret"
)

type ctxKey struct{}

// Who identifies the actor of a request.
type Who struct {
	Actor    string
	SourceIP string
}

// WithActor attaches the actor to ctx.
func WithActor(ctx context.Context, actor, ip string) context.Context {
	return context.WithValue(ctx, ctxKey{}, Who{actor, ip})
}

// From returns the actor in ctx, or "system".
func From(ctx context.Context) Who {
	if w, ok := ctx.Value(ctxKey{}).(Who); ok {
		return w
	}
	return Who{Actor: "system"}
}

// Logger records audit entries; Forward (optional) streams them to the central server.
type Logger struct {
	Store    db.Store
	ServerID string
	Forward  func(db.AuditEntry)
}

// Record writes one entry. before/after are JSON-encoded unless already strings; secrets are redacted.
func (l *Logger) Record(ctx context.Context, action, target string, before, after any) {
	if l == nil || l.Store == nil {
		return
	}
	w := From(ctx)
	e := db.AuditEntry{Actor: w.Actor, SourceIP: w.SourceIP, Action: action, Target: target,
		Before: enc(before), After: enc(after), ServerID: l.ServerID}
	if err := l.Store.AppendAudit(context.WithoutCancel(ctx), e); err != nil {
		slog.Error("audit write failed", "action", action, "err", err)
	}
	if l.Forward != nil {
		l.Forward(e)
	}
}

func enc(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return secret.Redact(x)
	case []byte:
		return secret.Redact(string(x))
	}
	b, _ := json.Marshal(v)
	return secret.Redact(string(b))
}
