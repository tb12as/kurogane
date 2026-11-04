package db

import (
	"encoding/json"
	"time"
)

// Entities from PRD §10.4 plus auth and fleet tables.

type Server struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Tags            []string  `json:"tags"`
	OS              string    `json:"os"`
	Kernel          string    `json:"kernel"`
	AgentVersion    string    `json:"agent_version"`
	LastSeen        time.Time `json:"last_seen"`
	CertFingerprint string    `json:"cert_fingerprint,omitempty"`
	EnrolledAt      time.Time `json:"enrolled_at"`
	Status          string    `json:"status"`
	Score           float64   `json:"score"`
	Grade           string    `json:"grade"`
}

type SSHKey struct {
	ServerID    string    `json:"server_id"`
	Fingerprint string    `json:"fingerprint"`
	Type        string    `json:"type"`
	Bits        int       `json:"bits"`
	User        string    `json:"user"`
	Label       string    `json:"label"`
	Comment     string    `json:"comment"`
	Options     string    `json:"options"`
	PublicKey   string    `json:"public_key"`
	OwnerPerson string    `json:"owner_person"`
	AddedAt     time.Time `json:"added_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	LastUsedAt  time.Time `json:"last_used_at"`
}

type Person struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Email     string      `json:"email"`
	Groups    []string    `json:"groups"`
	Keys      []PersonKey `json:"keys"`
	CreatedAt time.Time   `json:"created_at"`
}

type PersonKey struct {
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"`
	LoginUser   string `json:"login_user"`
}

type SSHChange struct {
	ID         string    `json:"id"`
	ServerID   string    `json:"server_id"`
	Actor      string    `json:"actor"`
	Setting    string    `json:"setting"`
	OldValue   string    `json:"old_value"`
	NewValue   string    `json:"new_value"`
	Status     string    `json:"status"` // pending | confirmed | rolled_back | failed
	TS         time.Time `json:"ts"`
	Deadline   time.Time `json:"deadline"`
	BackupPath string    `json:"backup_path"`
}

// SiteChange is one web site enable/disable attempt.
type SiteChange struct {
	ID       string    `json:"id"`
	ServerID string    `json:"server_id"`
	Actor    string    `json:"actor"`
	SiteID   string    `json:"site_id"`
	SiteName string    `json:"site_name"`
	Kind     string    `json:"kind"`   // nginx | apache
	Action   string    `json:"action"` // enable | disable
	Ops      string    `json:"ops"`    // the file moves, human readable
	Status   string    `json:"status"` // applying | applied | failed | rolled_back
	Error    string    `json:"error,omitempty"`
	TS       time.Time `json:"ts"`
}

type Scan struct {
	ID         string          `json:"id"`
	ServerID   string          `json:"server_id"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt time.Time       `json:"finished_at"`
	Score      float64         `json:"score"`
	Grade      string          `json:"grade"`
	Results    json.RawMessage `json:"results"`
}

type Fix struct {
	ID         string    `json:"id"`
	ServerID   string    `json:"server_id"`
	CheckID    string    `json:"check_id"`
	Diff       string    `json:"diff"`
	BackupPath string    `json:"backup_path"`
	AppliedBy  string    `json:"applied_by"`
	AppliedAt  time.Time `json:"applied_at"`
	RevertedAt time.Time `json:"reverted_at"`
	Status     string    `json:"status"`
}

type Ignore struct {
	ServerID  string    `json:"server_id"`
	CheckID   string    `json:"check_id"`
	Reason    string    `json:"reason"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

type AlertRule struct {
	ID       string        `json:"id"`
	Name     string        `json:"name"`
	Expr     string        `json:"expr"`
	For      time.Duration `json:"for"`
	Severity string        `json:"severity"`
	Channels []string      `json:"channels"`
	Enabled  bool          `json:"enabled"`
	Tags     []string      `json:"tags"`
	Builtin  bool          `json:"builtin"`
}

type AlertEvent struct {
	ID          string          `json:"id"`
	RuleID      string          `json:"rule_id"`
	ServerID    string          `json:"server_id"`
	Fingerprint string          `json:"fingerprint"`
	State       string          `json:"state"` // firing | acknowledged | resolved
	Severity    string          `json:"severity"`
	Summary     string          `json:"summary"`
	StartedAt   time.Time       `json:"started_at"`
	AckedAt     time.Time       `json:"acked_at"`
	AckedBy     string          `json:"acked_by"`
	ResolvedAt  time.Time       `json:"resolved_at"`
	LastSentAt  time.Time       `json:"last_sent_at"`
	Noise       bool            `json:"noise"`
	Payload     json.RawMessage `json:"payload"`
}

// Matcher selects alerts for a silence; empty fields match anything.
type Matcher struct {
	Server string `json:"server,omitempty"`
	Rule   string `json:"rule,omitempty"`
	Tag    string `json:"tag,omitempty"`
}

type Silence struct {
	ID        string    `json:"id"`
	Matcher   Matcher   `json:"matcher"`
	StartsAt  time.Time `json:"starts_at"`
	EndsAt    time.Time `json:"ends_at"`
	CreatedBy string    `json:"created_by"`
	Reason    string    `json:"reason"`
}

type Channel struct {
	Name   string            `json:"name"`
	Type   string            `json:"type"`
	Config map[string]string `json:"config"` // secret values sealed with secret.Box
}

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	TOTPSecret   string    `json:"-"`
	TOTPEnabled  bool      `json:"totp_enabled"`
	Role         string    `json:"role"`
	FailedLogins int       `json:"failed_logins"`
	LockedUntil  time.Time `json:"locked_until"`
	OIDCSubject  string    `json:"oidc_subject,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

type Session struct {
	ID        string    `json:"-"`
	UserID    string    `json:"user_id"`
	CSRF      string    `json:"-"`
	IP        string    `json:"ip"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type APIToken struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Hash       string    `json:"-"`
	Scopes     []string  `json:"scopes"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastUsedAt time.Time `json:"last_used_at"`
}

type AuditEntry struct {
	ID       int64     `json:"id"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	Target   string    `json:"target"`
	Before   string    `json:"before"`
	After    string    `json:"after"`
	TS       time.Time `json:"ts"`
	SourceIP string    `json:"source_ip"`
	ServerID string    `json:"server_id"`
}

type AuditFilter struct {
	Actor  string
	Action string
	Since  time.Time
	Limit  int
	Offset int
}

type EventFilter struct {
	State    string
	RuleID   string
	ServerID string
	Since    time.Time
	Limit    int
}

type EnrollToken struct {
	Hash       string    `json:"-"`
	ServerName string    `json:"server_name"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	UsedAt     time.Time `json:"used_at"`
}

type FleetOp struct {
	ID        string          `json:"id"`
	ServerID  string          `json:"server_id"`
	Kind      string          `json:"kind"`
	Payload   json.RawMessage `json:"payload"`
	Status    string          `json:"status"` // pending | sent | done | failed
	Result    string          `json:"result"`
	CreatedBy string          `json:"created_by"`
	CreatedAt time.Time       `json:"created_at"`
	DoneAt    time.Time       `json:"done_at"`
}
