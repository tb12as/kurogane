package db

import (
	"context"
	"time"
)

// Store is the metadata persistence interface used by agent and central server.
type Store interface {
	Close() error
	VacuumInto(ctx context.Context, dest string) error

	AppendAudit(ctx context.Context, e AuditEntry) error
	ListAudit(ctx context.Context, f AuditFilter) ([]AuditEntry, error)
	PruneAudit(ctx context.Context, before time.Time) (int64, error)

	UpsertServer(ctx context.Context, s Server) error
	GetServer(ctx context.Context, id string) (Server, error)
	GetServerByName(ctx context.Context, name string) (Server, error)
	ListServers(ctx context.Context) ([]Server, error)
	TouchServer(ctx context.Context, id string, at time.Time, status string) error
	DeleteServer(ctx context.Context, id string) error

	UpsertKey(ctx context.Context, k SSHKey) error
	ListKeys(ctx context.Context, serverID, user string) ([]SSHKey, error)
	FindKeys(ctx context.Context, fingerprint string) ([]SSHKey, error)
	DeleteKey(ctx context.Context, serverID, user, fp string) error

	CreatePerson(ctx context.Context, p Person) error
	GetPerson(ctx context.Context, idOrName string) (Person, error)
	ListPeople(ctx context.Context) ([]Person, error)
	DeletePerson(ctx context.Context, id string) error
	AddPersonKey(ctx context.Context, personID string, k PersonKey) error
	RemovePersonKey(ctx context.Context, personID, fp string) error
	SetPersonGroup(ctx context.Context, personID, group string, member bool) error
	GroupMembers(ctx context.Context, group string) ([]Person, error)
	ListGroups(ctx context.Context) (map[string][]string, error)

	SaveSSHChange(ctx context.Context, c SSHChange) error
	ListSSHChanges(ctx context.Context, limit int) ([]SSHChange, error)

	SaveScan(ctx context.Context, s Scan) error
	GetScan(ctx context.Context, id string) (Scan, error)
	ListScans(ctx context.Context, serverID string, limit int) ([]Scan, error)

	SaveFix(ctx context.Context, f Fix) error
	GetFix(ctx context.Context, id string) (Fix, error)
	ListFixes(ctx context.Context, serverID string, limit int) ([]Fix, error)

	SetIgnore(ctx context.Context, ig Ignore) error
	DeleteIgnore(ctx context.Context, serverID, checkID string) error
	ListIgnores(ctx context.Context, serverID string) ([]Ignore, error)

	UpsertRule(ctx context.Context, r AlertRule) error
	GetRule(ctx context.Context, id string) (AlertRule, error)
	ListRules(ctx context.Context) ([]AlertRule, error)
	DeleteRule(ctx context.Context, id string) error

	SaveEvent(ctx context.Context, e AlertEvent) error
	GetEvent(ctx context.Context, id string) (AlertEvent, error)
	OpenEvent(ctx context.Context, fingerprint string) (AlertEvent, error)
	ListEvents(ctx context.Context, f EventFilter) ([]AlertEvent, error)

	SaveSilence(ctx context.Context, s Silence) error
	DeleteSilence(ctx context.Context, id string) error
	ListSilences(ctx context.Context, activeAt time.Time) ([]Silence, error)

	UpsertChannel(ctx context.Context, c Channel) error
	DeleteChannel(ctx context.Context, name string) error
	ListChannels(ctx context.Context) ([]Channel, error)

	SaveUser(ctx context.Context, u User) error
	GetUser(ctx context.Context, id string) (User, error)
	GetUserByName(ctx context.Context, name string) (User, error)
	GetUserByOIDC(ctx context.Context, subject string) (User, error)
	ListUsers(ctx context.Context) ([]User, error)
	DeleteUser(ctx context.Context, id string) error

	CreateSession(ctx context.Context, s Session) error
	GetSession(ctx context.Context, id string) (Session, error)
	DeleteSession(ctx context.Context, id string) error
	PruneSessions(ctx context.Context, now time.Time) error

	CreateToken(ctx context.Context, t APIToken) error
	GetTokenByHash(ctx context.Context, hash string) (APIToken, error)
	ListTokens(ctx context.Context) ([]APIToken, error)
	DeleteToken(ctx context.Context, id string) error
	TouchToken(ctx context.Context, id string, at time.Time) error

	CreateEnrollToken(ctx context.Context, t EnrollToken) error
	UseEnrollToken(ctx context.Context, hash string, now time.Time) (EnrollToken, error)

	EnqueueOp(ctx context.Context, op FleetOp) error
	PendingOps(ctx context.Context, serverID string) ([]FleetOp, error)
	UpdateOp(ctx context.Context, id, status, result string) error
	ListOps(ctx context.Context, limit int) ([]FleetOp, error)

	GetKV(ctx context.Context, key string) (string, error)
	SetKV(ctx context.Context, key, value string) error
}

var _ Store = (*SQLite)(nil)
