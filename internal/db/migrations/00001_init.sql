-- +goose Up
CREATE TABLE servers (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  tags TEXT NOT NULL DEFAULT '[]',
  os TEXT NOT NULL DEFAULT '',
  kernel TEXT NOT NULL DEFAULT '',
  agent_version TEXT NOT NULL DEFAULT '',
  last_seen INTEGER NOT NULL DEFAULT 0,
  cert_fingerprint TEXT NOT NULL DEFAULT '',
  enrolled_at INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'unknown',
  score REAL NOT NULL DEFAULT -1,
  grade TEXT NOT NULL DEFAULT ''
);

CREATE TABLE ssh_keys (
  server_id TEXT NOT NULL DEFAULT 'local',
  fingerprint TEXT NOT NULL,
  user TEXT NOT NULL,
  type TEXT NOT NULL,
  bits INTEGER NOT NULL DEFAULT 0,
  label TEXT NOT NULL DEFAULT '',
  comment TEXT NOT NULL DEFAULT '',
  options TEXT NOT NULL DEFAULT '',
  public_key TEXT NOT NULL DEFAULT '',
  owner_person TEXT NOT NULL DEFAULT '',
  added_at INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL DEFAULT 0,
  last_used_at INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (server_id, user, fingerprint)
);
CREATE INDEX ssh_keys_fp ON ssh_keys(fingerprint);

CREATE TABLE people (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE TABLE person_keys (
  person_id TEXT NOT NULL REFERENCES people(id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL,
  public_key TEXT NOT NULL,
  login_user TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (person_id, fingerprint)
);
CREATE TABLE person_groups (
  person_id TEXT NOT NULL REFERENCES people(id) ON DELETE CASCADE,
  group_name TEXT NOT NULL,
  PRIMARY KEY (person_id, group_name)
);

CREATE TABLE ssh_changes (
  id TEXT PRIMARY KEY,
  server_id TEXT NOT NULL DEFAULT 'local',
  actor TEXT NOT NULL,
  setting TEXT NOT NULL,
  old_value TEXT NOT NULL DEFAULT '',
  new_value TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  ts INTEGER NOT NULL,
  deadline INTEGER NOT NULL DEFAULT 0,
  backup_path TEXT NOT NULL DEFAULT ''
);

CREATE TABLE scans (
  id TEXT PRIMARY KEY,
  server_id TEXT NOT NULL DEFAULT 'local',
  started_at INTEGER NOT NULL,
  finished_at INTEGER NOT NULL DEFAULT 0,
  score REAL NOT NULL,
  grade TEXT NOT NULL,
  results TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX scans_server ON scans(server_id, started_at);

CREATE TABLE fixes (
  id TEXT PRIMARY KEY,
  server_id TEXT NOT NULL DEFAULT 'local',
  check_id TEXT NOT NULL,
  diff TEXT NOT NULL DEFAULT '',
  backup_path TEXT NOT NULL DEFAULT '',
  applied_by TEXT NOT NULL,
  applied_at INTEGER NOT NULL,
  reverted_at INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'applied'
);

CREATE TABLE harden_ignores (
  server_id TEXT NOT NULL DEFAULT 'local',
  check_id TEXT NOT NULL,
  reason TEXT NOT NULL CHECK (length(trim(reason)) > 0),
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (server_id, check_id)
);

CREATE TABLE alert_rules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  expr TEXT NOT NULL,
  for_s INTEGER NOT NULL DEFAULT 0,
  severity TEXT NOT NULL,
  channels TEXT NOT NULL DEFAULT '[]',
  enabled INTEGER NOT NULL DEFAULT 1,
  tags TEXT NOT NULL DEFAULT '[]',
  builtin INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE alert_events (
  id TEXT PRIMARY KEY,
  rule_id TEXT NOT NULL,
  server_id TEXT NOT NULL DEFAULT 'local',
  fingerprint TEXT NOT NULL,
  state TEXT NOT NULL,
  severity TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '',
  started_at INTEGER NOT NULL,
  acked_at INTEGER NOT NULL DEFAULT 0,
  acked_by TEXT NOT NULL DEFAULT '',
  resolved_at INTEGER NOT NULL DEFAULT 0,
  last_sent_at INTEGER NOT NULL DEFAULT 0,
  noise INTEGER NOT NULL DEFAULT 0,
  payload TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX alert_events_open ON alert_events(fingerprint, state);
CREATE INDEX alert_events_started ON alert_events(started_at);

CREATE TABLE silences (
  id TEXT PRIMARY KEY,
  matcher TEXT NOT NULL,
  starts_at INTEGER NOT NULL,
  ends_at INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT ''
);

CREATE TABLE channels (
  name TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  config TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL DEFAULT '',
  totp_secret TEXT NOT NULL DEFAULT '',
  totp_enabled INTEGER NOT NULL DEFAULT 0,
  role TEXT NOT NULL,
  failed_logins INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  oidc_subject TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL,
  ip TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE api_tokens (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  hash TEXT NOT NULL UNIQUE,
  scopes TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL DEFAULT 0,
  last_used_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  before TEXT NOT NULL DEFAULT '',
  after TEXT NOT NULL DEFAULT '',
  ts INTEGER NOT NULL,
  source_ip TEXT NOT NULL DEFAULT '',
  server_id TEXT NOT NULL DEFAULT 'local'
);
CREATE INDEX audit_ts ON audit(ts);
-- +goose StatementBegin
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit
WHEN OLD.ts > CAST(strftime('%s','now') AS INTEGER) - 31536000
BEGIN SELECT RAISE(ABORT, 'audit entries younger than 1 year cannot be deleted'); END;
-- +goose StatementEnd

CREATE TABLE enrollment_tokens (
  hash TEXT PRIMARY KEY,
  server_name TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE fleet_ops (
  id TEXT PRIMARY KEY,
  server_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'pending',
  result TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  done_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX fleet_ops_pending ON fleet_ops(server_id, status);

CREATE TABLE kv (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- +goose Down
DROP TABLE kv;
DROP TABLE fleet_ops;
DROP TABLE enrollment_tokens;
DROP TRIGGER audit_no_delete;
DROP TRIGGER audit_no_update;
DROP TABLE audit;
DROP TABLE api_tokens;
DROP TABLE sessions;
DROP TABLE users;
DROP TABLE channels;
DROP TABLE silences;
DROP TABLE alert_events;
DROP TABLE alert_rules;
DROP TABLE harden_ignores;
DROP TABLE fixes;
DROP TABLE scans;
DROP TABLE ssh_changes;
DROP TABLE person_groups;
DROP TABLE person_keys;
DROP TABLE people;
DROP TABLE ssh_keys;
DROP TABLE servers;
