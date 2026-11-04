-- +goose Up
CREATE TABLE site_changes (
  id TEXT PRIMARY KEY,
  server_id TEXT NOT NULL DEFAULT 'local',
  actor TEXT NOT NULL,
  site_id TEXT NOT NULL,
  site_name TEXT NOT NULL,
  kind TEXT NOT NULL,
  action TEXT NOT NULL,
  ops TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  error TEXT NOT NULL DEFAULT '',
  ts INTEGER NOT NULL
);
CREATE INDEX site_changes_ts ON site_changes(ts);

-- +goose Down
DROP TABLE site_changes;
