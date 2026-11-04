-- +goose Up
-- central server: the latest site inventory each agent reported (JSON of pb.Sites)
CREATE TABLE fleet_sites (
  server_id TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

-- +goose Down
DROP TABLE fleet_sites;
