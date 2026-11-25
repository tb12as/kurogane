# Kurogane internal contracts

Shared agreements between packages. Source of truth for requirements: `docs/PRD.md`.

## Conventions

- Module `github.com/tb12as/kurogane`, `CGO_ENABLED=0`, Go stdlib `log/slog` for logs.
- Every host path read goes through `hostfs.P()` / `hostfs.Read()` so tests can use fixture trees (`KRGN_ROOT`).
- Every privileged write or command goes through `executor.Executor` (allowlist in `internal/executor/executor.go`).
  Add a command to the allowlist only if strictly needed, with the narrowest first-argument list.
- Every mutating action records `audit.Logger.Record(ctx, action, target, before, after)`.
- Errors shown to users state the cause and the next step (PRD §11.5).
- Tests use `executor.NewFake()` + `hostfs.Root = t.TempDir()`; never touch the real host.
- API routes: register from `init()` via `api.Register(func(s *api.Server){ s.Route("GET /path", scope, h) })`.
  Paths are relative to `/api/v1`. Scopes: `auth.ScopeRead`, `auth.ScopeSSH`, `auth.ScopeHarden`, `auth.ScopeAdmin`.
  Alert/fleet/user mutations need `admin`.
- OpenAPI: each domain writes `internal/api/openapi/<domain>.yaml` (a `paths:` + `components.schemas:` fragment);
  they are merged into `internal/api/openapi.yaml`.
- CLI: each domain adds cobra commands in `cmd/kurogane/<domain>.go` via `init(){ rootCmd.AddCommand(...) }`,
  using the `client` in `cmd/kurogane/client.go` (thin client over the REST API). Honor `--json`.

## Metric catalog (collector → store/alerts/UI)

Names are dotted; labels in braces. `_pct` = 0 to 100, `_bps` = bytes/s, `_ps` = per second.

| Group | Metrics |
| --- | --- |
| CPU | `cpu.total_pct`, `cpu.user_pct`, `cpu.system_pct`, `cpu.iowait_pct`, `cpu.steal_pct`, `cpu.core_pct{core}`, `load.1`, `load.5`, `load.15` |
| Memory | `mem.total_bytes`, `mem.used_bytes`, `mem.used_pct`, `mem.available_bytes`, `mem.available_pct`, `mem.cached_bytes`, `mem.buffers_bytes`, `swap.total_bytes`, `swap.used_bytes`, `swap.used_pct`, `mem.oom_kills` (counter), `mem.oom_kills_delta` (new since last sample) |
| Disk space | `disk.used_pct{mount}`, `disk.used_bytes{mount}`, `disk.total_bytes{mount}`, `disk.free_bytes{mount}`, `disk.inodes_used_pct{mount}` |
| Disk I/O | `diskio.read_bps{dev}`, `diskio.write_bps{dev}`, `diskio.read_iops{dev}`, `diskio.write_iops{dev}`, `diskio.await_ms{dev}`, `diskio.util_pct{dev}` |
| Network | `net.rx_bps{iface}`, `net.tx_bps{iface}`, `net.rx_pps{iface}`, `net.tx_pps{iface}`, `net.rx_errors_ps{iface}`, `net.tx_errors_ps{iface}`, `net.rx_drops_ps{iface}`, `net.tx_drops_ps{iface}`, totals over non-loopback: `net.rx_bps_total`, `net.tx_bps_total`, `net.rx_pps_total`, `net.tx_pps_total`, `net.udp_pps` |
| Connections | `net.tcp.established`, `net.tcp.syn_recv`, `net.tcp.syn_sent`, `net.tcp.time_wait`, `net.tcp.close_wait`, `net.tcp.fin_wait`, `net.tcp.listen`, `net.tcp.total`, `net.new_conns_ps`, `net.conns_per_ip_max`, `net.conns_per_subnet_max`, `net.listening_ports` |
| Processes | `proc.total`, `proc.running`, `proc.zombies`, `proc.threads` |
| System | `sys.uptime_s`, `sys.reboot_required` (0/1), `sys.security_updates`, `sys.pending_updates` |
| Services | `service.active{unit}` (1 active, 0 otherwise) |
| Agent self | `agent.cpu_pct`, `agent.rss_bytes`, `agent.collect_lag_ms`, `agent.goroutines`, `agent.store_bytes` |
| HTTP (opt-in nginx tail) | `http.rps`, `http.4xx_ps`, `http.5xx_ps`, `http.ip_path_max_1m`, `http.path_max_1m` (sliding last-minute maxima for one client IP -> request and one request from all clients) |
| Redis (`collector.redis`), label `instance` | `redis.up`, `redis.ping_ms`, `redis.uptime_s`, `redis.memory_used_bytes`, `redis.memory_rss_bytes`, `redis.maxmemory_bytes`, `redis.memory_used_pct` (only with maxmemory), `redis.fragmentation_ratio`, `redis.clients`, `redis.clients_pct`, `redis.blocked_clients`, `redis.rdb_ok`, `redis.rdb_changes_since_save`, `redis.rdb_last_save_age_s`, `redis.aof_ok` (only with AOF), `redis.replicas` (primary), `redis.replica_link_up` and `redis.replica_last_io_s` (replica), `redis.keys{instance,db}`, `redis.keys_total`; rates (skipped across a restart): `redis.ops_ps`, `redis.hit_ratio` (percent, only with lookups), `redis.evicted_keys_ps`, `redis.expired_keys_ps`, `redis.rejected_connections_ps`, `redis.net_in_bps`, `redis.net_out_bps`. A *needs_credentials* instance emits nothing. |
| Web servers (`web.enabled`) | `web.config_ok{server}` (1 when `nginx -t` / `apachectl configtest` passes), `web.sites{server,state}` (state enabled or disabled) |
| TLS certificates (`collector.certs`) | `cert.days_left{name}` (negative once expired, recomputed every tick from an hourly scan), `cert.stale_served{name}` (1 when a probed port serves an older certificate for the same names) |

Details that are not numbers live in `collector.Snapshot` (`System`, `TopCPU`, `TopMem`, `Conns`, `Services`, `Mounts`,
`Certs`, `Redis`). The site inventory lives in `sites.Manager`, not the snapshot.

## Cross-package APIs

- `collector.NewManager(cfg config.Collector, ex) *Manager`; `Run(ctx, sink func(*Snapshot))`; `Latest() *Snapshot`;
  `Certs()` / `RescanCerts(ctx)` return the certificate scan and its time.
- `certs.Scan(ctx, r certs.Reader, certs.Options) []certs.Cert`: discovery (Let's Encrypt renewal configs and `live/`,
  nginx `ssl_certificate` and Apache `SSLCertificateFile` via `internal/webconf`, extra paths), leaf inspection and local TLS probes. Reads go through the
  executor so root-only certbot directories work under privsep. Only `CERTIFICATE` PEM blocks are decoded; paths
  naming private keys are never read.
- `redisinfo.Dial(ctx, Target) (*Conn, error)` (`ErrNoAuth` = needs a password we lack, `ErrAuth` = rejected);
  `Conn.Ping`, `Info`, `SlowLog(n)` (command names only); `ParseConfig(r, file)` reads redis.conf (bind, port, tls,
  socket, requirepass, protected-mode, rename-command, ACL users with passwords masked).
- `webconf.ParseNginx(r)` / `ParseApache(r) *Config` (nil when not configured): sites (`Block`) and every directive
  with file, line and context; `ParseNginxFile` / `ParseApacheFile` parse a disabled site file on its own.
- `sites.New(Deps) *Manager`; `Run(ctx)`; `Inventory()`; `Scan(ctx, test)`; `Plan(ctx, id, enable)`;
  `Apply(ctx, id, enable) (db.SiteChange, error)`; `Reload(ctx, kind)`; `Config(ctx, id)`; `Changes(ctx)`. Errors
  wrap `sites.ErrNotFound`, `ErrRefused` or `ErrBusy`. Toggles go through `Executor.LinkSite`, `UnlinkSite` and
  `RenameSite`, which only move files inside the sites-enabled/sites-available and conf.d directories.
- `firewall.New(ex) *Manager`; `Ban(ctx, ip, d, reason)`, `Unban(ctx, ip)`, `Bans() []Ban`, `Backend() string`.
- `alert.NewEngine(Deps) (*Engine, error)`; `Run(ctx)`; `Eval(ctx, *collector.Snapshot)`; `Fire(ctx, alert.Event)`.
  One-shot events set `Once: true`; conditions detected elsewhere fire and later send `Resolve: true` with the same
  `Rule` + `Labels`. Rule ids for externally fired events: `ssh_bruteforce`, `ssh_login`, `ssh_config_changed`,
  `ssh_rolled_back`, `hardening_drift`, `agent_offline`, `updates_pending`, `ddos`, `web_config_invalid`,
  `site_change_rolled_back`.
- `notify.New(config.Channel, *secret.Box) (Notifier, error)`; `Notifier.Send(ctx, notify.Alert) error`.
- `sshmgr.New(Deps) *Manager`; `Run(ctx)`; `Settings(ctx)`; `SafeApply(ctx, set, rollback)`; `AddKey`; `RemoveKey`;
  `BruteforceActive()`.
- `harden.New(Deps) *Service`; `Run(ctx)` (scheduler); `Scan(ctx) (db.Scan, error)`.
- Fleet-wide key revoke: CLI `ssh keys revoke <fp> --all-servers` calls `POST /fleet/keys/revoke {"fingerprint"}`
  on the central server API; push is `POST /fleet/keys/push {"person"|"group", "user"}`.
