# Configuration reference

Kurogane reads one YAML file, `/etc/kurogane/config.yaml` by default (`--config` selects another path).
`sudo krgn init` writes a starting file, and `deploy/config.example.yaml` holds an annotated example. The agent
(`kurogane agent run`) and the central server (`kurogane server run`) share the same file format: each one reads
the sections it needs and ignores the rest.

The file is read once at startup. Apply changes with `sudo systemctl restart kurogane` (agent) or
`sudo systemctl restart kurogane-server` (central server). An invalid file stops the service from starting, and
the error names the offending key: check it with `journalctl -u kurogane -n 20`.

## Conventions

- **Durations** accept Go syntax (`90s`, `10m`, `1h30m`) plus `d` for days and `w` for weeks (`7d`, `2w`). A bare
  integer is read as seconds.
- **Lists** accept YAML lists (`[nginx, mysql]`) or a comma-separated string (`"nginx, mysql"`).
- **Environment overrides:** every key can be overridden by an environment variable named `KRGN_` followed by the
  upper-case key path, with dots replaced by underscores. For example, `KRGN_LISTEN=127.0.0.1:9000` overrides
  `listen`, and `KRGN_COLLECTOR_INTERVAL=30s` overrides `collector.interval`. An override only takes effect for a
  key that has a default value or that is present in the file. Set variables for the service through a systemd
  drop-in (`systemctl edit kurogane`).
- **Secrets:** `krgn init` and `krgn alert channels add` seal webhook URLs with `secret_key` (values starting with
  `enc:`). A plain URL in the file also works, but it stays readable to anyone who can read the file.
  `webhook_url_env` keeps the secret out of the file.

## Contents

- [Top-level keys](#top-level-keys)
- [`tls`](#tls)
- [`collector`](#collector)
- [`ssh`](#ssh)
- [`harden`](#harden)
- [`alerts`](#alerts)
- [`web`](#web)
- [`auth`](#auth)
- [`central`](#central) (agent side of a fleet)
- [`server`](#server) (central server only)
- [`telemetry`](#telemetry)
- [Complete example](#complete-example)

## Top-level keys

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `server_name` | string | host name | Name shown in the UI, in alert messages and to the central server. |
| `tags` | list | `[]` | Free-form labels. The central server uses them for filtering and for `tag:` alert routing. |
| `listen` | host:port | `127.0.0.1:9443` | Address of the agent web UI and API. A non-loopback address requires `tls.cert`, `tls.key` and `tls.allow_remote: true`. |
| `data_dir` | path | `/var/lib/kurogane` | Holds `kurogane.db` (metadata), `agent.db` (metrics) and `backups/`. |
| `dashboard_url` | URL | empty | Public dashboard address. When set, alert messages link to the alert in the UI. |
| `secret_key` | path | `/etc/kurogane/secret.key` | Key used to seal webhook URLs and other secrets. Created on first use; it must be mode `0600`. |
| `privsep` | bool | `true` | Runs the API, collectors and rules in an unprivileged worker under the `kurogane` user, while a root parent executes an allowlist of typed operations. It only takes effect when the agent starts as root and the `kurogane` user exists. |

## `tls`

TLS for the web UI and API. Only TLS 1.3 is offered.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tls.cert` | path | empty | PEM certificate (chain). Setting it switches the listener to HTTPS. |
| `tls.key` | path | empty | PEM private key for `tls.cert`. |
| `tls.allow_remote` | bool | `false` | Explicit consent to listen on a non-loopback address. Required together with `cert` and `key` whenever `listen` is not loopback. |

## `collector`

Metric collection on the agent.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `collector.interval` | duration | `10s` | Sampling interval. Allowed range: `1s` to `60s`. |
| `collector.retention_raw` | duration | `24h` | How long raw samples are kept. |
| `collector.retention_rollup` | duration | `7d` | How long downsampled (rollup) samples are kept. |
| `collector.watch_services` | list | `[]` | systemd units to monitor (`service_down` alert). nginx and Apache units are added automatically when `web.enabled` is true. |
| `collector.nginx_log` | path | empty | nginx access log to tail for the HTTP 4xx/5xx rate and the top HTTP client IPs shown in the `ddos` alert and `krgn top`. Empty disables it. See [Behind Cloudflare](#behind-cloudflare). |
| `collector.prometheus` | bool | `false` | Exposes `GET /metrics` in Prometheus format (metric prefix `kurogane_`). Requires a token with the `read` scope. |

### `collector.certs`

TLS certificate expiry monitoring. Let's Encrypt lineages, nginx `ssl_certificate` and Apache
`SSLCertificateFile` are discovered automatically.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `collector.certs.enabled` | bool | `true` | Turns certificate monitoring and the `TLS-CERT-VALID` check on or off. |
| `collector.certs.paths` | list | `[]` | Extra PEM certificate files to watch. Files named like private keys are never read. |
| `collector.certs.probe_ports` | list of ints | `[443]` | Local ports to probe with a TLS handshake, to see which certificate is really served. `[]` disables probing. |
| `collector.certs.interval` | duration | `1h` | Rescan interval. Minimum `1m`. |

### `collector.redis`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `collector.redis.enabled` | `auto` / `true` / `false` | `auto` | `auto` monitors a Redis whose config file exists and whose unit is enabled or whose port answers. `true` always tries; `false` disables Redis monitoring. |
| `collector.redis.instances` | list | `[]` | Explicit instances. Empty means autodetect from `/etc/redis/redis*.conf` and `/etc/redis.conf`, using their `requirepass`. |

Each entry of `collector.redis.instances`:

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `name` | string | no | Display name. |
| `addr` | string | yes | `host:port` or `unix:/path/to/socket`. |
| `username` | string | no | ACL user. A read-only user is recommended: `ACL SETUSER kurogane on >PASSWORD -@all +ping +info +slowlog\|get`. |
| `password_file` | path | no | File that holds the password. The password is only kept in memory. |
| `tls` | bool | no | Connects with TLS. |

## `ssh`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ssh.config_path` | path | `/etc/ssh/sshd_config` | Main sshd configuration file. |
| `ssh.rollback_timeout` | duration | `120s` | Time allowed to run `krgn ssh confirm` after an sshd change before it is rolled back. Minimum `10s`. |

### `ssh.bruteforce`

Bans source addresses that fail SSH authentication repeatedly.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ssh.bruteforce.enabled` | bool | `false` | Enables banning. `krgn init` writes `true`. |
| `ssh.bruteforce.max_failures` | int | `5` | Failed attempts within `window` that trigger a ban. |
| `ssh.bruteforce.window` | duration | `10m` | Counting window for failures. |
| `ssh.bruteforce.ban_for` | duration | `1h` | Ban duration. |
| `ssh.bruteforce.allowlist` | list of CIDRs | `[]` | Addresses that are never banned (also applies to `alerts.auto_ban`). |

### `ssh.ca`

Limits for SSH user certificates issued by the SSH CA (`krgn ssh ca init`).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ssh.ca.default_ttl` | duration | `8h` | Validity used when a certificate request gives no TTL. |
| `ssh.ca.max_ttl` | duration | `24h` | Longest validity that may be requested. |

## `harden`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `harden.schedule` | cron | `"0 3 * * *"` | When the scheduled hardening scan runs (standard 5-field cron, local time). An invalid value is logged and replaced by the default. |
| `harden.ignore` | list | `[]` | Checks to exclude from the score. Each entry needs `id` and a non-empty `reason`. |
| `harden.packs` | list of dirs | `[]` | Directories of custom check packs (`*.yaml` / `*.yml`). |
| `harden.expected_ports` | list of ints | `[]` | Listening ports that the firewall check treats as intended. |

`harden.ignore` example:

```yaml
harden:
  ignore:
    - id: SSH-PORT-NONDEFAULT
      reason: "Port 22 is required by the provider console"
```

A check pack file holds a `checks` list. Supported `type` values are `file_mode`, `file_contains`,
`file_not_contains`, `sysctl`, `service_active`, `service_inactive` and `command_output`. Automatic fixes
(`fix: true`) are available for `sysctl` and `file_mode` only. Check IDs must not collide with built-in IDs.

```yaml
checks:
  - id: CUSTOM-IP-FORWARD
    type: sysctl
    severity: medium
    title: IP forwarding off
    rationale: This host does not route traffic.
    remediation: Set net.ipv4.ip_forward = 0.
    key: net.ipv4.ip_forward
    value: "0"
    fix: true
```

## `alerts`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `alerts.channels` | list | `[]` | Delivery channels (see below). Channels added in the UI or with `krgn alert channels add` are stored in the database and used as well. |
| `alerts.rules` | list | `[]` | Custom rules (see below). |
| `alerts.repeat_interval` | duration | `30m` | Reminder interval for an alert that is still firing. `updates_pending`, `cert_expiring` and `cert_stale_served` always remind daily. |
| `alerts.rate_limit` | int | `20` | Maximum messages per minute per channel. `0` disables the limit. |
| `alerts.thresholds` | map | `{}` | Overrides the threshold of a built-in rule, keyed by rule ID (for example `high_cpu: 80`). |
| `alerts.disable_builtin` | list | `[]` | Built-in rule IDs to disable. |
| `alerts.routing` | map | `{}` | Central server only: which channels receive which alerts (see below). |
| `alerts.new_login_only_new_ip` | bool | `false` | Sends `ssh_login` only for logins from an address not seen before. |
| `alerts.new_login_only_root` | bool | `false` | Sends `ssh_login` only for logins as `root`. |
| `alerts.auto_ban` | map | see below | Automatic firewall bans during a suspected DDoS. |

### Channels

Each entry of `alerts.channels` needs a unique `name` and a `type`.

| Key | Used by | Description |
|-----|---------|-------------|
| `name` | all | Unique channel name, referenced by rules and routing. |
| `type` | all | `slack`, `discord`, `telegram`, `email`, `pagerduty` or `webhook`. |
| `webhook_url` | all | The channel secret, ideally sealed (`enc:...`). See the table below for its meaning per type. |
| `webhook_url_env` | all | Name of an environment variable that holds the secret. It takes precedence over `webhook_url`. |
| `chat_id` | `telegram` | Target chat ID. Required. |
| `smtp_addr` | `email` | SMTP server as `host:port`. The server must offer STARTTLS; mail is never sent in clear text. |
| `smtp_user` | `email` | SMTP user name. When set, the password is read from the secret. |
| `from` | `email` | Sender address. Required. |
| `to` | `email` | List of recipient addresses. Required. |

Meaning of the secret (`webhook_url` or `webhook_url_env`) per type:

| Type | Secret |
|------|--------|
| `slack` | Incoming webhook URL. |
| `discord` | Webhook URL. |
| `webhook` | URL that receives a JSON `POST` for each alert. |
| `telegram` | Bot API base URL, `https://api.telegram.org/bot<TOKEN>`. |
| `pagerduty` | Events API v2 routing (integration) key. |
| `email` | SMTP password (only when `smtp_user` is set). |

```yaml
alerts:
  channels:
    - name: ops
      type: slack
      webhook_url_env: KRGN_SLACK_OPS
    - name: oncall
      type: telegram
      webhook_url: "enc:..."
      chat_id: "-1001234567890"
    - name: mail
      type: email
      smtp_addr: smtp.example.com:587
      smtp_user: alerts@example.com
      webhook_url_env: KRGN_SMTP_PASSWORD
      from: alerts@example.com
      to: [ops@example.com]
```

### Rules

Each entry of `alerts.rules` defines a custom rule, or replaces a built-in rule with the same ID.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `id` | string | yes | Unique rule ID. |
| `name` | string | no | Title used in messages. Defaults to the ID. |
| `expr` | string | yes | Condition over metrics, for example `mem.available_pct < 10` or `disk.used_pct{mount="/"} > 85`. Conditions can be combined with `and`, `or` and brackets. |
| `for` | duration | no | How long the condition must hold before the alert fires. |
| `severity` | string | yes | `info`, `warning` or `critical`. |
| `channels` | list | no | Channel names. |
| `enabled` | bool | no | Defaults to `true`. |
| `tags` | list | no | Free-form labels. |

Built-in rules whose threshold can be changed with `alerts.thresholds` (default in parentheses): `high_cpu` (90),
`mem_available_low` (10), `disk_full` (85), `disk_full_projected` (24 hours), `high_iowait` (30), `high_traffic`
(3 times the baseline), `ddos` (500 SYN_RECV), `cert_expiring` (14 days), `redis_down` (1), `redis_memory_high`
(90), `redis_evicting` (0), `redis_clients_high` (80) and `redis_slow` (50 ms). Other built-in rules that can be
disabled with `alerts.disable_builtin`: `oom_kill`, `service_down`, `updates_pending`, `cert_stale_served`,
`redis_persistence_failing`, `redis_replication_broken`, `ssh_bruteforce`, `ssh_login`, `ssh_config_changed`,
`ssh_rolled_back`, `hardening_drift`, `agent_offline`, `web_config_invalid` and `site_change_rolled_back`.

Threshold edits made in the UI are kept across restarts unless `alerts.thresholds` sets the same rule.

The metrics a rule can use, with what each measures, where it comes from, its unit and labels, are listed under
Alerts → Rules → Metrics reference, and by `GET /api/v1/alerts/metrics`. The rule builder in the UI picks the metric,
label filter, comparison and threshold from that list, and writes the same `expr`. Rules created or edited through the
UI or API must use metrics and labels from it. Rules in `config.yaml` are only checked for syntax, and a rule that
mixes `and` with `or` is shown read-only in the builder.

### Routing (central server)

`alerts.routing` maps a key to a list of channel names. Supported keys are a severity (`critical`, `warning`,
`info`), `rule:<id>`, `server:<name>`, `tag:<tag>` and `default`. An alert goes to the union of every matching key.
If nothing matches, it goes to `default`. If `routing` is empty, it goes to every channel.

```yaml
alerts:
  routing:
    critical: [oncall]
    tag:db: [dba]
    default: [ops]
```

### `alerts.auto_ban`

Bans the top offending source addresses while a DDoS is suspected. Off by default. Host-level banning cannot stop
volumetric attacks; those need upstream mitigation.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `alerts.auto_ban.enabled` | bool | `false` | Enables automatic bans. Only addresses with at least 50 concurrent connections are banned. |
| `alerts.auto_ban.duration` | duration | `30m` | Ban duration. |
| `alerts.auto_ban.max_bans` | int | `50` | Maximum number of automatic bans per agent run. `0` removes the cap. |
| `alerts.auto_ban.allowlist` | list of CIDRs | `[]` | Addresses that are never banned. `ssh.bruteforce.allowlist` also applies. |
| `alerts.auto_ban.rate_limit` | bool | `false` | Reserved. It currently has no effect. |

Cloudflare edge addresses are never banned automatically: a ban would block every visitor routed through that edge.
Behind Cloudflare, visitor addresses never reach the host firewall either, so offenders must be blocked in Cloudflare
(WAF or rate limiting rules).

### Behind Cloudflare

Behind Cloudflare, every TCP connection comes from a Cloudflare edge, so the `ddos` alert marks those addresses with
`Cloudflare` and lists the real visitor addresses under "Top HTTP clients (real IP)". The real address comes from the
`CF-Connecting-IP` request header, which nginx must log. Use one of the following setups.

Append the header as the last quoted field of the log format:

```nginx
log_format cf '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent '
              '"$http_referer" "$http_user_agent" "$http_cf_connecting_ip"';
access_log /var/log/nginx/access.log cf;
```

The agent uses that field only when `$remote_addr` is a published Cloudflare address, so a forged header sent
directly to the origin is ignored. Alternatively, let nginx rewrite `$remote_addr` with the `realip` module, adding
one `set_real_ip_from` line per range listed at <https://www.cloudflare.com/ips/>:

```nginx
set_real_ip_from 173.245.48.0/20;
# one line per published range
real_ip_header CF-Connecting-IP;
```

The agent ships the Cloudflare ranges published on 2026-11-11. `CF-Connecting-IPv6` (Pseudo IPv4) and Apache logs are
not supported.

## `web`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `web.enabled` | bool | `true` | nginx and Apache site inventory, periodic config tests, safe enable/disable and the `WEB-*` hardening checks. |

## `auth`

Applies to both the agent and the central server.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `auth.session_ttl` | duration | `12h` | Lifetime of a web UI session. |

### `auth.oidc`

Optional single sign-on. OIDC is enabled when `issuer` is set.

| Key | Type | Description |
|-----|------|-------------|
| `auth.oidc.issuer` | URL | OIDC issuer URL (discovery is used). |
| `auth.oidc.client_id` | string | OAuth client ID. |
| `auth.oidc.client_secret_env` | string | Name of the environment variable that holds the client secret. |
| `auth.oidc.redirect_url` | URL | Callback URL registered with the provider: `<dashboard>/api/v1/auth/oidc/callback`. |
| `auth.oidc.admin_group` | string | Members of this group (case-insensitive) receive the admin role. |

## `central`

Agent side of a fleet. Leave this section out for a standalone server.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `central.addr` | host:port | empty | gRPC address of the central server, for example `central.example.com:9444`. |
| `central.enrollment_token` | string | empty | One-time token from `krgn server token create`. Only needed for the first connection; the token embeds a pin of the central CA. |
| `central.ca_file` | path | empty | PEM CA certificate of the central server. When set, it replaces the pin in the token. |

## `server`

Central server only (`kurogane server run`). The central server also reads `tls`, `alerts.channels`,
`alerts.routing`, `auth`, `dashboard_url`, `data_dir` and `secret_key`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `server.grpc_listen` | host:port | `0.0.0.0:9444` | Address where agents connect (mutual TLS). |
| `server.http_listen` | host:port | `127.0.0.1:9443` | Web UI and API. A non-loopback address requires `tls.cert` and `tls.key`. |
| `server.offline_after` | duration | `2m` | Silence after which an agent is marked offline and `agent_offline` fires. |
| `server.audit_retention` | duration | `8760h` | How long audit log entries are kept (one year). |

### `server.vm`

VictoriaMetrics, which stores fleet metrics.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `server.vm.url` | URL | `http://127.0.0.1:8428` | VictoriaMetrics HTTP address. |
| `server.vm.mode` | `systemd` / `child` | `systemd` | `systemd` runs it as its own unit; `child` starts it as a child process of the central server. |
| `server.vm.binary` | path | `/usr/local/bin/victoria-metrics-prod` | Binary installed by `krgn server init`. |
| `server.vm.retention` | duration | `90d` | Metric retention. |
| `server.vm.data_dir` | path | `/var/lib/kurogane/vm` | VictoriaMetrics data directory. |

### `server.backup`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `server.backup.dest` | path | `<data_dir>/backups` | Backup destination directory. |
| `server.backup.schedule` | cron | `"30 2 * * *"` | When the nightly backup runs. |
| `server.backup.keep` | int | `7` | Number of backups to keep. |

## `telemetry`

Opt-in onboarding timing (installation time and first dashboard view). Nothing is sent unless both keys are set.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `telemetry.enabled` | bool | `false` | Enables telemetry. |
| `telemetry.url` | URL | empty | Endpoint that receives the report. |

## Complete example

A standalone agent with every section shown. Values are the defaults unless noted.

```yaml
server_name: web-01
tags: [prod, web]
listen: 127.0.0.1:9443
data_dir: /var/lib/kurogane
# dashboard_url: https://web-01.example.com:9443
secret_key: /etc/kurogane/secret.key
privsep: true

# tls:
#   cert: /etc/kurogane/tls/cert.pem
#   key: /etc/kurogane/tls/key.pem
#   allow_remote: true

collector:
  interval: 10s
  retention_raw: 24h
  retention_rollup: 7d
  watch_services: [nginx, mysql]
  # nginx_log: /var/log/nginx/access.log
  prometheus: false
  certs:
    enabled: true
    paths: []
    probe_ports: [443]
    interval: 1h
  redis:
    enabled: auto
    instances: []

ssh:
  config_path: /etc/ssh/sshd_config
  rollback_timeout: 120s
  bruteforce:
    enabled: true
    max_failures: 5
    window: 10m
    ban_for: 1h
    allowlist: [203.0.113.10/32]
  ca:
    default_ttl: 8h
    max_ttl: 24h

harden:
  schedule: "0 3 * * *"
  ignore: []
  packs: []
  expected_ports: [22, 80, 443]

alerts:
  channels:
    - name: ops
      type: slack
      webhook_url_env: KRGN_SLACK_OPS
  rules:
    - id: load_high
      expr: cpu.total_pct > 95
      for: 10m
      severity: critical
      channels: [ops]
  repeat_interval: 30m
  rate_limit: 20
  thresholds: {high_cpu: 85}
  disable_builtin: []
  new_login_only_new_ip: false
  new_login_only_root: false
  auto_ban:
    enabled: false
    duration: 30m
    max_bans: 50
    allowlist: []

web:
  enabled: true

auth:
  session_ttl: 12h

telemetry:
  enabled: false

# fleet member:
# central:
#   addr: central.example.com:9444
#   enrollment_token: <token from `krgn server token create`>
```
