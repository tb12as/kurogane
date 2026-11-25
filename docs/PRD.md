# Kurogane PRD: Go Server Management Agent

Nov 2, 2026 · @Syafiq Afifuddin

## 1. Overview

Kurogane (黒鉄, "black iron"; formerly the working name ServerKeeper) is a single Go binary that monitors a Linux server's health, manages SSH access, audits and hardens the server, and pushes alerts to Slack or Discord. It targets small teams and solo operators who run 1 to 50 servers and find Prometheus + Grafana + Ansible + fail2ban too much to assemble and maintain.

**Problem.** Operators of small fleets juggle separate tools for metrics, SSH key hygiene, CIS-style hardening and alerting. Keys of ex-staff linger in `authorized_keys`, `sshd_config` drifts, and nobody notices RAM pressure or a traffic spike until users complain.

**Vision.** Install one static binary, run `kurogane init`, and within five minutes get live metrics, a hardening score, a managed SSH key inventory and alerts in the team's chat channel.

**Document status:** Draft v0.1, open for review. Licensing and pricing are open questions (section 13). Sections 4 to 12
describe the original plan. Where shipped behavior differs (53 hardening checks, Telegram, email, PagerDuty and webhook
channels), the README and `docs/configuration.md` are authoritative.

## 2. Goals, non-goals and success metrics

**Goals**

1. Give real-time and historical visibility into CPU, memory, disk, I/O, network and process health with under 1% CPU overhead.
2. Make SSH access auditable and safe to change: who has which key, which `sshd_config` settings are active, and a rollback if a change locks you out.
3. Turn hardening into a repeatable score with one-click (or one-command) fixes, not a one-off script.
4. Alert the right channel within 60 seconds of a threshold breach or attack pattern, without alert spam.

**Non-goals (v1)**

- Windows or macOS servers. Linux only.
- Replacing a full SIEM, IDS (Suricata/Snort) or log aggregation stack.
- Application performance monitoring (traces, per-request latency).
- Configuration management of arbitrary packages and apps (Ansible territory).
- Inline DDoS mitigation at network scale. v1 detects and can apply host-level rate limits only.

**Success metrics**

| Metric | Target | Measured by |
| --- | --- | --- |
| Time from install to first dashboard | ≤ 5 min | Onboarding telemetry (opt-in) |
| Agent CPU overhead | < 1% avg on 2 vCPU | Benchmark suite |
| Agent memory (RSS) | < 50 MB | Benchmark suite |
| Alert latency (event → Slack/Discord) | p95 < 60 s | Synthetic alert tests |
| False-positive alerts | < 5% of alerts marked noise | "Mark as noise" button / ack data |
| Lockouts caused by SSH changes | 0 | Rollback watchdog logs |
| Avg hardening score after 30 days | +25 points vs first scan | Scan history |

## 3. Users and key user stories

| Persona | Context | Primary need |
| --- | --- | --- |
| Solo DevOps / freelancer | Runs 1 to 10 VPS for clients | One tool, minimal setup, phone alerts via Discord |
| Small-team SRE | 10 to 50 servers, 3 to 8 engineers with SSH access | Key inventory, onboarding/offboarding, audit trail |
| Security/compliance lead | Must show hardening evidence | Scores, reports, drift detection over time |
| Hosting reseller / MSP | Many customer servers | Multi-server view, per-server alert routing |

**User stories**

- As an operator, I want to see CPU, RAM, disk and network for the last 24 hours so I can spot trends before an outage.
- As an operator, I want a Slack message when RAM stays above 90% for 5 minutes so I can act before the OOM killer does.
- As a team lead, I want to revoke a departing engineer's key from every server with one command.
- As an admin, I want to disable password login safely, with automatic rollback if I lose access.
- As a security lead, I want a hardening score and a PDF/JSON report I can hand to an auditor.
- As an operator, I want an alert when inbound connections spike abnormally, with the top source IPs listed.
- As an operator, I want to silence an alert during a maintenance window.

## 4. Scope and release plan

The MVP is single-server and CLI + local web UI; multi-server management arrives in v1. Priorities use MoSCoW (P0 = must, P1 = should, P2 = could).

| Capability | MVP (single server) | v1 (fleet) | Later |
| --- | --- | --- | --- |
| Performance monitoring | P0: CPU, RAM, swap, disk, I/O, net, load, top processes; 7-day local history | P0: central server, 30-day history, multi-host dashboard | Prometheus `/metrics` export, custom plugins |
| SSH management | P0: key inventory, add/remove keys, sshd\_config viewer, safe-apply with rollback | P0: fleet-wide key push/revoke, user groups | Short-lived SSH certificates (CA) |
| Hardening | P0: \~40 checks, score, JSON report, `--fix` per check | P1: scheduled scans, drift alerts, PDF report | Custom check packs, CIS level 2 |
| Alerts | P1: threshold rules, Slack + Discord webhooks | P0: anomaly/DDoS detection, routing, silences | Telegram, email, PagerDuty, generic webhook |
| Access to the tool | P0: local CLI, web UI bound to localhost | P0: auth, RBAC, audit log | SSO (OIDC) |

## 5. Feature 1: Performance monitoring

The agent samples system metrics every 10 seconds (configurable from 1 to 60 s), stores them locally, and serves them to the CLI, the web UI and the alert engine. Collection uses `/proc` and `/sys` directly (via `gopsutil` where convenient), with no external daemons.

**Metrics collected**

| Group | Metrics | Source |
| --- | --- | --- |
| CPU | total %, per-core %, user/system/iowait/steal, load avg 1/5/15 | `/proc/stat`, `/proc/loadavg` |
| Memory | used, available, cached, buffers, swap used, OOM-kill count | `/proc/meminfo`, `/proc/vmstat` |
| Disk space | used % and inodes per mount point | `statfs` |
| Disk I/O | read/write bytes/s, IOPS, await, util % per device | `/proc/diskstats` |
| Network | rx/tx bytes/s, packets/s, errors, drops per interface | `/proc/net/dev` |
| Connections | TCP states (ESTABLISHED, SYN\_RECV, TIME\_WAIT), conns per remote IP, listening ports | netlink `sock_diag` / `/proc/net/tcp` |
| Processes | top 10 by CPU and RAM, zombie count, total processes | `/proc/[pid]` |
| System | uptime, kernel version, reboot required, pending security updates | `uname`, apt/dnf |
| Services | systemd unit state for a watch list (nginx, mysql, docker…) | D-Bus / `systemctl` |

**Requirements**

| ID | Requirement | Priority |
| --- | --- | --- |
| PM-1 | Sample all metric groups at a configurable interval (default 10 s) | P0 |
| PM-2 | Store raw samples for 24 h and 1-min rollups (avg/max) for 7 days in an embedded store | P0 |
| PM-3 | `kurogane top` shows a live terminal dashboard (like htop, plus net and disk) | P0 |
| PM-4 | Web UI shows time-series charts with 1h / 6h / 24h / 7d ranges | P0 |
| PM-5 | REST endpoint returns current and historical metrics as JSON | P0 |
| PM-6 | Watch list of systemd services; report state changes | P1 |
| PM-7 | Expose Prometheus `/metrics` endpoint (opt-in) | P2 |
| PM-8 | Agent self-metrics (own CPU, RAM, collection lag) | P1 |

**Acceptance:** On a 2 vCPU / 2 GB VPS the agent stays under 1% average CPU and 50 MB RSS at a 10 s interval, and a 7-day store stays under 200 MB.

## 6. Feature 2: SSH management

Kurogane owns the inventory of SSH keys and the `sshd_config` settings, and never applies an SSH change without a rollback path. Every change is logged with who, what, when and the previous value.

**6.1 Key management**

- Discover all `authorized_keys` files for every local user (including root) and parse type, bits, fingerprint (SHA256), comment and options.
- Flag weak keys: RSA < 3072 bits, DSA, duplicate keys across users, keys without a comment/owner label.
- Add, remove, label and expire keys. An expiry date removes the key automatically.
- Fleet mode (v1): assign keys to people and groups (`devs`, `ops`), then push or revoke across all servers in one command.
- Optional import of public keys from GitHub/GitLab usernames (`https://github.com/<user>.keys`).

**6.2 sshd\_config management**

Managed settings, each with a recommended value shown beside the current one:

| Setting | Recommended | Notes |
| --- | --- | --- |
| `Port` | custom (e.g. 2222) | Reduces log noise, not real security |
| `PermitRootLogin` | `no` or `prohibit-password` |  |
| `PasswordAuthentication` | `no` | Blocked unless at least one working key exists |
| `PubkeyAuthentication` | `yes` |  |
| `KbdInteractiveAuthentication` | `no` |  |
| `MaxAuthTries` | `3` |  |
| `LoginGraceTime` | `30` |  |
| `ClientAliveInterval` / `CountMax` | `300` / `2` | Drops idle sessions |
| `AllowUsers` / `AllowGroups` | explicit list |  |
| `X11Forwarding`, `AllowTcpForwarding` | `no` unless needed |  |
| `Ciphers`, `KexAlgorithms`, `MACs` | modern set only | Drop CBC, SHA1, diffie-hellman-group1 |

**6.3 Safe-apply flow (lockout protection)**

1. Write the candidate config to a temp file and validate it with `sshd -t -f <file>`.
2. Back up the current config with a timestamp.
3. Apply via `sshd_config.d/99-kurogane.conf` drop-in where supported, otherwise in-place, then reload (not restart) sshd.
4. Start a rollback timer (default 120 s). The operator confirms by opening a new SSH session and running `kurogane ssh confirm`, or clicking Confirm in the UI.
5. No confirmation before the timer ends → restore the backup and reload sshd automatically, and send an alert.

**6.4 Sessions and login audit**

- List active sessions (user, source IP, start time, TTY) and allow killing a session.
- Parse `auth.log` / journald for successful and failed logins; show top failing IPs and users.
- Optional built-in brute-force blocker (fail2ban-like) that bans an IP after N failures in M minutes via nftables/iptables, with an allowlist.

**Requirements**

| ID | Requirement | Priority |
| --- | --- | --- |
| SSH-1 | Inventory all authorized keys with fingerprint, owner label, last-used time (from auth logs) | P0 |
| SSH-2 | Add/remove/expire keys via CLI, UI and API | P0 |
| SSH-3 | Validate, back up and safe-apply sshd\_config with auto rollback | P0 |
| SSH-4 | Refuse to disable password auth or root login if it would leave no working login path | P0 |
| SSH-5 | Show active sessions and login history | P1 |
| SSH-6 | Brute-force IP banning with allowlist and ban expiry | P1 |
| SSH-7 | Fleet-wide key push/revoke by person or group | P0 (v1) |
| SSH-8 | SSH certificate authority with short-lived certs | P2 |

## 7. Feature 3: Server hardening scan and remediation

Hardening ships as a library of checks written in Go (not shell scripts), each with an ID, severity, rationale, a read-only `Check()` and an optional `Fix()`. Scans are read-only by default; fixes need an explicit flag or UI confirmation, and each fix records a backup so it can be reverted.

**7.1 Check catalog (MVP, \~40 checks)**

| Category | Example checks | Auto-fix |
| --- | --- | --- |
| SSH | Root login disabled, password auth off, strong ciphers, MaxAuthTries ≤ 4 | Yes (via safe-apply) |
| Accounts | No UID 0 besides root, no empty passwords, password aging set, sudoers without `NOPASSWD: ALL` | Partial |
| Firewall | ufw/nftables/firewalld active, default inbound deny, only expected ports open | Yes (with confirmation) |
| Updates | Unattended security updates enabled, no pending security updates, reboot not pending | Yes |
| Kernel / sysctl | `net.ipv4.tcp_syncookies=1`, `rp_filter=1`, ICMP redirects off, `kernel.randomize_va_space=2`, `fs.suid_dumpable=0` | Yes |
| File permissions | `/etc/shadow` 640 or stricter, no world-writable files in system dirs, unexpected SUID binaries | Partial |
| Services | No telnet/rsh/ftp, unused services disabled, listening services reviewed | Report only |
| Logging & audit | journald persistent, auditd installed, log rotation configured | Yes |
| Intrusion protection | fail2ban or built-in SSH ban active | Yes |
| Filesystem | `/tmp` mounted `noexec,nosuid` (if separate), core dumps restricted | Report only |
| Time | NTP / chrony synchronized | Yes |
| Malware basics (P2) | rkhunter/chkrootkit present, known-bad crontab entries | Report only |

Checks map to CIS Benchmark IDs where one exists, so reports can reference them.

**7.2 Scoring**

Score = 100 × (weighted passed checks / weighted applicable checks), weights Critical 10, High 5, Medium 3, Low 1. Grades: A ≥ 90, B ≥ 75, C ≥ 60, D < 60. Checks that do not apply (e.g. no separate `/tmp`) are excluded, not failed.

**7.3 Fix flow**

1. `kurogane harden scan` → table of results plus score.
2. `kurogane harden fix <check-id>` or `--all --severity high` → shows a dry-run diff first.
3. Operator confirms → backup taken → fix applied → check re-run to verify.
4. `kurogane harden revert <fix-id>` restores the backup.

**Requirements**

| ID | Requirement | Priority |
| --- | --- | --- |
| HD-1 | Run full scan in < 30 s on a typical VPS, read-only | P0 |
| HD-2 | Score, per-check status, rationale and remediation text | P0 |
| HD-3 | Dry-run diff before any fix; backup + revert per fix | P0 |
| HD-4 | Export report as JSON and Markdown; PDF in v1 | P0 / P1 |
| HD-5 | Scheduled scans (daily default) with drift alert when a passing check fails | P1 |
| HD-6 | Per-check ignore with mandatory reason (accepted risk) | P1 |
| HD-7 | Distro support: Ubuntu 22.04/24.04, Debian 12, RHEL/Rocky/Alma 9 | P0 |
| HD-8 | Custom check packs (YAML or Go plugin) | P2 |

## 8. Feature 4: Alerts and notifications (Slack / Discord)

An in-agent rule engine evaluates every sample against rules and sends alerts through Slack and Discord incoming webhooks. Each alert has a lifecycle (firing → acknowledged → resolved) so channels get one message per incident plus a resolve message, not a stream.

**8.1 Built-in event types**

| Event | Default rule | Severity |
| --- | --- | --- |
| High CPU | CPU > 90% for 5 min | Warning |
| RAM almost full | Available RAM < 10% for 5 min, or swap > 50% | Warning → Critical at < 5% |
| OOM kill | Any new OOM-kill event | Critical |
| Disk almost full | Mount > 85% (warn) / 95% (crit), or projected full in < 24 h | Warning / Critical |
| High I/O wait | iowait > 30% for 5 min | Warning |
| High traffic | rx or tx > 3× the 7-day baseline for the same hour, for 3 min | Warning |
| Possible SYN flood | SYN\_RECV > 500 | Critical |
| Possible DDoS: connection surge | New conns/s > 10× baseline, or a traffic anomaly | Critical |
| Connection flood from one client | One IP > 200 inbound ESTABLISHED or SYN\_RECV conns (outbound and closing sockets excluded) | Warning |
| SSH brute force | > 20 failed logins from one IP in 5 min | Warning |
| New SSH login | Successful login (optionally only from new IPs or as root) | Info |
| SSH config changed / rolled back | Any sshd change or rollback | Info / Critical |
| Service down | Watched systemd unit not active | Critical |
| Hardening drift | Previously passing check now fails | Warning |
| Agent offline (v1) | No heartbeat to central server for 2 min | Critical |
| Reboot required / security updates pending | Daily check | Info |

All thresholds are editable per server. Baselines are learned from 7 days of history; until then, static thresholds apply.

**8.2 DDoS / traffic anomaly detection (host level)**

- Signals: packets/s and bytes/s per interface, new connections/s, SYN\_RECV count, connections per source IP and per /24, UDP pps, HTTP 4xx/5xx rate from an optional nginx log tail.
- Method: rolling EWMA baseline plus seasonal (hour-of-week) baseline; alert when the z-score exceeds 4 and an absolute floor is crossed, to avoid alerts on idle servers.
- Alert body includes top 10 source IPs/subnets, top destination ports, and the current SYN cookie status.
- Optional auto-response (off by default): rate-limit or ban top offenders via nftables for N minutes, with allowlist and a hard cap on bans. Message clearly states that volumetric attacks need upstream mitigation (provider or CDN).

**8.3 Delivery and noise control**

- Channels: Slack incoming webhook (Block Kit message with color by severity), Discord webhook (embed). Also shipped: Telegram, email, generic webhook, PagerDuty.
- Routing: rule → channel mapping, e.g. Critical to `#ops-alerts`, Info to `#ops-log`.
- Dedup and grouping: one alert per (server, rule) while firing; repeat reminder every 30 min (configurable); a resolved message when it clears.
- Silences: by server, rule or tag, with start/end time, for maintenance windows.
- Rate limit: max 20 messages/min per channel; overflow collapsed into a summary.
- Retry with exponential backoff; alerts queued on disk if the network is down.
- `kurogane alert test <channel>` sends a test message.

**Example Slack/Discord message**

```
🔴 CRITICAL · web-01 · RAM almost full
Available memory 4.2% (168 MB of 4 GB) for 6 min
Top processes: java 2.1 GB, mysqld 1.2 GB, node 310 MB
Firing since 23:41 WIB · Rule: mem_available_low
[Open dashboard] [Silence 1h]
```

**Requirements**

| ID | Requirement | Priority |
| --- | --- | --- |
| AL-1 | Rule engine with threshold + duration conditions on any metric | P0 |
| AL-2 | Slack and Discord webhook delivery with severity formatting | P0 |
| AL-3 | Firing/resolved lifecycle, dedup, repeat interval | P0 |
| AL-4 | Silences and maintenance windows | P1 |
| AL-5 | Baseline anomaly detection for traffic and connections | P1 |
| AL-6 | Optional automatic IP rate-limit/ban on attack detection | P2 |
| AL-7 | Alert history view and export | P1 |
| AL-8 | Webhook URLs stored encrypted, never logged | P0 |

## 9. System architecture

In the MVP the agent runs alone and sends alerts itself; in v1 agents stream to a central server that stores fleet history and routes alerts.

The agent runs as a systemd service as root (needed for sshd and sysctl changes), with privileged actions isolated in one package and every action audited.

**Tech choices**

| Concern | Choice | Why |
| --- | --- | --- |
| Language | Go 1.26+, `CGO_ENABLED=0` static binary | One file to install on any distro |
| CLI | `spf13/cobra` + `viper` | Standard, subcommands, config binding |
| Metrics collection | `shirou/gopsutil` + direct `/proc` parsing | Mature, low overhead |
| Netlink / conntrack | `vishvananda/netlink`, `mdlayher/netlink` | Connection stats without shelling out |
| Firewall | `google/nftables` (fallback: iptables exec) | Native nftables API |
| Agent local storage | `go.etcd.io/bbolt` | Embedded, pure Go, bounded size |
| Central metrics store | VictoriaMetrics single-node, separate binary managed by Kurogane | High compression, PromQL queries, \~1 KB RAM per active series |
| Central metadata store | SQLite via `modernc.org/sqlite` | Embedded file, no CGO, nothing to install |
| Agent ↔ central | gRPC with mutual TLS, token-based enrollment | Streaming, strongly typed |
| Web UI | Nuxt (Vue 3, TypeScript) + Tailwind CSS + shadcn-vue, static build embedded via `embed.FS` | Ready-made tables, forms, dialogs and toasts; no Node.js on production servers |
| Charts | ECharts via `vue-echarts` | Canvas rendering with LTTB downsampling for long time series |
| Terminal UI | `charmbracelet/bubbletea` | For `kurogane top` |
| Logging | `log/slog` JSON | Standard library |

**Repository layout**

```
cmd/kurogane/        main, cobra commands (agent, server, CLI)
internal/collector/      cpu, mem, disk, net, proc collectors
internal/store/          agent bbolt store + rollups
internal/metricsdb/      VictoriaMetrics client (import, PromQL) + process supervisor
internal/db/             SQLite store, embedded migrations
internal/alert/          rules, baselines, lifecycle
internal/notify/         slack, discord (Notifier interface)
internal/sshmgr/         keys, sshd_config parser, safe-apply
internal/harden/         checks/ (one file per check), score, fix, revert
internal/firewall/       nftables/iptables abstraction, bans
internal/api/            REST + SSE handlers, auth, audit middleware
internal/server/         central server (v1)
web/                     Nuxt app (pages, composables, components/ui from shadcn-vue)
web/.output/public/      static build, embedded into the Go binary
```

Core interfaces keep features pluggable: `Collector{ Collect(ctx) ([]Sample, error) }`, `Check{ ID(); Run(ctx) Result; Fix(ctx, dryRun bool) (Diff, error) }`, `Notifier{ Send(ctx, Alert) error }`.

**Storage design**

Metrics go to VictoriaMetrics and everything else to an embedded SQLite file, so production needs no database server: only the `kurogane` binary plus the VictoriaMetrics binary it installs.

| Data | Store | Location | Retention |
| --- | --- | --- | --- |
| Fleet metrics (central) | VictoriaMetrics single-node on `127.0.0.1:8428` | `/var/lib/kurogane/vm/` | 90 days default (`-retentionPeriod`) |
| Metadata (central): servers, keys, scans, fixes, rules, alert events, silences, users, audit log | SQLite, WAL mode | `/var/lib/kurogane/kurogane.db` | Audit log 1 year, rest kept |
| Agent local metrics | bbolt | `/var/lib/kurogane/agent.db` | 24 h raw + 7 d rollups |
| Agent pending SSH changes, alert queue | bbolt | `/var/lib/kurogane/agent.db` | Until confirmed / delivered |

- **Writes and reads:** the central server writes to VictoriaMetrics over local HTTP (`/api/v1/import/prometheus`, batched every 5 s) and reads with PromQL (`/api/v1/query_range`). The UI and CLI never talk to VictoriaMetrics directly.
- **SQLite settings:** one writer connection, `journal_mode=WAL`, `synchronous=NORMAL`, `foreign_keys=ON`, `busy_timeout=5000`; migrations embedded and run on startup (`pressly/goose`). All access goes through a `Store` interface so PostgreSQL can be added later if high availability is ever needed.
- **Installing VictoriaMetrics:** `kurogane server init` downloads a pinned release, verifies its SHA256, and runs it under its own systemd unit. An offline bundle ships both binaries for air-gapped servers.
- **Sizing (estimate):** 500 servers × \~300 series at 10 s ≈ 15,000 samples/s and \~150,000 active series → \~150 MB RAM for VictoriaMetrics, about 0.6 to 1.5 GB disk per day, so roughly 60 to 130 GB for 90 days. Central server spec: 2 vCPU, 4 GB RAM, SSD.
- **Backups:** `kurogane backup` runs nightly: SQLite `VACUUM INTO` plus VictoriaMetrics `/snapshot/create`, copied off-host. `kurogane restore` reverses it.
- **Downsampling:** an Enterprise-only feature in VictoriaMetrics, so v1 relies on retention plus compression; hourly rollups via `vmalert` recording rules are optional.

**Web UI**

- Nuxt (Vue 3, TypeScript) with Tailwind CSS and shadcn-vue components for tables, forms, dialogs and toasts.
- Built as a static single-page app (`ssr: false`, `nuxi generate`) and embedded in the Go binary with `embed.FS`, so production servers need no Node.js.
- The same UI is served by the agent (MVP, one server) and by the central server (v1, fleet view).
- Talks only to the Kurogane REST API (`/api/v1`) with session cookie + CSRF token; a typed TypeScript client is generated from the OpenAPI spec.
- Live metrics and alert state stream over Server-Sent Events (`GET /api/v1/stream`); historical charts use `query_range` results rendered with ECharts.
- Key pages: Overview (all servers), Server detail (metrics, services, sessions), SSH (keys, config, pending changes), Hardening (score, checks, fix diff), Alerts (rules, events, silences, channels), Audit log, Settings.

## 10. Interfaces

Every feature is reachable from the CLI, the REST API and the web UI. The CLI is a thin client over the same API, so behavior never diverges.

**10.1 CLI**

```
kurogane init                         # interactive setup, writes /etc/kurogane/config.yaml
kurogane agent run                    # run as service (used by systemd unit)
kurogane status                       # health summary: metrics, score, active alerts
kurogane top                          # live terminal dashboard
kurogane metrics get cpu,mem --since 6h --json

kurogane ssh keys list [--user deploy]
kurogane ssh keys add --user deploy --file id_ed25519.pub --label "budi laptop" --expires 2027-01-31
kurogane ssh keys add --user deploy --github budi-dev
kurogane ssh keys revoke <fingerprint> [--all-servers]
kurogane ssh config show              # current vs recommended
kurogane ssh config set PasswordAuthentication no --rollback 120s
kurogane ssh confirm                  # confirm pending change
kurogane ssh sessions [--kill <pid>]

kurogane harden scan [--json|--md]
kurogane harden fix <check-id>|--all [--severity high] [--dry-run]
kurogane harden revert <fix-id>
kurogane harden ignore <check-id> --reason "..."

kurogane alert rules list|add|edit|delete
kurogane alert channels add slack --webhook <url> --name ops
kurogane alert test ops
kurogane alert silence --rule high_cpu --for 2h
```

**10.2 REST API (v1, JSON, `/api/v1`)**

| Method + path | Purpose |
| --- | --- |
| `GET /metrics/current` | Latest sample of all groups |
| `GET /metrics/history?names=cpu,mem&from=&to=&step=` | Time series |
| `GET /ssh/keys` · `POST /ssh/keys` · `DELETE /ssh/keys/{fp}` | Key inventory and changes |
| `GET /ssh/config` · `PATCH /ssh/config` · `POST /ssh/config/confirm` | sshd settings, safe-apply |
| `GET /ssh/sessions` · `GET /ssh/logins` | Sessions and login history |
| `POST /harden/scans` · `GET /harden/scans/{id}` | Run and fetch scans |
| `POST /harden/fixes` · `POST /harden/fixes/{id}/revert` | Apply and revert fixes |
| `GET/POST/PUT/DELETE /alerts/rules` | Rule CRUD |
| `GET /alerts/events` · `POST /alerts/silences` | History and silences |
| `GET /audit` | Audit log of every change |

Auth: API tokens (scoped: `read`, `ssh:write`, `harden:write`, `admin`). Web UI uses session cookies + CSRF tokens. Mutating calls require `admin` or the matching write scope.

**10.3 Config file example**

```yaml
# /etc/kurogane/config.yaml
server_name: web-01
tags: [prod, web]
listen: 127.0.0.1:9443

collector:
  interval: 10s
  retention_raw: 24h
  retention_rollup: 7d
  watch_services: [nginx, mysql, docker]

ssh:
  rollback_timeout: 120s
  bruteforce:
    enabled: true
    max_failures: 5
    window: 10m
    ban_for: 1h
    allowlist: [203.0.113.10/32]

harden:
  schedule: "0 3 * * *"
  ignore:
    - id: SSH-PORT-NONDEFAULT
      reason: "Port 22 required by provider console"

alerts:
  channels:
    - name: ops
      type: slack
      webhook_url_env: KRGN_SLACK_OPS      # secret read from env / encrypted store
    - name: phone
      type: discord
      webhook_url_env: KRGN_DISCORD_ME
  rules:
    - id: mem_available_low
      expr: mem.available_pct < 10
      for: 5m
      severity: warning
      channels: [ops, phone]
    - id: syn_flood
      expr: net.tcp.syn_recv > 500
      for: 1m
      severity: critical
      channels: [ops, phone]
  repeat_interval: 30m
```

**10.4 Core data model**

| Entity | Key fields |
| --- | --- |
| Server | id, name, tags, os, kernel, agent\_version, last\_seen |
| Sample | server\_id, metric, labels (device, iface, mount), ts, value |
| SSHKey | fingerprint, type, bits, user, label, owner\_person, added\_at, expires\_at, last\_used\_at |
| SSHChange | id, actor, setting, old\_value, new\_value, status (pending/confirmed/rolled\_back), ts |
| Scan | id, server\_id, started\_at, score, grade, results\[\] (check\_id, status, evidence) |
| Fix | id, check\_id, diff, backup\_path, applied\_by, applied\_at, reverted\_at |
| AlertRule | id, expr, for, severity, channels, enabled |
| AlertEvent | id, rule\_id, server\_id, state, started\_at, resolved\_at, payload |
| Silence | id, matcher, starts\_at, ends\_at, created\_by, reason |
| AuditEntry | id, actor, action, target, before, after, ts, source\_ip |

## 11. Non-functional requirements

Because the agent runs as root and can change SSH and firewall settings, the tool's own security is the top non-functional requirement.

**11.1 Security of Kurogane itself**

- Web UI and API bind to `127.0.0.1` by default; remote access only via SSH tunnel or explicit opt-in with TLS.
- TLS 1.3 only for remote access; agent ↔ central uses mutual TLS with per-agent certificates and one-time enrollment tokens (expire in 1 h).
- Admin login: Argon2id password hashes, mandatory TOTP 2FA for the web UI, lockout after 5 failures.
- Secrets (webhook URLs, tokens) encrypted at rest with a key in `/etc/kurogane/secret.key` (mode 0600) or read from env; never written to logs.
- Least privilege: the API process drops privileges where possible; root actions go through a small internal executor with an allowlist of operations (no arbitrary shell from the API).
- Every mutating action is written to an append-only audit log (who, what, before/after, source IP).
- Signed releases (cosign / minisign), SBOM published, reproducible builds; `govulncheck` and `gosec` in CI.
- Central server can never push arbitrary commands, only typed operations defined in the gRPC API. VictoriaMetrics listens on 127.0.0.1 only and the SQLite file is mode 0600, so only the Kurogane process can reach either.

**11.2 Performance budget**

| Resource | Budget |
| --- | --- |
| CPU (agent, 10 s interval) | < 1% average on 2 vCPU |
| Memory (agent RSS) | < 50 MB |
| Disk (7-day local history) | < 200 MB |
| Network (agent → central) | < 5 KB/s per agent |
| Binary size | < 30 MB |
| Central server capacity (v1) | 500 agents on 4 vCPU / 8 GB |

**11.3 Compatibility**

- OS: Ubuntu 22.04/24.04, Debian 12, RHEL/Rocky/AlmaLinux 9. Best effort: Amazon Linux 2023, Fedora.
- Arch: amd64 and arm64.
- Init: systemd required. Firewall: nftables, iptables, ufw, firewalld detected automatically.
- Packages: `.deb`, `.rpm`, install script, and a Docker image for the central server. No database server to install: SQLite is embedded and the VictoriaMetrics binary is fetched (checksum-verified) by the kurogane server init command or shipped in an offline bundle.

**11.4 Reliability**

- Agent auto-restarts via systemd; a crash never leaves sshd or firewall half-changed (changes are transactional with backup).
- Alert queue persisted on disk; no alert lost during a network outage of up to 24 h.
- Agent works fully offline from the central server (monitoring, alerts, local UI).
- Upgrades are in-place with config and SQLite schema migrations; downgrade supported one minor version back. Nightly backups of SQLite and VictoriaMetrics snapshots, restorable with one command.

**11.5 Usability**

- Every risky action shows a dry-run diff and plain-language impact before applying.
- Error messages state the cause and the next step (e.g. "sshd -t failed on line 42: unknown option").

## 12. Milestones and testing

The proposed plan reaches a single-server MVP in about 18 weeks and fleet-capable v1 about 11 weeks later; adjust once team size is confirmed.

**What each milestone delivers**

1. **Foundations:** repo, CI (lint, `govulncheck`, tests), config loader, bbolt store, API skeleton with auth + audit log, systemd unit, `.deb`/`.rpm` packaging.
2. **Monitoring + alerts:** all collectors (PM-1 to PM-5), `kurogane top`, web UI charts, threshold rules, Slack + Discord delivery (AL-1 to AL-3).
3. **SSH management:** key inventory, add/revoke/expire, sshd\_config parser, safe-apply with rollback, login history (SSH-1 to SSH-5).
4. **Hardening:** \~40 checks, score, dry-run fixes, revert, JSON/Markdown reports (HD-1 to HD-4, HD-7).
5. **Beta and polish:** 10 to 20 beta servers, docs site, install script, bug fixes. Exit: zero lockouts, overhead within budget.
6. **Fleet features (v1):** central server, enrollment, fleet key push/revoke, anomaly/DDoS detection, silences, scheduled scans + drift, PDF reports, RBAC.

**Testing strategy**

- Unit tests for parsers (`/proc` fixtures, `sshd_config` edge cases, `authorized_keys` options), with a target of 80% coverage in `internal/`.
- Integration tests in VMs/containers per supported distro (Ubuntu, Debian, Rocky) via a CI matrix; every hardening check is tested for scan, fix and revert.
- Lockout tests: scripted SSH change with no confirm must roll back within the timeout, every release.
- Load tests: simulated SYN flood and traffic spikes (hping3, iperf3) in an isolated lab to tune detection thresholds and false-positive rate.
- Benchmarks: agent CPU/RAM on a 2 vCPU VPS tracked per commit; fail CI if budget is exceeded by > 10%.
- Security review: external pentest of the API and agent before v1.

## 13. Risks and open questions

The biggest risk is a tool with root access locking users out or becoming an attack path; most mitigations above exist for that reason.

| Risk | Impact | Likelihood | Mitigation |
| --- | --- | --- | --- |
| SSH change locks operator out | High | Medium | `sshd -t` validation, rollback timer, refuse unsafe combos (SSH-3, SSH-4) |
| Agent compromise = root on every server | High | Low | Localhost bind, mTLS, typed operations only, signed releases, pentest |
| Hardening fix breaks an app (e.g. firewall closes a needed port) | High | Medium | Dry-run diff, detect listening ports first, per-fix revert |
| Alert fatigue from noisy thresholds | Medium | High | Duration windows, baselines, dedup, "mark as noise" feedback |
| DDoS detection false positives on traffic spikes (launches, crawlers) | Medium | Medium | Absolute floors + z-score, auto-ban off by default, allowlist |
| Volumetric DDoS saturates the link before the agent can act | High | Medium | Document clearly: host tool detects; mitigation needs provider/CDN |
| Distro differences (paths, firewall, package managers) | Medium | High | Detection layer, CI matrix per distro, limited official support list |
| Slack/Discord webhook URL leaks | Medium | Low | Encrypted at rest, never logged, rotation guide |
| Overlap with fail2ban/ufw already installed | Low | High | Detect existing tools and integrate or defer, never fight them |

**Open questions**

- [x] Final product name: Kurogane (CLI `kurogane`, short `krgn`). Still open: license (open source AGPL/Apache-2.0, or open-core with paid fleet features)?
- [ ] Is the central server self-hosted only, or also offered as SaaS?
- [x] VictoriaMetrics runs as its own systemd unit by default; `server.vm.mode: child` runs it as a child process supervised by Kurogane.
- [ ] Should auto-remediation of attacks (IP bans) ship in v1 or wait for more field data?
- [ ] Which compliance mappings matter most to target users: CIS only, or also ISO 27001 / PCI DSS evidence?
- [ ] WhatsApp channel: needed early for users in Indonesia/SEA? (Telegram has shipped.)
- [ ] Minimum team size and confirmed start date to lock the timeline.
