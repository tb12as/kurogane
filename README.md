# Kurogane

Kurogane (黒鉄, "black iron") is one static Go binary that monitors a Linux server, manages SSH access, audits and hardens the server, and sends
alerts to Slack or Discord. Built for small teams running 1 to 50 servers. The command is `kurogane`;
packages and the install script also add the short alias `krgn`, used in the examples below. Spec: `docs/PRD.md`.

## Install

```sh
curl -fsSL https://github.com/tb12as/kurogane/releases/latest/download/install.sh | sudo sh
# or: sudo apt install ./kurogane_<ver>_amd64.deb   /   sudo dnf install ./kurogane-<ver>.x86_64.rpm
sudo krgn init                # writes /etc/kurogane/config.yaml, creates the admin user (TOTP), starts the unit
```

The web UI and API listen on `127.0.0.1:9443`. Reach them through an SSH tunnel:

```sh
ssh -L 9443:127.0.0.1:9443 web-01   # then open http://127.0.0.1:9443
```

Remote access without a tunnel needs `tls.cert`, `tls.key` and `tls.allow_remote: true` (TLS 1.3 only).

Every option of `/etc/kurogane/config.yaml`, with its default, is documented in
[docs/configuration.md](docs/configuration.md).

Supported: Ubuntu 22.04/24.04, Debian 12, RHEL/Rocky/AlmaLinux 9 (amd64, arm64; systemd required). Best effort:
Amazon Linux 2023, Fedora.

## Moving from ServerKeeper

Kurogane is ServerKeeper renamed, as a clean break: paths, the system user, units, environment variables (`SK_` is
now `KRGN_`), cookies, the Prometheus prefix (`kurogane_`) and the fleet protocol all changed, and nothing is
migrated automatically. On each server:

1. Keep a copy of `/etc/serverkeeper/config.yaml`, then remove the old agent: `sudo serverkeeper uninstall` (add
   `--purge` to also delete its data and the `serverkeeper` user once you no longer need them).
2. Install Kurogane and run `sudo krgn init`.
3. Copy your settings into `/etc/kurogane/config.yaml`, changing `/etc/serverkeeper` to `/etc/kurogane` and any
   `SK_` environment variable names to `KRGN_`. Restart with `sudo systemctl restart kurogane`.
4. Clean up what the old version deliberately left behind: once `sshd -T` shows Kurogane's settings from
   `/etc/ssh/sshd_config.d/99-kurogane.conf`, delete `99-serverkeeper.conf` (and `/etc/ssh/serverkeeper_ca.pub` if
   you used the SSH CA, after re-running `krgn ssh ca init`). Delete the old ban table with
   `sudo nft delete table inet serverkeeper` if it still exists; on iptables hosts, delete the old
   `SERVERKEEPER` chain (`iptables -D INPUT -j SERVERKEEPER; iptables -F SERVERKEEPER; iptables -X SERVERKEEPER`, and
   the same with `ip6tables`).
5. Fleets: ServerKeeper agents cannot talk to a Kurogane central server. Move the central server and every agent
   together, then re-enroll each agent with a new token (`krgn server token create`).

Prometheus scrapers and dashboards need their metric names updated from `serverkeeper_*` to `kurogane_*`.

## CLI

```sh
krgn status                               # metrics, hardening score, active alerts
krgn top                                  # live terminal dashboard
krgn metrics get cpu,mem --since 6h --json

krgn ssh keys list [--user deploy]
krgn ssh keys add --user deploy --file id_ed25519.pub --label "budi laptop" --expires 2027-01-31
krgn ssh keys add --user deploy --github budi-dev
krgn ssh keys revoke <fingerprint> [--all-servers]
krgn ssh config show                      # current vs recommended
krgn ssh config set PasswordAuthentication no --rollback 120s
krgn ssh confirm                          # from a NEW ssh session, before the timer ends
krgn ssh sessions [--kill <pid>]

krgn harden scan [--json|--md]
krgn harden fix <check-id>|--all [--severity high] [--dry-run]
krgn harden revert <fix-id>
krgn harden ignore <check-id> --reason "..."

krgn alert rules list|add|edit|delete
krgn alert channels add slack --webhook <url> --name ops
krgn alert test ops
krgn alert silence --rule high_cpu --for 2h

krgn users add alice --role operator           # prints the TOTP enrollment URL
krgn tokens create ci --scopes read
krgn audit --since 24h
krgn certs list [--warn-days 14]          # TLS certificates; exits 1 if one is expiring, stale or unreadable
krgn certs rescan                         # scan now, e.g. right after a renewal
krgn sites list                           # nginx/Apache sites, enabled and disabled, with the config test state
krgn sites disable shop.example.org --dry-run
krgn sites enable shop.example.org [--yes]
krgn sites test | reload nginx | changes
krgn redis status                         # per Redis instance: up, memory, ops/s, hit ratio, clients, last save
sudo krgn uninstall [--purge] [--yes]           # --purge also deletes data, config and the system user
```

Settings → Appearance sets the layout density (Default, Comfortable or Compact) and the theme for this browser. On a
server's page, each chart can be widened to the full width. Alert rules are built from dropdowns (metric, filter,
comparison, threshold), and Alerts → Rules → Metrics reference explains every metric.

Settings → Storage shows the disk usage of `data_dir` and of each agent store bucket, and deletes metric history
older than a chosen cutoff. The store file is compacted afterwards, so the freed space returns to the filesystem.
Settings → About offers the same uninstall as the CLI; it runs as a transient systemd unit three seconds after the
request. Uninstall leaves the sshd drop-in and applied hardening fixes in place.

The CLI is a thin client over the REST API (`/api/v1`, spec at `/api/v1/openapi.yaml`). As root on the agent host it
uses the local admin token in `/var/lib/kurogane/cli.token`; elsewhere pass `--api` and `--token`.

## SSH changes roll back unless you confirm them

`ssh config set` validates the candidate with `sshd -t`, backs up the current config, applies it as a
`sshd_config.d/99-kurogane.conf` drop-in (or in place), reloads sshd and starts a rollback timer (default 120 s).
Open a new SSH session and run `krgn ssh confirm`. Without confirmation the backup is restored, sshd is
reloaded and an alert is sent. Disabling password or root login is refused when it would leave no working login.

## Hardening

About 53 checks (SSH, accounts, firewall, updates, sysctl, file permissions, services, logging, intrusion
protection, filesystem, time, malware basics, TLS certificates, web servers, Redis), mapped to CIS IDs where one exists. Score =
100 × weighted passed / weighted applicable (Critical 10, High 5, Medium 3, Low 1); grades A ≥ 90, B ≥ 75,
C ≥ 60, D < 60. Every fix shows a dry-run diff, takes a backup, re-runs the check, and can be reverted. Scans run
daily (`harden.schedule`) and a passing check that starts failing raises a drift alert. Reports: JSON, Markdown,
PDF. Custom checks: YAML packs listed in `harden.packs` (Go plugins are not possible in a static `CGO_ENABLED=0`
binary).

## Alerts

Built-in rules for CPU, RAM, OOM kills, disk (including projected-full), I/O wait, traffic anomalies, SYN flood /
DDoS, SSH brute force and logins, SSH config changes and rollbacks, service down, hardening drift, agent offline and
pending security updates. Thresholds are editable per server; traffic baselines (EWMA + hour-of-week) are learned
from 7 days of history. One message per incident plus a resolve message, reminders every 30 min, silences, max 20
messages/min per channel, and an on-disk queue that survives network outages. Channels: Slack, Discord, Telegram,
email, PagerDuty, generic webhook. Webhook URLs are encrypted at rest with `/etc/kurogane/secret.key` and never
logged.

Host-level detection cannot stop volumetric DDoS: that needs upstream mitigation (provider or CDN). Optional
auto-ban (`alerts.auto_ban`) is off by default.

## TLS certificates

The agent finds certificates on its own: Let's Encrypt lineages (`/etc/letsencrypt/renewal/*.conf`, falling back to
`live/`), every nginx `ssl_certificate` and Apache `SSLCertificateFile` (includes followed), and any PEM files listed in
`collector.certs.paths`. It rescans hourly and records `cert.days_left` per certificate. Local TLS handshakes on
`collector.certs.probe_ports` (default 443) show which certificate each name is really served with. They catch a
certificate renewed on disk but never reloaded, and certificates served without a file the agent could find (Caddy,
HAProxy).

- `cert_expiring` warns under 14 days (per-server threshold), turns critical under 3, and reminds daily.
- `cert_stale_served` fires when a renewed certificate is still not served after an hour.
- `TLS-CERT-VALID` (High) fails on certificates within 7 days of expiry, RSA keys under 2048 bits, SHA-1 signatures,
  stale served certificates and nginx `server_name`s the certificate does not cover.

The server page lists the certificates with a Rescan button; on the central server the dashboard shows each server's
next expiry. Only `CERTIFICATE` PEM blocks are parsed and files named like private keys are never read. Turn the
feature off with `collector.certs.enabled: false`.

## Redis

With `collector.redis.enabled: auto` (the default) the agent monitors every Redis it finds:
`/etc/redis/redis.conf`, `/etc/redis.conf` and Debian `redis-<name>.conf` instances whose unit is enabled or whose
port answers. Hosts without Redis are left alone. It connects over loopback with the `requirepass` from the config,
or with the credentials you list under `collector.redis.instances`. The password is only held in memory. A dedicated
read-only user is the cleanest setup:

```
ACL SETUSER kurogane on >PASSWORD -@all +ping +info +slowlog|get
```

The client only ever sends `AUTH`, `PING`, `INFO` and `SLOWLOG GET`. It never reads keys. Each instance reports up,
PING time, memory against `maxmemory`, fragmentation, clients against `maxclients`, ops/s, hit ratio, evictions,
expirations, rejected connections, network traffic, keys per database, persistence (last save, AOF) and replication.
The slow log keeps command names only, because arguments can hold keys, values or passwords.

A Redis that needs a password Kurogane does not have is shown as *needs credentials*, with the fix. It is not
monitored and never alerts. A rejected password or an unreachable instance does alert.

- Alerts: `redis_down`, `redis_persistence_failing` (critical), `redis_memory_high` (> 90 % of maxmemory),
  `redis_evicting`, `redis_clients_high`, `redis_replication_broken` (critical) and `redis_slow` (PING > 50 ms).
- Hardening: `REDIS-NOT-EXPOSED` (Critical: reachable from the network without a password), `REDIS-AUTH`,
  `REDIS-PROTECTED-MODE` and `REDIS-DANGEROUS-COMMANDS`.

The server page shows one card per instance and memory, ops/s, hit ratio and client charts. The central dashboard
shows how many instances are up on each server. Redis forks such as Valkey are not detected.

## Web sites (nginx and Apache)

The agent reads the nginx and Apache configuration (Debian `apache2` and RHEL `httpd` layouts, includes followed) and
lists every server block and virtual host, enabled or disabled, with its names, ports, root or upstream and
certificate. Every 15 minutes, and after each change, it runs `nginx -t` / `apachectl configtest`. Two failing tests
in a row raise `web_config_invalid`: the running server is fine, but the next reload or reboot would take every
site down. The web server units are added to the service watch automatically.

Enabling or disabling a site never edits a file. Kurogane only links or unlinks it in `sites-enabled` (Debian) or
renames `X.conf` to `X.conf.disabled` in `conf.d`, through three narrow typed operations of the privileged parent.
Each toggle:

1. shows a dry run: the file move, every site in that file, and warnings (default site, a port left with no site,
   an expiring certificate, a duplicate name, a site that proxies to Kurogane itself);
2. is refused while the configuration already fails its test;
3. runs the config test after the move, reloads, checks the unit is active and re-probes every other site that
   answered before;
4. is undone automatically (and the server reloaded again) if any step fails, raising `site_change_rolled_back`.

Sites defined in the main config file, regular files in `sites-enabled`, and files that also hold shared settings
(an `upstream` block, `Listen`) are shown but not toggled. The `WEB-*` hardening checks cover the config test,
`server_tokens` / `ServerTokens`, TLS protocols and directory listings. Toggling and reading raw site files need the
`web:write` scope (admin and operator roles). Turn the feature off with `web.enabled: false`.

On the central server the Sites page answers "which server hosts this name?" across the fleet, and a toggle there is
queued as a typed `SetSite` op that the agent runs with the same checks.

## Fleet (central server)

```sh
sudo krgn server init                      # CA, VictoriaMetrics (pinned, SHA256-verified), systemd units
sudo systemctl enable --now kurogane-server
krgn server token create --name web-02           # one-time enrollment token, expires in 1 h
```

On each agent set `central.addr` and `central.enrollment_token`. Agents enroll once, then stream over gRPC with
mutual TLS; they keep working fully offline. The central server stores fleet metrics in VictoriaMetrics
(`127.0.0.1:8428`, 90-day retention) and metadata in SQLite, routes alerts, detects offline agents, and pushes or
revokes SSH keys by person or group across all servers. It can only send typed operations, never shell commands.

`krgn backup` (nightly on the central server) writes SQLite `VACUUM INTO` plus a VictoriaMetrics snapshot;
`krgn restore` reverses it.

## Security model

- Binds to `127.0.0.1` by default; TLS 1.3 for remote access; mTLS between agent and central server.
- Admin login: Argon2id, mandatory TOTP, lockout after 5 failures. Optional OIDC SSO. API tokens are scoped
  (`read`, `ssh:write`, `harden:write`, `web:write`, `admin`); RBAC roles admin, operator, viewer.
- Privilege separation: when a `kurogane` system user exists, a root parent only executes an allowlist of typed
  operations for an unprivileged worker that runs the API, collectors and rules. There is no shell anywhere.
- Every mutating action goes to an append-only audit log (who, what, before/after, source IP), kept for 1 year.

## Development

Requirements: Go 1.26 or later (release builds use the latest 1.27.x patch release), Node 24 and pnpm for the web UI.
The built UI in `web/.output/public` is committed, so `go build ./cmd/kurogane` alone produces a complete binary.

```sh
make build        # web UI (pnpm) + binary in bin/
make build-go     # binary only, using the committed UI build
make test cover lint vuln gosec
make proto        # regenerate gRPC code (buf, no protoc needed)
make openapi      # merge internal/api/openapi/*.yaml into internal/api/openapi.yaml
make dist packages
```

Tests never touch the host: parsers run against fixtures (`KRGN_ROOT`), and privileged operations go through a fake
executor. Distro integration tests (real sshd lockout rollback, every hardening fix and revert) run in disposable
containers in CI (`-tags integration`). `go run ./tools/totpcode <secret>` prints a TOTP code for manual UI testing.
