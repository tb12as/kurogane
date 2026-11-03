# ServerKeeper

One static Go binary that monitors a Linux server, manages SSH access, audits and hardens the server, and sends
alerts to Slack or Discord. Built for small teams running 1–50 servers. Spec: `docs/PRD — ServerKeeper Go Server
Management Agent.md`.

## Install

```sh
curl -fsSL https://github.com/tb12as/serverman/releases/latest/download/install.sh | sudo sh
# or: sudo apt install ./serverkeeper_<ver>_amd64.deb   /   sudo dnf install ./serverkeeper-<ver>.x86_64.rpm
sudo serverkeeper init        # writes /etc/serverkeeper/config.yaml, creates the admin user (TOTP), starts the unit
```

The web UI and API listen on `127.0.0.1:9443`. Reach them through an SSH tunnel:

```sh
ssh -L 9443:127.0.0.1:9443 web-01   # then open http://127.0.0.1:9443
```

Remote access without a tunnel needs `tls.cert`, `tls.key` and `tls.allow_remote: true` (TLS 1.3 only).

Supported: Ubuntu 22.04/24.04, Debian 12, RHEL/Rocky/AlmaLinux 9 (amd64, arm64; systemd required). Best effort:
Amazon Linux 2023, Fedora.

## CLI

```sh
serverkeeper status                       # metrics, hardening score, active alerts
serverkeeper top                          # live terminal dashboard
serverkeeper metrics get cpu,mem --since 6h --json

serverkeeper ssh keys list [--user deploy]
serverkeeper ssh keys add --user deploy --file id_ed25519.pub --label "budi laptop" --expires 2027-01-31
serverkeeper ssh keys add --user deploy --github budi-dev
serverkeeper ssh keys revoke <fingerprint> [--all-servers]
serverkeeper ssh config show              # current vs recommended
serverkeeper ssh config set PasswordAuthentication no --rollback 120s
serverkeeper ssh confirm                  # from a NEW ssh session, before the timer ends
serverkeeper ssh sessions [--kill <pid>]

serverkeeper harden scan [--json|--md]
serverkeeper harden fix <check-id>|--all [--severity high] [--dry-run]
serverkeeper harden revert <fix-id>
serverkeeper harden ignore <check-id> --reason "..."

serverkeeper alert rules list|add|edit|delete
serverkeeper alert channels add slack --webhook <url> --name ops
serverkeeper alert test ops
serverkeeper alert silence --rule high_cpu --for 2h

serverkeeper users add alice --role operator   # prints the TOTP enrollment URL
serverkeeper tokens create ci --scopes read
serverkeeper audit --since 24h
serverkeeper certs list [--warn-days 14]  # TLS certificates; exits 1 if one is expiring, stale or unreadable
serverkeeper certs rescan                 # scan now, e.g. right after a renewal
sudo serverkeeper uninstall [--purge] [--yes]   # --purge also deletes data, config and the system user
```

Settings → Storage shows the disk usage of `data_dir` and of each agent store bucket, and deletes metric history
older than a chosen cutoff. The store file is compacted afterwards, so the freed space returns to the filesystem.
Settings → About offers the same uninstall as the CLI; it runs as a transient systemd unit three seconds after the
request. Uninstall leaves the sshd drop-in and applied hardening fixes in place.

The CLI is a thin client over the REST API (`/api/v1`, spec at `/api/v1/openapi.yaml`). As root on the agent host it
uses the local admin token in `/var/lib/serverkeeper/cli.token`; elsewhere pass `--api` and `--token`.

## SSH changes never lock you out

`ssh config set` validates the candidate with `sshd -t`, backs up the current config, applies it as a
`sshd_config.d/99-serverkeeper.conf` drop-in (or in place), reloads sshd and starts a rollback timer (default 120 s).
Open a new SSH session and run `serverkeeper ssh confirm`. Without confirmation the backup is restored, sshd is
reloaded and an alert is sent. Disabling password or root login is refused when it would leave no working login.

## Hardening

About 45 checks (SSH, accounts, firewall, updates, sysctl, file permissions, services, logging, intrusion
protection, filesystem, time, malware basics, TLS certificates), mapped to CIS IDs where one exists. Score =
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
email, PagerDuty, generic webhook. Webhook URLs are encrypted at rest with `/etc/serverkeeper/secret.key` and never
logged.

Host-level detection cannot stop volumetric DDoS: that needs upstream mitigation (provider or CDN). Optional
auto-ban (`alerts.auto_ban`) is off by default.

## TLS certificates

The agent finds certificates on its own: Let's Encrypt lineages (`/etc/letsencrypt/renewal/*.conf`, falling back to
`live/`), every `ssl_certificate` in the nginx configuration (includes followed), and any PEM files listed in
`collector.certs.paths`. It rescans hourly and records `cert.days_left` per certificate. Local TLS handshakes on
`collector.certs.probe_ports` (default 443) show which certificate each name is really served with. They catch a
certificate renewed on disk but never reloaded, and certificates served without a file the agent could find (Apache,
Caddy, HAProxy).

- `cert_expiring` warns under 14 days (per-server threshold), turns critical under 3, and reminds daily.
- `cert_stale_served` fires when a renewed certificate is still not served after an hour.
- `TLS-CERT-VALID` (High) fails on certificates within 7 days of expiry, RSA keys under 2048 bits, SHA-1 signatures,
  stale served certificates and nginx `server_name`s the certificate does not cover.

The server page lists the certificates with a Rescan button; on the central server the dashboard shows each server's
next expiry. Only `CERTIFICATE` PEM blocks are parsed and files named like private keys are never read. Turn the
feature off with `collector.certs.enabled: false`.

## Fleet (central server)

```sh
sudo serverkeeper server init              # CA, VictoriaMetrics (pinned, SHA256-verified), systemd units
sudo systemctl enable --now serverkeeper-server
serverkeeper server token create --name web-02   # one-time enrollment token, expires in 1 h
```

On each agent set `central.addr` and `central.enrollment_token`. Agents enroll once, then stream over gRPC with
mutual TLS; they keep working fully offline. The central server stores fleet metrics in VictoriaMetrics
(`127.0.0.1:8428`, 90-day retention) and metadata in SQLite, routes alerts, detects offline agents, and pushes or
revokes SSH keys by person or group across all servers. It can only send typed operations, never shell commands.

`serverkeeper backup` (nightly on the central server) writes SQLite `VACUUM INTO` plus a VictoriaMetrics snapshot;
`serverkeeper restore` reverses it.

## Security model

- Binds to `127.0.0.1` by default; TLS 1.3 for remote access; mTLS between agent and central server.
- Admin login: Argon2id, mandatory TOTP, lockout after 5 failures. Optional OIDC SSO. API tokens are scoped
  (`read`, `ssh:write`, `harden:write`, `admin`); RBAC roles admin, operator, viewer.
- Privilege separation: when a `serverkeeper` system user exists, a root parent only executes an allowlist of typed
  operations for an unprivileged worker that runs the API, collectors and rules. There is no shell anywhere.
- Every mutating action goes to an append-only audit log (who, what, before/after, source IP), kept for 1 year.

## Development

Requirements: Go 1.26 or later (release builds use the latest 1.27.x patch release), Node 24 and pnpm for the web UI.
The built UI in `web/.output/public` is committed, so `go build ./cmd/serverkeeper` alone produces a complete binary.

```sh
make build        # web UI (pnpm) + binary in bin/
make build-go     # binary only, using the committed UI build
make test cover lint vuln gosec
make proto        # regenerate gRPC code (buf, no protoc needed)
make openapi      # merge internal/api/openapi/*.yaml into internal/api/openapi.yaml
make dist packages
```

Tests never touch the host: parsers run against fixtures (`SK_ROOT`), and privileged operations go through a fake
executor. Distro integration tests (real sshd lockout rollback, every hardening fix and revert) run in disposable
containers in CI (`-tags integration`). `go run ./tools/totpcode <secret>` prints a TOTP code for manual UI testing.
