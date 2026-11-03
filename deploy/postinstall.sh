#!/bin/sh
set -e
# system user for privilege separation (the agent's unprivileged worker runs as it)
if ! getent passwd serverkeeper >/dev/null; then
  useradd --system --home-dir /var/lib/serverkeeper --no-create-home --shell /usr/sbin/nologin serverkeeper
fi
# debian family: read /var/log/auth.log directly (RHEL falls back to journald via the root executor)
getent group adm >/dev/null && usermod -a -G adm serverkeeper || true
install -d -m 0700 -o serverkeeper -g serverkeeper /var/lib/serverkeeper
install -d -m 0750 -o root -g serverkeeper /etc/serverkeeper
if [ ! -f /etc/serverkeeper/config.yaml ]; then
  echo "ServerKeeper installed. Run: sudo serverkeeper init"
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  # restart on upgrade only if it was running (config/schema migrate on start)
  systemctl try-restart serverkeeper.service || true
fi
