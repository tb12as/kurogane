#!/bin/sh
set -e
# system user for privilege separation (the agent's unprivileged worker runs as it)
if ! getent passwd kurogane >/dev/null; then
  useradd --system --home-dir /var/lib/kurogane --no-create-home --shell /usr/sbin/nologin kurogane
fi
# debian family: read /var/log/auth.log directly (RHEL falls back to journald via the root executor)
getent group adm >/dev/null && usermod -a -G adm kurogane || true
install -d -m 0700 -o kurogane -g kurogane /var/lib/kurogane
install -d -m 0750 -o root -g kurogane /etc/kurogane
if [ ! -f /etc/kurogane/config.yaml ]; then
  echo "Kurogane installed (also as krgn). Run: sudo krgn init"
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  # restart on upgrade only if it was running (config/schema migrate on start)
  systemctl try-restart kurogane.service || true
fi
