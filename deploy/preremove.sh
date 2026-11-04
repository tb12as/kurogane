#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop kurogane.service kurogane-server.service 2>/dev/null || true
  systemctl disable kurogane.service kurogane-server.service 2>/dev/null || true
fi
