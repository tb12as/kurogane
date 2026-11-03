#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop serverkeeper.service serverkeeper-server.service 2>/dev/null || true
  systemctl disable serverkeeper.service serverkeeper-server.service 2>/dev/null || true
fi
