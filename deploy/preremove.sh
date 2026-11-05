#!/bin/sh
set -e
# deb passes "upgrade" on reinstall/upgrade and rpm passes 1; only stop/disable on real removal
case "$1" in
  remove|0) ;;
  *) exit 0 ;;
esac
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop kurogane.service kurogane-server.service 2>/dev/null || true
  systemctl disable kurogane.service kurogane-server.service 2>/dev/null || true
fi
