#!/bin/sh
# Kurogane install script:
#   curl -fsSL https://github.com/tb12as/kurogane/releases/latest/download/install.sh | sudo sh
# Downloads the release for this arch, verifies SHA256 and the cosign signature (if cosign is present),
# installs the binary, systemd units and the kurogane system user.
set -eu

VERSION="${KRGN_VERSION:-latest}"
REPO="tb12as/kurogane"
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
[ "$(uname -s)" = Linux ] || { echo "Linux only"; exit 1; }
command -v systemctl >/dev/null || { echo "systemd is required"; exit 1; }

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported arch $(uname -m)"; exit 1 ;;
esac

if [ "$VERSION" = latest ] && [ -z "${KRGN_BASE_URL:-}" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')
fi
# KRGN_BASE_URL points at a mirror or an internal artifact server with the same file layout as a release
BASE="${KRGN_BASE_URL:-https://github.com/$REPO/releases/download/$VERSION}"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

BIN="kurogane-linux-$ARCH"
curl -fsSL -o "$TMP/$BIN" "$BASE/$BIN"
curl -fsSL -o "$TMP/checksums.txt" "$BASE/checksums.txt"
(cd "$TMP" && grep " $BIN\$" checksums.txt | sha256sum -c -) || { echo "checksum mismatch"; exit 1; }

if command -v cosign >/dev/null 2>&1; then
  curl -fsSL -o "$TMP/$BIN.sig" "$BASE/$BIN.sig"
  curl -fsSL -o "$TMP/$BIN.pem" "$BASE/$BIN.pem"
  cosign verify-blob --certificate "$TMP/$BIN.pem" --signature "$TMP/$BIN.sig" \
    --certificate-identity-regexp "https://github.com/$REPO/" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com "$TMP/$BIN"
else
  echo "cosign not found: signature not verified (checksum verified)"
fi

install -m 0755 "$TMP/$BIN" /usr/bin/kurogane
ln -sf kurogane /usr/bin/krgn # short alias
curl -fsSL -o /lib/systemd/system/kurogane.service "$BASE/kurogane.service"
curl -fsSL -o /lib/systemd/system/kurogane-server.service "$BASE/kurogane-server.service"
if ! getent passwd kurogane >/dev/null; then
  useradd --system --home-dir /var/lib/kurogane --no-create-home --shell /usr/sbin/nologin kurogane
fi
# debian family: read /var/log/auth.log directly (RHEL falls back to journald via the root executor)
getent group adm >/dev/null && usermod -a -G adm kurogane || true
install -d -m 0700 -o kurogane -g kurogane /var/lib/kurogane
install -d -m 0750 -o root -g kurogane /etc/kurogane
systemctl daemon-reload
echo "Installed kurogane $VERSION (also as krgn). Next: sudo krgn init"
