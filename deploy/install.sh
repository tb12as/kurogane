#!/bin/sh
# ServerKeeper install script: curl -fsSL https://get.serverkeeper.dev | sudo sh
# Downloads the release for this arch, verifies SHA256 and the cosign signature (if cosign is present),
# installs the binary, systemd units and the serverkeeper system user.
set -eu

VERSION="${SK_VERSION:-latest}"
REPO="serverkeeper/serverkeeper"
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
[ "$(uname -s)" = Linux ] || { echo "Linux only"; exit 1; }
command -v systemctl >/dev/null || { echo "systemd is required"; exit 1; }

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported arch $(uname -m)"; exit 1 ;;
esac

if [ "$VERSION" = latest ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')
fi
BASE="https://github.com/$REPO/releases/download/$VERSION"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

BIN="serverkeeper-linux-$ARCH"
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

install -m 0755 "$TMP/$BIN" /usr/bin/serverkeeper
curl -fsSL -o /lib/systemd/system/serverkeeper.service "$BASE/serverkeeper.service"
curl -fsSL -o /lib/systemd/system/serverkeeper-server.service "$BASE/serverkeeper-server.service"
if ! getent passwd serverkeeper >/dev/null; then
  useradd --system --home-dir /var/lib/serverkeeper --no-create-home --shell /usr/sbin/nologin serverkeeper
fi
# debian family: read /var/log/auth.log directly (RHEL falls back to journald via the root executor)
getent group adm >/dev/null && usermod -a -G adm serverkeeper || true
install -d -m 0700 -o serverkeeper -g serverkeeper /var/lib/serverkeeper
install -d -m 0750 -o root -g serverkeeper /etc/serverkeeper
systemctl daemon-reload
echo "Installed serverkeeper $VERSION. Next: sudo serverkeeper init"
