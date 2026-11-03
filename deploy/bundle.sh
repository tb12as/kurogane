#!/bin/sh
# Builds an offline bundle (serverkeeper + VictoriaMetrics) for air-gapped servers:
#   deploy/bundle.sh <arch> <vm-version>
# Install on the target: tar xzf bundle.tgz && sudo ./install-offline.sh
set -eu
ARCH="${1:-amd64}"
VM_VERSION="${2:?victoriametrics version, e.g. v1.110.0}"
OUT="dist/serverkeeper-offline-$ARCH"
rm -rf "$OUT" && mkdir -p "$OUT"
cp "dist/serverkeeper-linux-$ARCH" "$OUT/serverkeeper"
cp deploy/serverkeeper.service deploy/serverkeeper-server.service deploy/config.example.yaml "$OUT/"
VM_TGZ="victoria-metrics-linux-$ARCH-$VM_VERSION.tar.gz"
curl -fsSL -o "$OUT/$VM_TGZ" "https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/$VM_VERSION/$VM_TGZ"
cat > "$OUT/install-offline.sh" <<SH
#!/bin/sh
set -eu
install -m 0755 serverkeeper /usr/bin/serverkeeper
install -m 0644 serverkeeper.service serverkeeper-server.service /lib/systemd/system/
getent passwd serverkeeper >/dev/null || useradd --system --home-dir /var/lib/serverkeeper --no-create-home --shell /usr/sbin/nologin serverkeeper
systemctl daemon-reload
echo "agent: sudo serverkeeper init    central: sudo serverkeeper server init --bundle $VM_TGZ"
SH
chmod +x "$OUT/install-offline.sh"
tar -C dist -czf "$OUT.tgz" "$(basename "$OUT")"
rm -rf "$OUT"
echo "$OUT.tgz"
