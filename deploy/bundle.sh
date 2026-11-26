#!/bin/sh
# Builds an offline bundle (kurogane + VictoriaMetrics) for air-gapped servers:
#   deploy/bundle.sh <arch> <vm-version>
# Install on the target: tar xzf bundle.tgz && sudo ./install-offline.sh
set -eu
ARCH="${1:-amd64}"
VM_VERSION="${2:?victoriametrics version, e.g. v1.110.0}"
OUT="dist/kurogane-offline-$ARCH"
rm -rf "$OUT" && mkdir -p "$OUT"
cp "dist/kurogane-linux-$ARCH" "$OUT/kurogane"
cp LICENSE deploy/kurogane.service deploy/kurogane-server.service deploy/config.example.yaml "$OUT/"
VM_TGZ="victoria-metrics-linux-$ARCH-$VM_VERSION.tar.gz"
curl -fsSL -o "$OUT/$VM_TGZ" "https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/$VM_VERSION/$VM_TGZ"
cat > "$OUT/install-offline.sh" <<SH
#!/bin/sh
set -eu
install -m 0755 kurogane /usr/bin/kurogane
ln -sf kurogane /usr/bin/krgn
install -m 0644 kurogane.service kurogane-server.service /lib/systemd/system/
getent passwd kurogane >/dev/null || useradd --system --home-dir /var/lib/kurogane --no-create-home --shell /usr/sbin/nologin kurogane
systemctl daemon-reload
echo "agent: sudo krgn init    central: sudo krgn server init --bundle $VM_TGZ"
SH
chmod +x "$OUT/install-offline.sh"
tar -C dist -czf "$OUT.tgz" "$(basename "$OUT")"
rm -rf "$OUT"
echo "$OUT.tgz"
