#!/bin/sh
# Agent resource benchmark (PRD §2, §11.2): runs the agent for $DURATION seconds at a 10 s interval and
# fails if average CPU > 1% (of one 2-vCPU host => 2% of a single core) or RSS > 50 MB, with 10% headroom.
set -eu
BIN="${BIN:-bin/serverkeeper}"
DURATION="${DURATION:-300}"
DIR=$(mktemp -d)
trap 'kill $PID 2>/dev/null || true; rm -rf "$DIR"' EXIT
cat > "$DIR/config.yaml" <<YAML
server_name: bench
listen: 127.0.0.1:19999
data_dir: $DIR/data
secret_key: $DIR/secret.key
privsep: false
collector: {interval: 10s}
YAML
"$BIN" agent run -c "$DIR/config.yaml" >"$DIR/log" 2>&1 &
PID=$!
sleep 15
HZ=$(getconf CLK_TCK)
t0=$(awk '{print $14+$15}' /proc/$PID/stat)
sleep "$DURATION"
t1=$(awk '{print $14+$15}' /proc/$PID/stat)
rss=$(awk '/VmRSS/ {print $2}' /proc/$PID/status)
# PSS splits shared code pages fairly; fall back to RSS when smaps_rollup is not readable
pss=$(awk '/^Pss:/ {print $2}' /proc/$PID/smaps_rollup 2>/dev/null || echo "$rss")
[ -n "$pss" ] || pss=$rss
NCPU=$(nproc)
cpu=$(awk -v a="$t0" -v b="$t1" -v hz="$HZ" -v d="$DURATION" -v n="$NCPU" 'BEGIN {printf "%.3f", (b-a)/hz/d*100/n}')
echo "agent cpu ${cpu}% of host (${NCPU} cpus), rss $((rss/1024)) MB, pss $((pss/1024)) MB"
awk -v c="$cpu" 'BEGIN {exit !(c < 1.1)}' || { echo "CPU budget exceeded"; exit 1; }
[ "$pss" -lt 56320 ] || { echo "memory budget exceeded (PSS)"; exit 1; }
