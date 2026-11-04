#!/usr/bin/env bash
# Run a throwaway ServerKeeper agent from this checkout for local UI/API testing (no root, no systemd).
#
#   ./local-run.sh            build, set up on first run, start the agent
#   ./local-run.sh --web      same, plus the Nuxt dev server with hot reload
#   ./local-run.sh totp       print the current TOTP code for the admin login
#   ./local-run.sh reset      delete the local data and start over next run
#
# Env: SK_PORT (default 9450), SK_ADMIN_PASSWORD (default devpassword123), SK_DEV_DIR (default ./.local-run).
set -euo pipefail

cd "$(dirname "$0")"
DIR="${SK_DEV_DIR:-$PWD/.local-run}"
PORT="${SK_PORT:-9450}"
PASS="${SK_ADMIN_PASSWORD:-devpassword123}"
BIN="$DIR/serverkeeper"
CFG="$DIR/config.yaml"

# as root the agent would enable privsep and chown the data dir; keep this a user-level sandbox
[ "$(id -u)" -ne 0 ] || { echo "run as a normal user, not root"; exit 1; }

totp() { go run ./tools/totpcode "$(cat "$DIR/totp.secret")"; }

case "${1:-}" in
  totp) totp; exit ;;
  reset) rm -rf "$DIR"; echo "removed $DIR"; exit ;;
esac

mkdir -p "$DIR"
echo "building..."
go build -o "$BIN" ./cmd/kurogane

if [ ! -f "$CFG" ]; then
  out=$("$BIN" init --yes -c "$CFG" --data-dir "$DIR/data" --admin-password "$PASS" 2>&1)
  # init prints the otpauth:// URL once; keep the secret so `totp` works on later runs
  sed -n 's/.*secret=\([A-Z2-7]*\).*/\1/p' <<<"$out" >"$DIR/totp.secret"
  [ -s "$DIR/totp.secret" ] || { echo "$out"; echo "init failed"; exit 1; }
fi

if ss -tln 2>/dev/null | grep -q "127.0.0.1:$PORT "; then
  echo "port $PORT is busy: stop the other process or set SK_PORT"
  exit 1
fi

pids=()
cleanup() { [ ${#pids[@]} -eq 0 ] || kill "${pids[@]}" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

SK_LISTEN="127.0.0.1:$PORT" "$BIN" agent run -c "$CFG" &
pids+=($!)

if [ "${1:-}" = "--web" ]; then
  (cd web && SK_API="http://127.0.0.1:$PORT" pnpm dev) &
  pids+=($!)
fi

cat <<EOF

ServerKeeper agent:  http://127.0.0.1:$PORT$([ "${1:-}" = "--web" ] && echo "   (hot-reload UI: http://localhost:3000)")
login:               admin / $PASS
TOTP code:           $(totp)   (later: ./local-run.sh totp)
data:                $DIR
Ctrl+C to stop.

EOF
wait -n "${pids[@]}"
