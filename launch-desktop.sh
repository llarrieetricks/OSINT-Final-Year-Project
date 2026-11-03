#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME_DIR="${ROOT_DIR}/.desktop-runtime"
mkdir -p "$RUNTIME_DIR"

cleanup() {
  trap - EXIT
  [[ -n "${BROWSER_PID:-}" ]] && kill "$BROWSER_PID" 2>/dev/null || true
  [[ -n "${CLIENT_PID:-}" ]] && kill "$CLIENT_PID" 2>/dev/null || true
  [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

npm --prefix "$ROOT_DIR/server" start >"$RUNTIME_DIR/server.log" 2>&1 &
SERVER_PID=$!
npm --prefix "$ROOT_DIR/client" run dev -- --host 127.0.0.1 >"$RUNTIME_DIR/client.log" 2>&1 &
CLIENT_PID=$!

for _ in {1..30}; do
  if curl --silent --fail http://127.0.0.1:5173/ >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! curl --silent --fail http://127.0.0.1:5173/ >/dev/null 2>&1; then
  printf 'The client did not start. See %s/client.log\n' "$RUNTIME_DIR" >&2
  exit 1
fi

chromium \
  --user-data-dir="$RUNTIME_DIR/chromium" \
  --app=http://127.0.0.1:5173 \
  --no-first-run \
  --no-default-browser-check &
BROWSER_PID=$!
wait "$BROWSER_PID"
