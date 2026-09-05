#!/bin/zsh
set -euo pipefail

CHROME_BIN="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
PROFILE_DIR="/Users/zuens2020/.xdctf-chrome-profile"
CDP_PORT="9222"

mkdir -p "$PROFILE_DIR"

if lsof -nP -iTCP:"$CDP_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "[xdctf] CDP port $CDP_PORT already listening."
  echo "[xdctf] Open: http://127.0.0.1:$CDP_PORT/json/version"
  exit 0
fi

"$CHROME_BIN" \
  --remote-debugging-port="$CDP_PORT" \
  --user-data-dir="$PROFILE_DIR" \
  >/tmp/xdctf-chrome.log 2>&1 &

echo "[xdctf] browser started"
echo "[xdctf] profile: $PROFILE_DIR"
echo "[xdctf] cdp: http://127.0.0.1:$CDP_PORT"
