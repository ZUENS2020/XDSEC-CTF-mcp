#!/bin/zsh
set -euo pipefail
pkill -f '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome.*--user-data-dir=/Users/zuens2020/.xdctf-chrome-profile' || true
echo "[xdctf] browser stop signal sent"
