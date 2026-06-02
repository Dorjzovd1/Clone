#!/usr/bin/env bash
# Frontend — дотоод сүлжээ + localhost (0.0.0.0:5173)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/frontend"

npm install --silent 2>/dev/null || npm install

LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo ""
echo "==> Frontend эхэлж байна..."
echo "    Local:   http://127.0.0.1:5173"
echo "    Network: http://${LAN_IP:-YOUR_IP}:5173"
echo ""

exec npx vite --host 0.0.0.0 --port 5173
