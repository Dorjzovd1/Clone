#!/usr/bin/env bash
# Backend + Frontend хоёуланг асаах (2 терминал шаардлагатай бол эхний хоёрыг тусад нь ажиллуулна)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

echo "============================================"
echo "  REA — Removable Evidence Analyzer"
echo "============================================"
echo ""
echo "  UI (дотоод сүлжээ):  http://${LAN_IP:-192.168.x.x}:5173"
echo "  API:                 http://${LAN_IP:-192.168.x.x}:8000"
echo ""
echo "  Терминал 1:  ./scripts/start-backend.sh"
echo "  Терминал 2:  ./scripts/start-frontend.sh"
echo ""
echo "  Эсвэл доор backend-ийг background-д эхлүүлнэ..."
echo "============================================"
echo ""

chmod +x "$ROOT/scripts/start-backend.sh" "$ROOT/scripts/start-frontend.sh"

# Backend background (sudo password асуух болно)
"$ROOT/scripts/start-backend.sh" &
BACK_PID=$!
sleep 2

trap 'kill $BACK_PID 2>/dev/null || true' EXIT INT TERM

# Frontend foreground
"$ROOT/scripts/start-frontend.sh"
