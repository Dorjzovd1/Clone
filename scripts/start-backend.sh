#!/usr/bin/env bash
# Backend — дотоод сүлжээ + localhost (0.0.0.0:8000)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/backend"

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
pip install -r requirements.txt -q
cp -n .env.example .env 2>/dev/null || true

LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo ""
echo "==> Backend эхэлж байна..."
echo "    Local:   http://127.0.0.1:8000/api/health"
echo "    Network: http://${LAN_IP:-?}:8000/api/health"
echo "    (USB scan-д sudo шаардлагатай)"
echo ""

if [[ "${EUID}" -ne 0 ]]; then
  exec sudo "$ROOT/backend/.venv/bin/uvicorn" app.main:app --reload --host 0.0.0.0 --port 8000
else
  exec "$ROOT/backend/.venv/bin/uvicorn" app.main:app --reload --host 0.0.0.0 --port 8000
fi
