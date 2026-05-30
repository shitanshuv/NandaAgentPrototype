#!/usr/bin/env bash
# ============================================================
# NANDA Prototype — Start Script
# Launches registry (8000), agent_host (8001),
# enterprise_registry (8002), dashboard (8080),
# then seeds all demo agents.
# ============================================================
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

cleanup() {
  echo ""
  echo "Shutting down services..."
  kill $REG_PID $AGT_PID $ENT_PID $DSH_PID 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo ""
echo "======================================"
echo "  NANDA Index Prototype"
echo "======================================"
echo ""

if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 not found"
  exit 1
fi

echo "[1/5] Installing dependencies..."
pip install fastapi uvicorn cryptography requests pytest httpx -q --break-system-packages 2>/dev/null || \
pip install fastapi uvicorn cryptography requests pytest httpx -q

echo "[2/5] Starting Registry (port 8000)..."
python3 -m uvicorn registry.main:app --host 0.0.0.0 --port 8000 --log-level warning &
REG_PID=$!

echo "[3/5] Starting Agent Host (port 8001)..."
python3 -m uvicorn agent_host.main:app --host 0.0.0.0 --port 8001 --log-level warning &
AGT_PID=$!

echo "[4/5] Starting Enterprise Registry (port 8002)..."
python3 -m uvicorn enterprise_registry.main:app --host 0.0.0.0 --port 8002 --log-level warning &
ENT_PID=$!

echo "[5/5] Starting Dashboard (port 8080)..."
python3 -m uvicorn dashboard.main:app --host 0.0.0.0 --port 8080 --log-level warning &
DSH_PID=$!

sleep 2
echo ""
echo "Seeding demo agents..."
python3 scripts/seed_agents.py

echo ""
echo "======================================"
echo "  Services running:"
echo "  Registry            → http://localhost:8000"
echo "  Agent Host          → http://localhost:8001"
echo "  Enterprise Registry → http://localhost:8002"
echo "  Dashboard           → http://localhost:8080"
echo "======================================"
echo ""
echo "Client commands:"
echo '  python3 client/resolver.py list'
echo '  python3 client/resolver.py resolve "urn:agent:nanda:TranslationAssistant"'
echo '  python3 client/resolver.py resolve "urn:agent:nanda:WeatherAgent"'
echo '  python3 client/resolver.py resolve "urn:agent:acme:SalesAgent"          # enterprise two-hop'
echo '  python3 client/resolver.py resolve "urn:agent:nanda:TranslationAssistant" --tamper'
echo '  python3 client/resolver.py resolve "urn:agent:nanda:TranslationAssistant" --private'
echo '  python3 client/resolver.py cache-demo "urn:agent:nanda:TranslationAssistant"'
echo '  python3 client/resolver.py revoke <agent_id>                             # then resolve again'
echo ""
echo "Run tests:"
echo '  pytest tests/test_nanda.py -v'
echo ""
echo "Press Ctrl+C to stop all services."
echo ""

wait $REG_PID
