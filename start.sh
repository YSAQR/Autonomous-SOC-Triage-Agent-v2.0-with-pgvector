#!/usr/bin/env bash
set -euo pipefail

API_HOST="${API_HOST:-127.0.0.1}"
API_PORT="${API_PORT:-8000}"
UI_PORT="${PORT:-7860}"

export API_BASE_URL="${API_BASE_URL:-http://127.0.0.1:${API_PORT}}"

echo "[start.sh] Launching FastAPI backend on ${API_HOST}:${API_PORT}..."
uvicorn app.main:app --host "${API_HOST}" --port "${API_PORT}" --workers 1 &
API_PID=$!

cleanup() {
    echo "[start.sh] Shutting down services..."
    kill "${API_PID}" 2>/dev/null || true
    wait "${API_PID}" 2>/dev/null || true
}
trap cleanup SIGTERM SIGINT EXIT

echo "[start.sh] Waiting for FastAPI /health..."
for i in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1; then
        echo "[start.sh] FastAPI backend is ready."
        break
    fi
    sleep 1
done

echo "[start.sh] Launching Streamlit SOC Analyst Console on 0.0.0.0:${UI_PORT}..."
exec streamlit run dashboard/ui.py \
    --server.address=0.0.0.0 \
    --server.port="${UI_PORT}" \
    --server.headless=true \
    --browser.gatherUsageStats=false
