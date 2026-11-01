#!/usr/bin/env bash
# SWA AI — macOS Server Shutdown Script
set -e

cd "$(dirname "$0")"

echo "==================================================="
echo "  SWA AI — Shutdown Server (macOS)"
echo "==================================================="

if [ -f ".swa.pid" ]; then
    PID=$(cat .swa.pid)
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "[+] Terminating SWA AI server (PID $PID)..."
        kill -TERM "$PID" || kill -9 "$PID"
        rm -f .swa.pid
        echo "[✓] SWA AI server stopped successfully."
        exit 0
    fi
    rm -f .swa.pid
fi

# Fallback: check listening port 8000
L_PID=$(lsof -ti:8000 2>/dev/null || true)
if [ -n "$L_PID" ]; then
    echo "[+] Found listening process on port 8000 (PID $L_PID). Terminating..."
    kill -TERM "$L_PID" 2>/dev/null || kill -9 "$L_PID" 2>/dev/null
    echo "[✓] SWA AI server stopped."
    exit 0
fi

echo "[i] No active SWA AI server found running on port 8000."
