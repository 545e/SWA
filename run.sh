#!/usr/bin/env bash
set -e

# Change to script directory
cd "$(dirname "$0")"

if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

echo "==================================================="
echo "  SWA AI - Security Operations Center & Cyber Hub"
echo "==================================================="
echo "[+] Starting SWA AI Web Server on http://127.0.0.1:8000"
echo "[+] Browser will open automatically."
echo "[+] Keep this terminal window OPEN while using SWA."
echo ""

python3 run.py "$@"
