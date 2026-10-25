#!/usr/bin/env bash
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

echo "==================================================="
echo "  SWA AI - Security Operations Center & Cyber Hub"
echo "==================================================="
echo "[+] Starting SWA AI Web Server on http://127.0.0.1:8000"
python3 run.py "$@"
