#!/usr/bin/env bash
# SWA AI — macOS Application Runner
set -e

cd "$(dirname "$0")"

# Activate virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

# Add standard Homebrew paths to PATH if present
if [ -d "/opt/homebrew/bin" ]; then
    export PATH="/opt/homebrew/bin:$PATH"
fi
if [ -d "/usr/local/bin" ]; then
    export PATH="/usr/local/bin:$PATH"
fi

echo "==================================================="
echo "  SWA AI — Security Operations Center & Cyber Hub"
echo "  Platform: macOS ($(uname -m))"
echo "==================================================="
echo "[+] Web Interface: http://127.0.0.1:8000"
echo "[+] Starting application server..."
echo ""

python3 run.py "$@"
