#!/usr/bin/env bash
# ======================================================================
#   SWA AI - Enterprise Air-Gapped / Offline Installation Helper
# ======================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT_DIR"

echo "======================================================================"
echo "  SWA AI - Enterprise Air-Gapped / Offline Installer"
echo "======================================================================"

WHEELHOUSE_DIR="$ROOT_DIR/wheelhouse"

if [ ! -d "$WHEELHOUSE_DIR" ]; then
    echo "[-] Wheelhouse directory not found at $WHEELHOUSE_DIR."
    echo "[!] To prepare an air-gapped bundle on an internet-connected machine:"
    echo "    pip download -r requirements.txt -d ./wheelhouse"
    echo "    tar -czvf swa-offline.tar.gz ."
    exit 1
fi

echo "[*] Creating virtual environment from local Python..."
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

echo "[*] Installing wheels from local wheelhouse (offline mode)..."
pip install --no-index --find-links="$WHEELHOUSE_DIR" -r requirements.txt

if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    cp .env.example .env
fi

chmod +x run.sh install.sh swa_cli.py

echo "[✓] Offline installation complete! Launch using: ./run.sh"
