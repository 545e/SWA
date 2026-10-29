#!/usr/bin/env bash
set -e

echo "==================================================="
echo "  SWA AI - Autonomous Cyber Tool Suite Installer"
echo "==================================================="
echo ""

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo "[-] python3 not found. Please install Python 3.10+ (e.g. apt install python3 python3-pip python3-venv)"
    exit 1
fi

echo "[+] Python detected: $(python3 --version)"

# Check virtual environment
if [ ! -d "venv" ]; then
    echo "[+] Creating virtual environment in ./venv..."
    python3 -m venv venv || true
fi

if [ -f "venv/bin/activate" ]; then
    echo "[+] Activating virtual environment..."
    source venv/bin/activate
fi

# Initialize .env if missing
if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    echo "[+] Initializing default .env from .env.example..."
    cp .env.example .env
fi

echo "[+] Upgrading pip and installing requirements..."
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
python3 -m pip install -e .

chmod +x run.sh || true
chmod +x swa_cli.py || true

echo ""
echo "==================================================="
echo " [✓] SWA AI successfully installed and configured!"
echo " Run './run.sh' or 'python3 run.py' to launch."
echo " Run 'swa --help' or 'python3 swa_cli.py --help' for CLI."
echo "==================================================="
