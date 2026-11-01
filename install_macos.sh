#!/usr/bin/env bash
# SWA AI — macOS Installation Script (Apple Silicon & Intel)
set -e

# Change to script directory
cd "$(dirname "$0")"

echo "==================================================="
echo "  SWA AI — macOS Installation & Setup"
echo "  Supporting Apple Silicon (M1/M2/M3/M4) and Intel"
echo "==================================================="
echo ""

# Detect architecture
ARCH=$(uname -m)
echo "[+] Detected macOS Architecture: $ARCH"

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo "[-] python3 not found in PATH."
    if command -v brew &> /dev/null; then
        echo "[+] Homebrew detected. Installing python@3.12..."
        brew install python@3.12
    else
        echo "[!] Please install Python 3.10+ via Homebrew ('brew install python') or from python.org."
        exit 1
    fi
fi

PYTHON_VER=$(python3 --version)
echo "[+] Using Python: $PYTHON_VER"

# Check optional security tools via Homebrew
if command -v brew &> /dev/null; then
    echo "[+] Checking optional cybersecurity tools via Homebrew..."
    for tool in nmap nuclei sqlmap nikto trivy gitleaks; do
        if command -v "$tool" &> /dev/null; then
            echo "    [✓] $tool is available"
        else
            echo "    [i] $tool is not installed (optional, install with 'brew install $tool')"
        fi
    done
fi

# Setup isolated virtual environment
if [ ! -d "venv" ]; then
    echo "[+] Creating virtual environment in ./venv ..."
    python3 -m venv venv
fi

if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

# Provision .env if missing
if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    echo "[+] Creating .env from .env.example ..."
    cp .env.example .env
fi

# Upgrade pip & install requirements
echo "[+] Upgrading pip in environment ..."
python3 -m pip install --upgrade pip

echo "[+] Installing SWA AI dependencies from requirements.txt ..."
python3 -m pip install -r requirements.txt

# Register swa CLI
echo "[+] Registering swa CLI command ..."
python3 -m pip install -e .

chmod +x run.sh || true
chmod +x run_macos.sh || true
chmod +x stop.sh || true
chmod +x stop_macos.sh || true
chmod +x swa_cli.py || true

echo ""
echo "==================================================="
echo " [✓] SWA AI successfully installed on macOS ($ARCH)!"
echo " Run './run_macos.sh' or './run.sh' to launch."
echo " Run './stop_macos.sh' or './stop.sh' to shutdown."
echo " Run 'swa --help' for CLI security commands."
echo "==================================================="
