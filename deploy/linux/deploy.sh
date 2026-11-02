#!/usr/bin/env bash
# ======================================================================
#   SWA AI - Automated Linux VPS Deployment Script
#   Target: Ubuntu 22.04 / 24.04 LTS, Debian 12, Kali Linux
# ======================================================================

set -euo pipefail

INSTALL_DIR="/opt/swa-ai"
USER_NAME="swa"

echo "======================================================================"
echo "  SWA AI - Automated Linux VPS Production Setup"
echo "======================================================================"

if [ "$(id -u)" -ne 0 ]; then
    echo "[-] This script must be run as root (use sudo)."
    exit 1
fi

echo "[1/6] Installing system prerequisites..."
apt-get update -y
apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    nginx \
    certbot \
    python3-certbot-nginx

echo "[2/6] Creating dedicated application user ($USER_NAME)..."
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
    useradd -r -s /bin/false -d "$INSTALL_DIR" -m "$USER_NAME"
fi

echo "[3/6] Setting up project directory at $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp -r . "$INSTALL_DIR/"
chown -R "$USER_NAME:$USER_NAME" "$INSTALL_DIR"

echo "[4/6] Creating Python virtual environment..."
sudo -u "$USER_NAME" python3 -m venv "$INSTALL_DIR/.venv"
sudo -u "$USER_NAME" "$INSTALL_DIR/.venv/bin/pip" install --upgrade pip --quiet
sudo -u "$USER_NAME" "$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

if [ ! -f "$INSTALL_DIR/.env" ]; then
    sudo -u "$USER_NAME" cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
fi

echo "[5/6] Installing systemd service..."
cp "$INSTALL_DIR/deploy/linux/swa.service" /etc/systemd/system/swa.service
systemctl daemon-reload
systemctl enable swa.service
systemctl restart swa.service

echo "[6/6] Verifying service health..."
sleep 3
if curl -sf http://127.0.0.1:8000/health >/dev/null; then
    echo "[✓] SWA AI service is HEALTHY and active on http://127.0.0.1:8000"
else
    echo "[!] Warning: SWA AI did not respond to initial healthcheck. Inspect: journalctl -u swa.service -n 50"
fi

echo ""
echo "======================================================================"
echo " [✓] Deployment Complete!"
echo " Next Steps:"
echo " 1. Configure Nginx: sudo cp $INSTALL_DIR/deploy/linux/nginx.conf /etc/nginx/sites-available/swa"
echo " 2. Enable site:     sudo ln -s /etc/nginx/sites-available/swa /etc/nginx/sites-enabled/"
echo " 3. Obtain SSL:      sudo certbot --nginx -d your-domain.com"
echo " 4. Check status:    sudo systemctl status swa.service"
echo "======================================================================"
