#!/bin/bash
# ======================================================================
#   SWA AI - AWS EC2 Cloud-Init User Data Script
#   Target: Amazon Linux 2023 / Ubuntu 22.04 LTS
# ======================================================================

set -e

echo "[*] Initializing SWA AI on Amazon EC2..."

# 1. Update and install Docker & Git
yum update -y || apt-get update -y
yum install -y docker git curl || apt-get install -y docker.io git curl

systemctl enable --now docker

# 2. Install Docker Compose plugin
DOCKER_CONFIG=${DOCKER_CONFIG:-/usr/local/lib/docker}
mkdir -p $DOCKER_CONFIG/cli-plugins
curl -SL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64 -o $DOCKER_CONFIG/cli-plugins/docker-compose
chmod +x $DOCKER_CONFIG/cli-plugins/docker-compose

# 3. Clone SWA AI repository
mkdir -p /opt/swa-ai
cd /opt/swa-ai
git clone https://github.com/545e/SWA.git .

# 4. Copy production environment file
cp deploy/docker/.env.production.example .env

# 5. Start container via Docker Compose
docker compose -f deploy/docker/docker-compose.prod.yml up -d --build

echo "[✓] SWA AI launched on EC2 instance (Port 8000)."
