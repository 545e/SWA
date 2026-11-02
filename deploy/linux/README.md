# SWA AI — Linux VPS & Server Deployment Guide

## Supported Platforms
- Ubuntu 20.04 / 22.04 / 24.04 LTS
- Debian 11 / 12
- Kali Linux (Enterprise Lab Host)
- RHEL / Rocky Linux 9

---

## 1. Quick Automated Deployment
Run the automated deployment script as root:
```bash
sudo bash deploy/linux/deploy.sh
```

---

## 2. Manual Step-by-Step Deployment

### Step 1: Install System Packages
```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git curl nginx certbot python3-certbot-nginx
```

### Step 2: Create Dedicated Service User
```bash
sudo useradd -r -s /bin/false -d /opt/swa-ai -m swa
```

### Step 3: Clone Repository
```bash
sudo git clone https://github.com/545e/SWA.git /opt/swa-ai
sudo chown -R swa:swa /opt/swa-ai
cd /opt/swa-ai
```

### Step 4: Setup Virtual Environment & Dependencies
```bash
sudo -u swa python3 -m venv .venv
sudo -u swa .venv/bin/pip install --upgrade pip
sudo -u swa .venv/bin/pip install -r requirements.txt
sudo -u swa cp .env.example .env
```

### Step 5: Install Systemd Service
```bash
sudo cp deploy/linux/swa.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now swa
```

### Step 6: Configure Nginx & SSL
```bash
sudo cp deploy/linux/nginx.conf /etc/nginx/sites-available/swa
# Edit server_name inside /etc/nginx/sites-available/swa
sudo ln -s /etc/nginx/sites-available/swa /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
sudo certbot --nginx -d swa.example.com
```

---

## 3. Maintenance, Monitoring & Rollback

- **Check Service Status**: `sudo systemctl status swa`
- **View Live Logs**: `sudo journalctl -u swa -f`
- **Health Check**: `curl http://127.0.0.1:8000/health`
- **Database Backup**: `sudo -u swa /opt/swa-ai/.venv/bin/python -c "from core.database import db; print(db.backup_database())"`
- **Restart Application**: `sudo systemctl restart swa`
- **Rollback Version**:
  ```bash
  cd /opt/swa-ai
  sudo -u swa git checkout <PREVIOUS_COMMIT_TAG>
  sudo -u swa .venv/bin/pip install -r requirements.txt
  sudo systemctl restart swa
  ```
