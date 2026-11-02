# SWA AI — Self-Hosted & On-Premises Enterprise Deployment Guide

## Overview
For dedicated on-premises security centers, SOC laboratories, and air-gapped environments, SWA AI runs completely independently without requiring cloud connections or external dependencies.

---

## 1. On-Premises Linux Host Setup
```bash
# Clone and install locally
git clone https://github.com/545e/SWA.git /opt/swa-ai
cd /opt/swa-ai
./install.sh
./run.sh
```

---

## 2. Air-Gapped / Isolated Network Setup

### Step A: On an Internet-Connected Machine
```bash
git clone https://github.com/545e/SWA.git swa-ai
cd swa-ai
pip download -r requirements.txt -d ./wheelhouse
cd ..
tar -czvf swa-offline.tar.gz swa-ai/
```

### Step B: Transfer to Air-Gapped Machine
```bash
tar -xzvf swa-offline.tar.gz
cd swa-ai
bash deploy/self-hosted/offline-install.sh
./run.sh
```

---

## 3. Automated Cron Backups
Add to root crontab (`crontab -e`):
```cron
0 2 * * * /opt/swa-ai/deploy/self-hosted/backup.sh >> /var/log/swa-backup.log 2>&1
```
This script executes online zero-downtime database snapshots every day at 02:00 AM and rotates backups older than 14 days.
