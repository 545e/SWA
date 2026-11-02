# SWA AI — Comprehensive Linux Installation & Operations Guide

**Platform:** Linux (Ubuntu 20.04/22.04/24.04, Debian 11/12, Fedora 38+, Arch Linux, Alpine)  
**Architecture:** x86_64 (AMD64) and aarch64 (ARM64)  
**Python Runtime:** Python 3.10 – 3.12  
**Document Version:** 2.2.0-Enterprise  

---

## 1. Prerequisites & System Packages

### Debian / Ubuntu:
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git curl
```

### Fedora / RHEL / AlmaLinux:
```bash
sudo dnf install -y python3 python3-pip git curl
```

### Arch Linux:
```bash
sudo pacman -S python python-pip git curl
```

### Optional Cybersecurity Tools:
To enable external tool discovery for Nmap, SQLmap, Nikto, and ClamAV:
```bash
sudo apt install -y nmap sqlmap nikto clamav
```

---

## 2. Automated Installation (`install.sh`)

SWA AI provides a dedicated POSIX installation script:

```bash
git clone https://github.com/545e/SWA.git
cd SWA
chmod +x install.sh
./install.sh
```

### What `install.sh` Does:
1. Validates that `python3` (3.10+) is installed.
2. Creates an isolated virtual environment in `./venv`.
3. Auto-provisions `.env` configuration from `.env.example`.
4. Upgrades `pip` and installs pinned dependencies from `requirements.txt`.
5. Registers the `swa` command via `pip install -e .`.
6. Sets execute permissions on runtime launcher scripts.

---

## 3. Starting, Stopping, and Restarting

### Start SWA AI:
```bash
./run.sh
```
Or directly with Python in background (daemon mode):
```bash
source venv/bin/activate
nohup python3 run.py > swa.log 2>&1 &
```

### Stop SWA AI:
```bash
./stop.sh
```
This reads `.swa.pid` and safely issues `SIGTERM` to allow SQLite WAL checkpointing, or falls back to port 8000 process termination.

### Restart SWA AI:
```bash
./stop.sh && ./run.sh
```

---

## 4. Systemd Service Setup (Production Linux Daemon)

For unattended 24/7 autonomous monitoring on Linux servers:

Create `/etc/systemd/system/swa.service`:
```ini
[Unit]
Description=SWA AI Autonomous Cyber Platform
After=network.target

[Service]
Type=simple
User=swa
WorkingDirectory=/opt/SWA
ExecStart=/opt/SWA/venv/bin/python /opt/SWA/run.py
Restart=always
RestartSec=5
Environment=HEADLESS=1
Environment=SWA_PORT=8000
Environment=SWA_HOST=0.0.0.0

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now swa
sudo systemctl status swa
```

---

## 5. Verification & Health Check

After launching, verify platform health:
```bash
curl -s http://127.0.0.1:8000/api/health | jq .
curl -s http://127.0.0.1:8000/api/agents/summary | jq .
```
Expected output:
```json
{
  "total_discovered": 85,
  "total_registered": 85,
  "status": "OPERATIONAL"
}
```
