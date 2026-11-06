# SWA AI — Comprehensive macOS Installation & Operations Guide

**Platform:** macOS 12 Monterey, macOS 13 Ventura, macOS 14 Sonoma, macOS 15 Sequoia  
**Hardware:** Apple Silicon (M1, M2, M3, M4) & Intel (x86_64)  
**Python Runtime:** Python 3.10 – 3.12  
**Document Version:** 2.2.0-Enterprise  

---

## 1. Prerequisites (Homebrew & Python)

On macOS, [Homebrew](https://brew.sh/) is the recommended package manager.

```bash
# Install Homebrew if not already installed:
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3.12 and Git:
brew install python@3.12 git
```

### Apple Silicon Notes (M1/M2/M3/M4):
Homebrew binaries on Apple Silicon install into `/opt/homebrew/bin/`.  
SWA AI's tool discovery engine automatically checks `/opt/homebrew/bin/` as well as standard `/usr/local/bin/`.

### Optional Security Tools via Homebrew:
```bash
brew install nmap nuclei sqlmap nikto trivy gitleaks
```

---

## 2. Automated Installation (`install_macos.sh`)

```bash
git clone https://github.com/545e/snmk.git
cd SWA
chmod +x install_macos.sh
./install_macos.sh
```

### What `install_macos.sh` Does:
1. Detects host architecture (`arm64` or `x86_64`).
2. Checks for Python 3.10+ and Homebrew tool binaries.
3. Creates an isolated virtual environment (`./venv`).
4. Generates `.env` from `.env.example` if not present.
5. Upgrades `pip` and installs pinned dependencies from `requirements.txt`.
6. Sets execution permissions on all shell scripts.

---

## 3. Starting, Stopping, and Restarting

### Start SWA AI on macOS:
```bash
./run_macos.sh
```
Or:
```bash
./run.sh
```
The browser will automatically open to `http://127.0.0.1:8000`.

### Stop SWA AI on macOS:
```bash
./stop_macos.sh
```
Or:
```bash
./stop.sh
```

### Restart SWA AI:
```bash
./stop_macos.sh && ./run_macos.sh
```

---

## 4. Launchd Agent (Optional macOS Background Daemon)

To run SWA AI automatically in the background on macOS:

Create `~/Library/LaunchAgents/com.swa.ai.plist`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.swa.ai</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/username/SWA/venv/bin/python</string>
        <string>/Users/username/SWA/run.py</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/Users/username/SWA</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>HEADLESS</key>
        <string>1</string>
        <key>SWA_PORT</key>
        <string>8000</string>
    </dict>
</dict>
</plist>
```

Load and start:
```bash
launchctl load ~/Library/LaunchAgents/com.swa.ai.plist
```

---

## 5. macOS Security Architecture & Telemetry
- SWA AI detects macOS Gatekeeper and XProtect status via `core/antivirus_edr_manager.py`.
- No root / `sudo` privileges are required for standard web assessments, OWASP scans, and intelligence gathering.
- Low raw-packet scans (e.g. `nmap -sS` SYN scan) require elevated permissions on macOS (`sudo nmap`), or default unprivileged TCP connect scans (`-sT`) are used automatically.

