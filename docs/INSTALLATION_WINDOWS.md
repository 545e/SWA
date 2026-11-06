# SWA AI — Comprehensive Windows Installation & Operations Guide
**Platform:** Microsoft Windows 10 / Windows 11 (64-bit) / Windows Server 2022  
**Python Runtime:** Python 3.10 – 3.12 (64-bit recommended)  
**Document Version:** 3.0.0-Enterprise  

---

## 1. Prerequisites & Environment Setup

Before launching SWA AI on Windows, ensure the following components are installed:

1. **Python 3.10 to 3.12:**
   - Download the official installer from [python.org](https://www.python.org/downloads/windows/).
   - **Crucial:** During installation, check the box **"Add python.exe to PATH"**.
2. **Git for Windows:**
   - Download from [git-scm.com](https://git-scm.com/).
3. **Optional External Tools (For Extended Network Recon):**
   - **Nmap:** Install from [nmap.org](https://nmap.org/download.html) and add to system PATH.
   - **Node.js (for REA Engine):** Install Node.js LTS (v18+) if binary reverse engineering of Electron/JS apps is needed.

---

## 2. One-Click Automated Installation (`install.bat`)

SWA AI includes an automated Windows installer that provisions the Python virtual environment and dependencies:

```cmd
git clone https://github.com/545e/snmk.git
cd SWA
install.bat
```

The installer will automatically:
1. Verify Python and Git installations.
2. Create an isolated virtual environment (`.venv`).
3. Upgrade `pip`, `setuptools`, and `wheel`.
4. Install all runtime dependencies from `requirements.txt`.
5. Initialize the SQLite database schema (`swa_data.db`).
6. Launch the server immediately on `http://127.0.0.1:8000`.

---

## 3. Starting the Platform (`run.bat` or `run.ps1`)

To start SWA AI at any time:

### Command Prompt:
```cmd
cd SWA
run.bat
```

### PowerShell:
```powershell
Set-Location C:\Users\krish\SWA
.\run.ps1
```

### Direct Python Execution:
```powershell
python run.py
```

The server binds cleanly to `http://127.0.0.1:8000` and automatically opens your default web browser to the SWA AI Executive Dashboard.

---

## 4. Port Conflict Resolution & Troubleshooting

- **Port 8000 Already in Use:**
  If another process is listening on port 8000, free the port using PowerShell:
  ```powershell
  Get-Process -Id (Get-NetTCPConnection -LocalPort 8000).OwningProcess | Stop-Process -Force
  ```
- **Permission Errors on Windows:**
  Always run commands inside PowerShell or CMD with standard user privileges. Avoid running as an elevated Administrator unless binding to low system ports (< 1024).

