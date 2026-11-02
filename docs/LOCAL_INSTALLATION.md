# SWA AI — Universal Local Installation & Execution Guide

This guide provides beginner-friendly, step-by-step instructions for installing and running **SWA AI — Autonomous Enterprise Security Auditor** across Windows CMD, Windows PowerShell, Ubuntu, Debian, and Kali Linux.

---

## ⚠️ Common Beginner Mistakes (Please Read First!)

If you open Command Prompt and see:
```text
C:\Users\YourUsername> pip install -r requirements.txt
ERROR: Could not open requirements file: [Errno 2] No such file or directory: 'requirements.txt'
```
or:
```text
'#' is not recognized as an internal or external command
'Copy-Item' is not recognized as an internal or external command
'.\run.ps1' is not recognized as an internal or external command
```

### Why did this happen?
1. **Wrong Directory**: You are currently in `C:\Users\YourUsername`, not inside the cloned SWA repository folder! You must change directory into the project folder first (`cd SWA`).
2. **Mixing Shells**: Commands starting with `#`, `Copy-Item`, or `.\run.ps1` are **PowerShell** commands. They will fail if pasted into classic Windows Command Prompt (`cmd.exe`).

---

## 1. Quick One-Click Installation

| Terminal / OS | Install Command | Run / Launch Command |
| :--- | :--- | :--- |
| **Windows CMD (`cmd.exe`)** | `install.bat` | `run.bat` |
| **Windows PowerShell** | `.\install.ps1` | `.\run.ps1` |
| **Ubuntu / Debian / Kali** | `./install.sh` | `./run.sh` |

> **Automated Handling**: All scripts automatically change directory to the repository folder, verify Python 3.10+, create an isolated `.venv` virtual environment, install requirements, and configure `.env`.

---

## 2. Platform-Specific Step-by-Step Instructions

### Method A: Windows Command Prompt (CMD)

1. Open **Command Prompt** (`cmd.exe`).
2. Navigate to your cloned SWA AI project directory:
   ```cmd
   cd path\to\SWA
   ```
3. Run the installer:
   ```cmd
   install.bat
   ```
4. Start the application:
   ```cmd
   run.bat
   ```
   *The script checks database connectivity and automatically opens your default browser at `http://127.0.0.1:8000`.*

---

### Method B: Windows PowerShell

1. Open **Windows PowerShell** (or Terminal).
2. If script execution is restricted on your system, enable it for the current session:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
   ```
3. Navigate to your SWA AI directory:
   ```powershell
   cd path\to\SWA
   ```
4. Run the installer:
   ```powershell
   .\install.ps1
   ```
5. Start the application:
   ```powershell
   .\run.ps1
   ```

---

### Method C: Ubuntu / Debian / Kali Linux / macOS

1. Open your terminal shell (`bash` or `zsh`).
2. Install Python 3 prerequisites (if not already installed):
   ```bash
   sudo apt update && sudo apt install -y python3 python3-pip python3-venv git curl
   ```
3. Navigate to the repository:
   ```bash
   cd SWA
   ```
4. Run the installer:
   ```bash
   chmod +x install.sh run.sh
   ./install.sh
   ```
5. Launch the platform:
   ```bash
   ./run.sh
   ```
   *The server initializes and opens the web dashboard at `http://127.0.0.1:8000`.*

---

## 3. Manual Installation (For Advanced Developers)

If you prefer to configure your environment manually:

```bash
# 1. Create Python virtual environment
python3 -m venv .venv

# 2. Activate virtual environment
# Windows CMD:
.venv\Scripts\activate.bat
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

# 3. Upgrade pip & install dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# 4. Copy default environment configuration
cp .env.example .env    # On Linux/macOS
copy .env.example .env  # On Windows CMD
Copy-Item .env.example .env # On Windows PowerShell

# 5. Start the web application
python run.py
```

---

## 4. Verification & Health Check

Once the application is running, open your browser to:
- **Web Dashboard**: `http://127.0.0.1:8000`
- **Health Telemetry**: `http://127.0.0.1:8000/health`
- **Readiness Check**: `http://127.0.0.1:8000/ready`
