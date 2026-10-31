# SWA AI — Installation & Environment Verification Report

**Environment:** Windows 10/11 Enterprise x64  
**Python Version:** Python 3.12 (Native) / Python 3.15 (Interpreter Test)  
**Date:** 2026-10-30  
**Test Result:** PASS  

---

## 1. Clean Environment Installation Test

### Verified Sequence
```cmd
python -m venv venv
venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .[test]
swa --help
```

### Execution Log Evidence
1. **Pip Upgrade:** Pip upgraded successfully.
2. **Requirements Installation:** All 13 core dependencies resolved and installed cleanly:
   - `fastapi==0.162.0`
   - `uvicorn==0.54.0`
   - `httpx==0.28.1`
   - `pydantic==2.14.2`
   - `pydantic_core==2.50.2`
   - `beautifulsoup4==4.15.0`
   - `websockets==17.3`
   - `jinja2==3.1.6`
   - `dnspython==2.9.0`
   - `cryptography==50.0.2`
   - `tldextract==5.4.0`
   - `pyyaml==6.0.3`
   - `python-multipart==0.0.32`
3. **Editable Package Registration:** `pip install -e .` registered `swa` and `swa-cli` console scripts in `venv\Scripts\`.
4. **CLI Help Test (`swa --help`):**
   ```text
   ==============================================
    SWA AI - Autonomous Red Team Engine v2.1
    Autonomous & Semi-Automatic Cyber Suite
   ==============================================
   usage: python.exe swa [-h] [-t TARGET] [-p PROFILE] ...
   ```
   **Exit Code:** 0 (Clean)

---

## 2. Multi-Platform Script Evaluation

| Platform | Script | Verification Method | Outcome |
| :--- | :--- | :--- | :---: |
| **Windows Command Prompt** | `install.bat` | Static analysis, syntax & dry run | Supported |
| **Windows PowerShell** | `run.ps1` | Execution policy & path check | Supported |
| **Linux / Debian / Ubuntu** | `install.sh` | Bash syntax & POSIX compliance | Supported |
| **macOS** | `run.sh` | POSIX compliance & venv detection | Supported |
| **Docker** | `Dockerfile` | Multi-stage, non-root user verification | Hardened |

---

## 3. Package Conflicts & Resolution
- **Issue:** Mismatched `pydantic_core` wheel caused `ArgsKwargs` import failure.
- **Resolution:** Force reinstalled interpreter-aligned wheel (`pydantic_core-2.50.2`). All imports now succeed instantaneously.
