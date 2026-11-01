# Installation Audit Report

**Date:** 2026-11-01  
**Auditor:** DevSecOps & Installation Engineering Team  

## 1. Inspected Installation Files
- `install.bat`: Windows batch installer with auto-detection of `python`, `py -3`, `python3`
- `install.sh`: Linux/Unix shell installer with venv creation and permission grants
- `run.bat`: Windows launcher with dependency check and browser auto-launch
- `run.ps1`: Modern PowerShell runner with colored logging and error handling
- `run.py`: Multi-platform Python entry point with port conflict detection and auto-switch
- `setup.py`: Setuptools configuration for `pip install -e .` and console script `swa`

## 2. Root Cause Analysis of Previous Installation Friction
- **Root Cause 1:** Stale port occupation. When port 8000 was held by a background process, `run.py` dynamically bound to 8001, but the browser was hardcoded to open 8000.
- **Fix 1:** Created transparent proxy on 8001 forwarding to 8000 and aligned launcher scripts.
- **Root Cause 2:** Working directory mismatches when double-clicking `.bat` files.
- **Fix 2:** Added `cd /d "%~dp0"` to force execution from script location.
