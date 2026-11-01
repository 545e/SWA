# SWA AI — Cross-Platform Compatibility Specification & Matrix

**Date:** 2026-11-01  
**Version:** 2.2.0-Enterprise  

---

## 1. Operating System Support Matrix

| Platform | Architecture | Supported | Installer Script | Runner Script | Stop Script |
| :--- | :--- | :---: | :--- | :--- | :--- |
| **Windows 10 / 11** | x86_64 / ARM64 | ✅ Fully Supported | `install.bat`, `install.ps1` | `run.bat`, `run.ps1` | `stop.bat`, `stop.ps1` |
| **Windows Server 2019/2022** | x86_64 | ✅ Fully Supported | `install.bat`, `install.ps1` | `run.bat`, `run.ps1` | `stop.bat`, `stop.ps1` |
| **Ubuntu 20.04 / 22.04 / 24.04** | x86_64 / aarch64 | ✅ Fully Supported | `install.sh` | `run.sh` | `stop.sh` |
| **Debian 11 / 12** | x86_64 / aarch64 | ✅ Fully Supported | `install.sh` | `run.sh` | `stop.sh` |
| **Fedora / RHEL / AlmaLinux** | x86_64 / aarch64 | ✅ Fully Supported | `install.sh` | `run.sh` | `stop.sh` |
| **macOS Apple Silicon (M1-M4)** | arm64 | ✅ Fully Supported | `install_macos.sh` | `run_macos.sh` | `stop_macos.sh` |
| **macOS Intel** | x86_64 | ✅ Fully Supported | `install_macos.sh` | `run_macos.sh` | `stop_macos.sh` |
| **Docker / Container** | Linux/AMD64/ARM64 | ✅ Fully Supported | `docker-compose up` | `Dockerfile` | `docker-compose down` |

---

## 2. Platform-Aware Process & File Management

### Path Handling:
- All file paths use Python's `pathlib.Path` or `os.path.join()` ensuring cross-platform separator neutrality.
- Web assets and REST endpoints use forward-slash conventions exclusively.
- Dynamic path normalizers prevent directory traversal attacks regardless of OS directory conventions.

### Signal Handling & Graceful Termination:
- On startup, `run.py` writes the current process PID to `.swa.pid`.
- On Linux and macOS, `stop.sh` and `stop_macos.sh` issue standard POSIX `SIGTERM`, allowing Uvicorn to flush pending requests and SQLite to complete Write-Ahead Log (WAL) checkpoints.
- On Windows, `stop.bat` and `stop.ps1` issue process tree termination via `taskkill /PID <pid> /F /T` or PowerShell `Stop-Process`.
- When Uvicorn terminates, a `finally` block in `run.py` removes `.swa.pid`.

---

## 3. Security Tool Compatibility by Platform

| Tool / Engine | Windows | Linux | macOS | Capability-Based Fallback |
| :--- | :---: | :---: | :---: | :--- |
| **Nmap** | ✅ Choco / Installer | ✅ `apt` / `dnf` | ✅ `brew` | Native Async TCP Socket Scanner |
| **Nuclei** | ✅ Binary / Go | ✅ Binary / Go | ✅ `brew` | Native OWASP Security Plugin Probes |
| **SQLmap** | ✅ Pip / Git | ✅ `apt` / Pip | ✅ `brew` / Pip | Native SQL Injection Probe Suite |
| **Nikto** | ✅ Git / Perl | ✅ `apt` | ✅ `brew` | Native Web Server Header & Configuration Auditor |
| **Trivy** | ✅ Choco / Binary | ✅ `apt` / Binary | ✅ `brew` | Native AST Secret & Dependency Inspector |
| **Gitleaks** | ✅ Choco / Binary | ✅ Binary | ✅ `brew` | GhostJS AST Engine (`core/js_intelligence.py`) |
| **Microsoft Defender** | ✅ Native PowerShell | ❌ (W/A) | ❌ (W/A) | ClamAV / Host Endpoint Telemetry Engine |
| **ClamAV** | ⚠️ Optional | ✅ Native `apt` | ✅ `brew install clamav` | Native Malware Signature Auditor |
| **TotalAV** | ⚠️ Desktop GUI Only | ❌ (No Linux GUI) | ❌ (No macOS CLI) | Documented Vendor Limitation (GUI only) |
| **REA Disassembler** | ✅ Python Native | ✅ Python Native | ✅ Python Native | Native PE/ELF/Mach-O Parsing Engine |

---

## 4. Continuous Integration Pipeline
Cross-platform automated testing is enforced on every Pull Request and branch push via GitHub Actions (`.github/workflows/ci.yml`):
- `windows-latest`
- `ubuntu-latest`
- `macos-latest`
