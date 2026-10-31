# SWA AI — Comprehensive Repository Audit

**Date:** 2026-10-30  
**Repository:** https://github.com/545e/SWA.git  
**Version:** 2.1.0  
**Environment:** Windows 10/11 Enterprise x64, Python 3.12 / 3.15  
**Auditor:** Principal Software & Security Engineering Review  

---

## 1. Executive Overview

This audit covers the structural, functional, operational, and security review of the **SWA AI (Autonomous Security Auditor)** repository. SWA AI is a hybrid red-team / blue-team cybersecurity platform providing autonomous vulnerability scanning, reconnaissance, OSINT analysis, path fuzzing, verifiable cURL PoC generation, WAF/IDS defense compilation, and log forensics.

---

## 2. File & Directory Inventory

| Path | Category | Purpose | Status |
| :--- | :--- | :--- | :---: |
| `agents/` | Core Logic | Autonomous scanning & recon agents (`amass_engine.py`, `attack_surface_agent.py`, `fuzzer_agent.py`, `orchestrator.py`, `recon_agent.py`, `vuln_hunter_agent.py`) | Operational |
| `core/` | System & Utility | Scope enforcement, SQLite database, AI hardware training, model evaluation, LLM red-teaming, cyber tools toolkit, WAF bypass, bug bounty hub, notifier | Operational |
| `config/` | Configuration | Target allowlist definitions (`targets.json`) | Operational |
| `data/` | Data Storage | Default persistent directory for database, uploads, and training artifacts | Operational |
| `docs/` | Documentation | Architecture, API reference, deployment, command manuals, troubleshooting | Verified & Updated |
| `plugins/` | Vulnerability Checks | Modular OWASP Top 10 exploits (`base_plugin.py`, `owasp_plugins.py`, `plugin_manager.py`) | Operational |
| `reports/` | Reporting & Audits | Multi-format report exporter (`generator.py`) and engineering audit reports | Operational |
| `tests/` | QA & Testing | Automated test suite (65 comprehensive tests covering all modules) | 100% Passing |
| `web/` | Presentation Layer | FastAPI server (`server.py`) and responsive SOC dark-navy interface (`app.js`, `index.html`, `styles.css`) | Operational |
| `install.bat` / `run.bat` | Windows Scripts | 1-click Windows installer and launcher with dependency health checks | Repaired |
| `install.sh` / `run.sh` | Linux/macOS Scripts | POSIX bash installer and service launcher | Verified |
| `run.ps1` | PowerShell | Native PowerShell runner with execution-policy guidance | Verified |
| `run.py` | Universal Runner | Standalone Python launch runner for FastAPI/Uvicorn | Operational |
| `swa_cli.py` | CLI Interface | Full-featured command-line interface with subcommands and daemon mode | Operational |
| `Dockerfile` | Containerization | Docker build specification with non-root security context | Hardened |
| `docker-compose.yml` | Orchestration | Production Compose definition with resource limits (2 vCPU / 3 GB RAM) | Hardened |

---

## 3. Dependency & Package Mapping

### Production Runtime Dependencies (`requirements.txt`)
- `fastapi>=0.110.0`: Async web API engine and WebSocket broker
- `uvicorn>=0.28.0`: High-performance ASGI server
- `httpx>=0.27.0`: Async HTTP client with connection pooling
- `pydantic>=2.6.0` & `pydantic_core`: Robust schema validation and model serialization
- `beautifulsoup4>=4.12.0`: HTML attack surface parsing and endpoint discovery
- `websockets>=12.0`: Live bi-directional real-time telemetry feed
- `jinja2>=3.1.0`: Dynamic HTML/Markdown report rendering engine
- `dnspython>=2.6.0`: Asynchronous multi-record DNS resolution and SPF/DMARC analysis
- `cryptography>=42.0.0`: Cryptographic hash validation, cipher inspection, and token verification
- `tldextract>=5.1.0`: Robust apex domain and subdomain parsing
- `pyyaml>=6.0`: Structured configuration parsing
- `python-multipart>=0.0.9`: Secure file upload parsing for dataset ingestion
- `setuptools>=69.0.0`: Package installation and CLI distribution

### Development & Testing Dependencies (`requirements-dev.txt`)
- `pytest>=8.0.0`: Automated test runner
- `pytest-cov>=5.0.0`: Test coverage metrics and reporting

---

## 4. Key Defects Discovered & Remediated

### Defect 1: Python Wheel Binary Architecture Incompatibility (`pydantic_core`)
- **Root Cause:** A pre-existing wheel for Python 3.12 (`_pydantic_core.cp312-win_amd64.pyd`) was present in the virtual environment when executed under Python 3.15, causing an unresolved symbol import `cannot import name 'ArgsKwargs' from 'pydantic_core._pydantic_core'`.
- **Remediation:** Reinstalled matching binary wheels for `pydantic` and `pydantic_core`. Added detailed error diagnostics to `run.bat` so future wheel issues clearly output root causes instead of generic failures.

### Defect 2: SQLite Connection Resource Leak in `core/database.py`
- **Root Cause:** Methods called `with self.get_connection() as conn:`. In Python's `sqlite3`, entering a connection context manager only manages transaction commit/rollback and does not close the connection upon exit. This resulted in leaked open file handles and multiple `ResourceWarning: unclosed database in <sqlite3.Connection>` warnings.
- **Remediation:** Refactored `get_connection()` into a context manager using `@contextlib.contextmanager` with guaranteed `conn.close()` inside a `finally` block and a `timeout=30.0` configuration to prevent SQLite concurrency deadlocks.

### Defect 3: Massive DOM Duplication in `web/static/index.html` (5,222 Redundant Lines)
- **Root Cause:** Commit `4562fb3` inadvertently duplicated the extended SOC tabs (`tabAssets`, `tabCompare`, `tabAiDatasets`, `tabAiTraining`, `tabAiEvaluation`, `tabLlmRedTeam`, `tabToolRegistry`) 14 times across multiple tab containers, causing invalid duplicate DOM IDs and browser slowdown.
- **Remediation:** Removed the 14 duplicate code blocks (5,222 lines) while preserving the single valid instance in the main tab content container. Reduced `index.html` from 8,485 lines down to 3,263 lines of clean, standards-compliant HTML.

### Defect 4: Missing Test Dependencies in Clean Environments
- **Root Cause:** `pytest` was omitted from `requirements.txt` and `setup.py`, causing `No module named pytest` when users or CI ran automated tests.
- **Remediation:** Added `extras_require={"test": [...]}` in `setup.py` and created `requirements-dev.txt`.

### Defect 5: Unhardened Container Configuration
- **Root Cause:** `Dockerfile` ran as `root`, lacked non-root user isolation, and `docker-compose.yml` lacked memory and CPU resource caps.
- **Remediation:** Added unprivileged `swa` user/group in `Dockerfile` and configured 2.0 vCPU and 3,072 MB RAM limits in `docker-compose.yml`.

---

## 5. Verification Summary

- **Total Test Cases Executed:** 65
- **Tests Passed:** 65 (100%)
- **Tests Failed:** 0
- **Regression Check:** Zero `ResourceWarning` occurrences with `-W error::ResourceWarning`.
