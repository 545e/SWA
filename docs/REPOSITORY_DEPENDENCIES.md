# SWA AI — Repository Dependencies & Compatibility

## 1. Runtime Environment Requirements

| Operating System | Supported Versions | Shell / Runner | Python Runtime |
|---|---|---|---|
| **Windows** | Windows 10, Windows 11, Windows Server 2019+ | PowerShell 5.1+, PowerShell 7+, CMD | Python 3.10 – 3.12 64-bit |
| **Linux** | Ubuntu 20.04+, Debian 11+, RHEL/CentOS 8+, Alpine | Bash, Zsh, Systemd | Python 3.10 – 3.12 |
| **macOS** | macOS Monterey (12)+, Ventura (13)+, Sonoma (14)+ (Apple Silicon & Intel) | Bash, Zsh | Python 3.10 – 3.12 |
| **Docker** | Docker Engine 20.10+, Docker Compose v2+ | Containerized Linux (Alpine/Debian) | Python 3.11/3.12 |

## 2. Core Python Dependencies

| Package | Minimum Version | Purpose in SWA Platform |
|---|---|---|
| `fastapi` | `>=0.110.0` | Core asynchronous web framework and OpenAPI REST router |
| `uvicorn` | `>=0.29.0` | High-performance ASGI server for HTTP & WebSocket connections |
| `pydantic` | `>=2.6.0` | Strict data validation, schema enforcement, and serialization |
| `cryptography` | `>=42.0.0` | Fernet/AES-256 encryption at rest for external integration API keys |
| `httpx` | `>=0.27.0` | Asynchronous HTTP client for threat intelligence and AI provider probes |
| `jinja2` | `>=3.1.3` | Dynamic report templating (HTML, SARIF, Markdown) |
| `aiosqlite` | `>=0.20.0` | Asynchronous SQLite driver for real-time background transactions |
| `python-multipart` | `>=0.0.9` | Form data parsing for file uploads and target imports |
| `pytest` | `>=8.0.0` | Automated test runner for unit, integration, and security suites |
| `pytest-cov` | `>=5.0.0` | Code coverage reporting |

## 3. External Security Tool Dependencies (Optional / Detected)

The SWA AI architecture decouples external command-line binaries from internal execution. If an external tool is not installed locally, SWA smoothly falls back to native Python engines without throwing runtime errors:

| Tool Binary | Recommended Version | Native Fallback Available? | Role |
|---|---|---|---|
| `nmap` | 7.90+ | Yes (`core/scanner_integrations.py` native socket scanner) | Network port scanning & service banner grab |
| `nuclei` | 3.0+ | Yes (Internal OWASP check suites in `agents/vuln_hunter_agent.py`) | Vulnerability template execution |
| `sqlmap` | 1.6+ | Yes (Internal `core/sqli_engine.py` injection suite) | SQL injection verification |
| `nikto` | 2.1+ | Yes (Internal web security crawler & header analyzer) | Web server misconfiguration scan |
| `amass` | 3.19+ | Yes (Autonomous OSINT subdomain miner in `agents/amass_engine.py`) | DNS enumeration & asset mapping |
| `rea` | 1.0+ | Yes (Native reverse engineering engine in `core/rea_engine.py`) | Binary analysis & symbol extraction |
