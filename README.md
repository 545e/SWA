# SNMK — Autonomous Cybersecurity Platform

<p align="center">
  <b>Generation 2 Autonomous Multi-Agent Cybersecurity Auditor & Operations Hub</b><br>
  <i>Cross-platform cybersecurity operating system for Windows, Linux, and macOS. Featuring 85 autonomous agents, OWASP Top 10 auditing, encrypted API key management, verifiable PoC generation, AI Lab, continuous EASM drift detection, and post-deployment verification.</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.3.0--Sentinel-10b981?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-3b82f6?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3b82f6?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Agents-85%20Operational-8b5cf6?style=for-the-badge" alt="Agents">
  <img src="https://img.shields.io/badge/API-v1%20Standardized-0284c7?style=for-the-badge" alt="API v1">
  <img src="https://img.shields.io/badge/Integrations-23%20Providers-6366f1?style=for-the-badge" alt="Integrations">
  <img src="https://img.shields.io/badge/Tests-206%20Passed%20(100%25)-10b981?style=for-the-badge" alt="Tests">
  <img src="https://img.shields.io/badge/License-MIT-purple?style=for-the-badge" alt="License">
</p>

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Key Features](#2-key-features)
3. [Supported Operating Systems](#3-supported-operating-systems)
4. [Installation and Quick Start](#4-installation-and-quick-start)
5. [Windows Installation](#5-windows-installation)
6. [Linux Installation](#6-linux-installation)
7. [macOS Installation](#7-macos-installation)
8. [Manual Installation](#8-manual-installation)
9. [Docker Installation](#9-docker-installation)
10. [Environment Configuration](#10-environment-configuration)
11. [API Key & Integrations Configuration](#11-api-key--integrations-configuration)
12. [Running the Application](#12-running-the-application)
13. [Application URLs](#13-application-urls)
14. [Usage Guide & Main Navigation](#14-usage-guide--main-navigation)
15. [Security, Scope Governance & Authorization](#15-security-scope-governance--authorization)
16. [Testing and Quality Assurance](#16-testing-and-quality-assurance)
17. [Troubleshooting](#17-troubleshooting)
18. [Documentation Index](#18-documentation-index)
19. [Contribution Guide](#19-contribution-guide)
20. [License Information](#20-license-information)

---

## 1. Project Overview

**SNMK** (Autonomous Cybersecurity Platform) is an autonomous, cross-platform cybersecurity operations platform designed to conduct authorized security assessments, external attack surface management (EASM), vulnerability identification, and remediation verification.

Operating across Windows, Linux, and macOS, SNMK coordinates an autonomous workforce of **85 specialist agents** to deliver verifiable, reproducible security insights without destructive payload side effects.

- **Unified Single-Page Application (SPA)**: Zero heavy framework dependencies, built with responsive vanilla JavaScript, HTML5, and CSS3.
- **Asynchronous FastAPI Engine**: High-concurrency backend powered by Python 3.10–3.12 with SQLite in WAL mode.
- **Enterprise Decoupling**: Seamless native Python fallbacks for external security binaries (Nmap, Nuclei, Nikto, SQLmap, Amass, REA).

---

## 2. Key Features

- **Autonomous Multi-Agent Workforce (85 Agents)**: 5 operational tiers (Specialist Workforce, Offensive Recon, OWASP Plugins, Core Cybersecurity Engines, Tool Adapters).
- **Secure Encrypted API Key Management**: AES-256 / Fernet encryption at rest for external integrations with master keys stored strictly outside the database.
- **Threat Intelligence & SIEM Integrations**: Native adapters for VirusTotal, AbuseIPDB, Shodan, Censys, AlienVault OTX, URLhaus, Wazuh, Splunk, Elastic, Sentinel, CrowdStrike, and DefectDojo.
- **AI Model Management**: Central model registry supporting OpenAI, Anthropic Claude, Google Gemini, OpenRouter, and Local/Ollama models with availability probes and fallback routing.
- **Canonical Posture Scoring**: Single source of truth for severity grading (`CRITICAL -30`, `HIGH -18`, `MEDIUM -8`, `LOW -3`, `INFO -1`).
- **Post-Deployment Verification Checklist**: Built-in 10-section automated acceptance checklist with Markdown and JSON exports.
- **Multi-Format Cyber Reporting**: One-click export to OASIS SARIF 2.1.0, HTML executive briefs, PDF, JSON, CSV, and Markdown.

---

## 3. Supported Operating Systems

| Operating System | Supported Versions | Supported Shells | Python Runtime |
|---|---|---|---|
| **Windows** | Windows 10, Windows 11, Windows Server 2019+ | PowerShell (5.1+, 7+), Command Prompt (CMD) | Python 3.10 – 3.12 (64-bit) |
| **Linux** | Ubuntu 20.04+, Debian 11+, RHEL/CentOS 8+, Alpine | Bash, Zsh, Systemd Service | Python 3.10 – 3.12 |
| **macOS** | macOS Monterey (12)+, Ventura (13)+, Sonoma (14)+ (Apple Silicon & Intel) | Bash, Zsh | Python 3.10 – 3.12 |
| **Docker** | Docker Engine 20.10+, Docker Compose v2+ | Docker CLI | Containerized Linux |

---

## 4. Installation and Quick Start

Clone the primary repository:

```bash
git clone https://github.com/545e/snmk.git
cd SWA
```

Select your operating system below to install and run SNMK with one command.

---

## 5. Windows Installation

SNMK provides fully verified native Windows batch and PowerShell installers that automatically provision a virtual environment (`.venv`), install dependencies, and launch the application.

### 5.1 Quick Install & Run (PowerShell)

Open PowerShell and execute:

```powershell
git clone https://github.com/545e/snmk.git
cd SWA
.\install.ps1
.\run.ps1
```

> **PowerShell Execution Policy Note**: If script execution is blocked on your machine, run `run.ps1` with the bypass flag for the current process without altering global system policies:
> ```powershell
> powershell -ExecutionPolicy Bypass -File .\run.ps1
> ```

### 5.2 Quick Install & Run (Command Prompt / Batch)

Open Command Prompt (`cmd.exe`) and execute:

```cmd
git clone https://github.com/545e/snmk.git
cd SWA
install.bat
run.bat
```

### 5.3 Stopping the Application (Windows)

To gracefully stop the background application processes:

```powershell
.\stop.ps1
```
or
```cmd
stop.bat
```

---

## 6. Linux Installation

SNMK includes verified POSIX shell scripts for Ubuntu, Debian, CentOS, RHEL, and Fedora.

### 6.1 Prerequisites

Ensure Python 3.10–3.12 and venv are installed:

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git
```

### 6.2 Install & Run

```bash
git clone https://github.com/545e/snmk.git
cd SWA
chmod +x install.sh run.sh stop.sh
./install.sh
./run.sh
```

### 6.3 Stopping the Application (Linux)

```bash
./stop.sh
```

---

## 7. macOS Installation

SNMK natively supports Apple Silicon (M1/M2/M3/M4) and Intel-based Macs.

### 7.1 Prerequisites

Ensure Homebrew and Python 3 are installed:

```bash
brew install python git
```

### 7.2 Install & Run

```bash
git clone https://github.com/545e/snmk.git
cd SWA
chmod +x install_macos.sh run_macos.sh stop_macos.sh
./install_macos.sh
./run_macos.sh
```

### 7.3 Stopping the Application (macOS)

```bash
./stop_macos.sh
```

---

## 8. Manual Installation

If you prefer to configure your Python environment manually:

```bash
git clone https://github.com/545e/snmk.git
cd SWA

# 1. Create a virtual environment
python -m venv .venv

# 2. Activate the virtual environment
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Windows (CMD):
.venv\Scripts\activate.bat
# Linux / macOS:
source .venv/bin/activate

# 3. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 4. Initialize environment file
cp .env.example .env

# 5. Start SNMK
python run.py
```

---

## 9. Docker Installation

For containerized environments, SNMK provides production and development Docker Compose configurations with persistent database volume mappings.

### 9.1 Quick Start with Docker Compose

```bash
git clone https://github.com/545e/snmk.git
cd SWA
docker compose up --build -d
```

### 9.2 Viewing Logs & Stopping

```bash
# View live application logs
docker compose logs -f

# Gracefully stop containers
docker compose down
```

---

## 10. Environment Configuration

SNMK reads configuration from `.env` in the project root. Create `.env` from the provided reference:

```bash
cp .env.example .env
```

| Variable | Default Value | Description |
|---|---|---|
| `HOST` | `127.0.0.1` | Network binding interface (`0.0.0.0` for container/remote access) |
| `PORT` | `8000` | HTTP application port |
| `SWA_HOME` | Current Directory | Root data directory for SQLite database and report storage |
| `SWA_ENCRYPTION_KEY` | Auto-Generated | Base64 master encryption key for securing stored credentials at rest |
| `SWA_API_TOKEN` | Empty | Optional bearer token required for remote `/api/*` access |
| `SWA_ENFORCE_ALLOWLIST` | `0` | Enforce strict target domain allowlist before executing scans |

---

## 11. API Key & Integrations Configuration

External services and AI models can be configured directly through the UI without touching source code:

1. Open **Settings → API Keys & Integrations**.
2. Click **+ Add Integration**.
3. Select your provider:
   - **AI Providers**: OpenAI, Anthropic, Google Gemini, OpenRouter, Local/Ollama.
   - **Threat Intelligence**: VirusTotal, AbuseIPDB, Shodan, Censys, AlienVault OTX, URLhaus.
   - **SIEM / EDR**: Wazuh, Splunk, Elastic Security, Microsoft Sentinel, CrowdStrike Falcon.
   - **Vulnerability Management**: DefectDojo, Tenable.io.
   - **Cloud Providers**: AWS (Security Hub/STS), Microsoft Azure, Google Cloud Platform (SCC).
4. Enter credentials. Keys are encrypted at rest using Fernet / AES-256 and masked in the UI (`sk-***-1234`).
5. Click **Test** to run an authentic reachability and authentication probe.

---

## 12. Running the Application

| Platform | Recommended Launcher | Alternate Command |
|---|---|---|
| **Windows (PowerShell)** | `.\run.ps1` | `python run.py` |
| **Windows (CMD)** | `run.bat` | `python run.py` |
| **Linux (Bash/Zsh)** | `./run.sh` | `python3 run.py` |
| **macOS (Zsh)** | `./run_macos.sh` | `python3 run.py` |
| **CLI Console Mode** | `python swa_cli.py --help` | `swa --help` |

---

## 13. Application URLs

Once started, SNMK exposes the following endpoints:

| Endpoint | URL | Description |
|---|---|---|
| **Web Dashboard** | `http://127.0.0.1:8000/` | Main cybersecurity operations console |
| **System Diagnostics** | `http://127.0.0.1:8000/api/system/status` | Honest component health diagnostics |
| **AI Status Probe** | `http://127.0.0.1:8000/api/ai/status` | Real-time AI reachability and configuration |
| **Health Check** | `http://127.0.0.1:8000/health` | Container orchestrator health probe |
| **Readiness Probe** | `http://127.0.0.1:8000/ready` | K8s / load balancer readiness check |
| **OpenAPI Docs (Swagger)** | `http://127.0.0.1:8000/docs` | Interactive Swagger REST API documentation |
| **OpenAPI JSON** | `http://127.0.0.1:8000/swagger.json` | OpenAPI 3.0 schema definition |
| **Security Disclosure** | `http://127.0.0.1:8000/.well-known/security.txt` | RFC 9116 security contact policy |

---

## 14. Usage Guide & Main Navigation

SNMK integrates 14 primary navigation views:

1. **Dashboard**: Real-time SOC overview, threat velocity, security posture grade, and recent scans.
2. **Assessments**: Start new scans, configure scan profiles (Passive, Standard, Lab, Aggressive), and monitor active tasks.
3. **Assets**: Live asset inventory with IP mappings, HTTP status, TLS certificates, and parent domains.
4. **Vulnerabilities**: Finding explorer with severity badges, CVE references, verifiable cURL PoCs, and CVSS scores.
5. **Security Tools**: Real-time inventory of detected tools (Nmap, Nuclei, Nikto, SQLmap, Amass, REA) and native engines.
6. **AI Agents**: Central multi-agent workforce registry managing 85 agents across 5 operational tiers with task dispatching.
7. **Investigation**: Attack path knowledge graph correlating assets, exposed ports, and shared vulnerabilities.
8. **Remediation**: Ticket management tracking findings through triage, assignment, approval, and automated retest.
9. **Reports**: Historical report archive and export manager.
10. **AI Lab**: LLM red-teaming, prompt injection resilience evaluation, and model safety testing.
11. **Cyber Export**: Export auditable reports in OASIS SARIF 2.1.0, HTML, PDF, Markdown, JSON, and CSV.
12. **Cyber Test**: Automated synthetic test harness executing non-destructive exploit injection tests.
13. **Cyber Deploy**: Deployment history and 10-section post-deployment acceptance checklist.
14. **Settings**: API Keys & Integrations, AI Models, Scope Governance, and System Health.

---

## 15. Security, Scope Governance & Authorization

- **SSRF Prevention**: All target requests filter RFC1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.1`), and cloud metadata IP (`169.254.169.254`).
- **Human Approval Gates**: Intrusive agent actions require approval from a security lead before execution.
- **Audit Logging**: An immutable, append-only audit trail records all security actions (`core/audit.py`).
- **Target Allowlist**: Enforce authorized pentest scope boundaries using `SWA_ENFORCE_ALLOWLIST=1`.

---

## 16. Testing and Quality Assurance

Execute the complete automated test suite:

```bash
# Run all unit, integration, and security tests
pytest

# Run tests with coverage report
pytest --cov=core --cov=web --cov=agents
```

### Key Test Suites
- `tests/test_api_and_dashboard.py`: Core REST APIs and SOC navigation dispatches.
- `tests/test_system_status.py`: Honest component health diagnostics and reachability.
- `tests/test_deployment_readiness.py`: Database integrity, WAL mode, and online zero-downtime backup.
- `tests/test_integrations_and_ai_models.py`: API key encryption, secret masking, and model management.
- `tests/test_gen3_navigation_acceptance.py`: View isolation and hash routing.
- `tests/test_expanded_cyber_coverage.py`: Expanded SQLi, XSS, and multi-class injection coverage.

---

## 17. Troubleshooting

### Port 8000 Already in Use
If port 8000 is occupied, set a different port in `.env` or start with:
```bash
python run.py --port 8080
```

### Database Locked / SQLite Concurrency
SNMK automatically operates SQLite in Write-Ahead Logging (`PRAGMA journal_mode=WAL`) to allow concurrent reads and writes. Verify database health via `http://127.0.0.1:8000/api/system/status`.

### Connection Refused
Ensure the backend process is running:
```powershell
# Windows
Get-Process -Name python*
# Linux / macOS
ps aux | grep run.py
```

---

## 18. Documentation Index

Comprehensive documentation is available in the `docs/` directory:
- [Master API Inventory & Endpoints](docs/API_INVENTORY.md)
- [API Architecture & Subsystems](docs/API_ARCHITECTURE.md)
- [API Authentication & RBAC](docs/API_AUTHENTICATION.md)
- [API Security & SSRF Defense](docs/API_SECURITY.md)
- [API Versioning & Evolution](docs/API_VERSIONING.md)
- [External Integrations Hub](docs/API_INTEGRATIONS.md)
- [API Deployment Runbook](docs/API_DEPLOYMENT.md)
- [API Testing & Verification](docs/API_TESTING.md)
- [API Environment Variables](docs/API_ENVIRONMENT_CONFIGURATION.md)
- [API Troubleshooting & Diagnostics](docs/API_TROUBLESHOOTING.md)
- [Deployment Acceptance Sign-Off](docs/DEPLOYMENT_ACCEPTANCE.md)
- [API Changelog](docs/API_CHANGELOG.md)
- [Windows Installation Guide](docs/INSTALLATION_WINDOWS.md)
- [Linux Installation Guide](docs/INSTALLATION_LINUX.md)
- [macOS Installation Guide](docs/INSTALLATION_MACOS.md)
- [Multi-Agent Workforce Guide](docs/AGENT_GUIDE.md)
- [Security & Governance Policy](docs/SECURITY.md)
- [Troubleshooting Manual](docs/TROUBLESHOOTING.md)

---

## 19. Contribution Guide

Contributions are welcome! Please review [CONTRIBUTING.md](docs/CONTRIBUTING.md) before submitting pull requests. Ensure all automated tests pass (`pytest`) and CodeQL SAST checks remain green.

---

## 20. License Information

SNMK is released under the [MIT License](LICENSE).
