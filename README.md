# ⚡ SWA AI — Autonomous Enterprise Cybersecurity Operations Platform

<p align="center">
  <b>Generation 2 Autonomous Multi-Agent Cybersecurity Auditor & Operations Hub</b><br>
  <i>Full cross-platform support for Windows, Linux, and macOS. Featuring 85 autonomous agents, OWASP Top 10 auditing, verifiable PoC generation, AI Lab, continuous EASM drift detection, and post-deployment verification.</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.2.0--Enterprise-10b981?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-3b82f6?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3b82f6?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Agents-85%20Operational-8b5cf6?style=for-the-badge" alt="Agents">
  <img src="https://img.shields.io/badge/Tests-127%20Passed%20(100%25)-10b981?style=for-the-badge" alt="Tests">
  <img src="https://img.shields.io/badge/License-MIT-purple?style=for-the-badge" alt="License">
</p>

---

## 📑 Table of Contents

1. [SWA AI Project Title and Introduction](#1-swa-ai-project-title-and-introduction)
2. [Project Overview](#2-project-overview)
3. [Vision and Objectives](#3-vision-and-objectives)
4. [Problems SWA AI Aims to Solve](#4-problems-swa-ai-aims-to-solve)
5. [Main Features and Modules](#5-main-features-and-modules)
6. [Dashboard Overview](#6-dashboard-overview)
7. [Security Assessments](#7-security-assessments)
8. [Asset Management](#8-asset-management)
9. [Vulnerability Management](#9-vulnerability-management)
10. [Security Tool Integrations](#10-security-tool-integrations)
11. [AI Agent Management (85 Agents Across 5 Tiers)](#11-ai-agent-management-85-agents-across-5-tiers)
12. [Investigation and Remediation](#12-investigation-and-remediation)
13. [Reports and Exports](#13-reports-and-exports)
14. [AI Lab and LLM Security Testing](#14-ai-lab-and-llm-security-testing)
15. [Cyber Export, Cyber Test and Cyber Deploy](#15-cyber-export-cyber-test-and-cyber-deploy)
16. [Architecture Overview](#16-architecture-overview)
17. [Technology Stack](#17-technology-stack)
18. [Project Directory Structure](#18-project-directory-structure)
19. [System Requirements](#19-system-requirements)
20. [Windows Installation](#20-windows-installation)
21. [Linux Installation](#21-linux-installation)
22. [macOS Installation](#22-macos-installation)
23. [Configuration and Environment Variables](#23-configuration-and-environment-variables)
24. [Database Setup](#24-database-setup)
25. [How to Start and Stop SWA AI](#25-how-to-start-and-stop-swa-ai)
26. [How to Access the Application](#26-how-to-access-the-application)
27. [How to Run Tests](#27-how-to-run-tests)
28. [Troubleshooting](#28-troubleshooting)
29. [Security and Responsible-Use Guidelines](#29-security-and-responsible-use-guidelines)
30. [Known Limitations](#30-known-limitations)
31. [Roadmap](#31-roadmap)
32. [Contribution Guidelines](#32-contribution-guidelines)
33. [License Information](#33-license-information)
34. [Support and Documentation Index](#34-support-and-documentation-index)

---

## 1. SWA AI Project Title and Introduction

**SWA AI** (Security Workflow Automation Artificial Intelligence) is an autonomous, cross-platform cybersecurity operations platform designed to conduct authorized security assessments, reconnaissance, vulnerability identification, and remediation verification. 

Operating on Windows, Linux, and macOS, SWA AI coordinates an autonomous workforce of **85 specialist agents** to deliver verifiable security insights without destructive payload side effects.

---

## 2. Project Overview

SWA AI unifies offensive reconnaissance and defensive posture management into a single, cohesive command console:
- **Client-Side SPA Architecture:** Pure HTML5, modern CSS3, and standard vanilla ES6+ JavaScript with zero heavy framework bloat.
- **Cross-Platform Backend:** FastAPI async server on Python 3.10–3.12, utilizing SQLite in WAL mode for persistent, concurrent data storage across all platforms.
- **Autonomous Multi-Agent Coordination:** Centralized discovery and execution registry managing 85 specialist agents across 5 operational tiers.

---

## 3. Vision and Objectives

- **Defensibility:** Deliver non-destructive, reproducible proof-of-concept (PoC) evidence for every finding rather than speculative risk scores.
- **Portability:** Provide 100% feature parity across Windows, Linux (Ubuntu/Debian/Fedora/Arch), and macOS (Apple Silicon & Intel).
- **Human-in-the-Loop Governance:** Restrict sensitive assessment profiles behind human authorization gates.
- **Integrity:** Zero mock data, zero simulated pass rates, and authentic capability detection.

---

## 4. Problems SWA AI Aims to Solve

1. **Fragmented Security Tooling:** Traditional security audits require juggling dozens of disconnected command-line tools. SWA AI unifies port discovery, DNS reconnaissance, web probing, SAST linting, and reverse engineering into one console.
2. **High False Positive Rates:** Automated scanners often report theoretical flaws without verifying exploitability. SWA AI verifies findings with safe, reproducible cURL PoCs.
3. **OS Incompatibility:** Many security platforms only operate on Linux. SWA AI is engineered to install and operate seamlessly on Windows 10/11, standard Linux distributions, and macOS.

---

## 5. Main Features and Modules

- **Unified SOC Dashboard:** Real-time telemetry, KPI cards, live security audit stream, and tool health monitoring.
- **Autonomous Assessments:** Passive reconnaissance, standard scans, authorized local lab assessments, and deep red team probing.
- **EASM Drift Engine:** Continuous attack surface tracking to catch newly exposed subdomains and ports.
- **Topological Knowledge Graph:** Interactive visual representation of connected infrastructure assets, vulnerabilities, and blast radiuses.
- **Remediation Kanban:** Full lifecycle tracking from discovery to automated verification retest.
- **AI Lab & LLM Security:** Fine-tuning job management, dataset validation, and 360 LLM security test suites.

---

## 6. Dashboard Overview

The SWA AI Executive Dashboard provides immediate operational awareness:
- **Workforce Banner:** Instant view of all 85 registered agents with one-click navigation.
- **Summary KPIs:** Total Assets, Total Vulnerabilities, Critical Findings, and Active Assessments.
- **Interactive Assessment Launcher:** Target input bar with profile selection pills (Passive Recon, Standard, Lab Mode, Full Red Team, OWASP Top 10, All Tools).
- **Recent Platform Activity:** Live audit log stream showing authenticated security events and system actions.

---

## 7. Security Assessments

SWA AI enforces strict scope validation rules:
- **Passive Reconnaissance:** Zero active packets; queries certificate transparency logs, DNS records, and search engines.
- **Standard Assessment:** Host discovery, non-blocking port auditing, web banner analysis, and OWASP Top 10 checks.
- **Authorized Lab Mode:** Explicitly tuned for local and test targets (`127.0.0.1`, `localhost`, PortSwigger Web Security Academy labs, DVWA).
- **Scope Guard (`core/scope_policy.py`):** Automatically blocks scanning of private RFC 1918 addresses and cloud metadata services (IMDS `169.254.169.254`) unless explicitly authorized.

---

## 8. Asset Management

- **Asset Discovery:** Discovers and records hostnames, IPs, services, and technologies.
- **Exposure Analysis:** Categorizes assets into perimeter, internal, and cloud-hosted.
- **Drift Detection:** Identifies newly created DNS records, removed hosts, and service alterations over time.

---

## 9. Vulnerability Management

Every finding recorded by SWA AI contains:
- Unique finding ID and affected asset association.
- Severity rating (Critical, High, Medium, Low, Info) mapped to CVSS scores.
- CVE and CWE identifiers where applicable.
- Verifiable proof-of-concept (PoC) reproduction commands.
- Specific remediation guidance and patch recommendations.

---

## 10. Security Tool Integrations

SWA AI automatically discovers host binaries and provides safe subprocess-isolated adapters:
- **Nmap:** Network discovery and port auditing.
- **Nuclei:** Template-driven web security checks.
- **SQLmap:** Safe detection of SQL injection vulnerabilities in lab scopes.
- **Nikto:** Web server configuration and outdated software checks.
- **Trivy & Grype:** Container and dependency vulnerability analysis.
- **Gitleaks & TruffleHog:** Token and secret detection.
- **GhostJS AST Engine:** Native client-side JavaScript secret analyzer.
- **REA Engine:** Binary reverse engineering and disassembly adapter.

---

## 11. AI Agent Management (85 Agents Across 5 Tiers)

SWA AI features an authoritative central registry (`core/agent_registry.py`) and persistent SQLite inventory managing all **85 autonomous agents**:

| Tier | Category | Count | Primary Capabilities |
| :---: | :--- | :---: | :--- |
| **Tier 1** | Specialist Workforce Agents | **17** | High-level autonomous roles: Lead Recon, Exploit Verifier, Blue Team Defender, Cloud Auditor, Cryptographer, Forensics Investigator, etc. |
| **Tier 2** | Offensive & Recon Domain Agents | **9** | Port Scanner, Subdomain Engine, DNS Enum, SSL Cert Auditor, Param Fuzzer, Crawler Engine, Content Discoverer, Tech Profiler. |
| **Tier 3** | OWASP Top 10 Security Plugins | **10** | Injection Prober, Broken Access Control, Cryptographic Failures, Insecure Design, Security Misconfig, SSRF Prober, etc. |
| **Tier 4** | Core Autonomous Security Engines | **32** | EASM Drift Monitor, Scope Guard, Findings Deduplicator, Posture Assessor, Ticket Manager, REA Engine, Approval Gatekeeper, etc. |
| **Tier 5** | External Tool & Scanner Adapters | **17** | Nmap, Masscan, Nuclei, SQLmap, Nikto, Trivy, Grype, Gitleaks, TruffleHog, Semgrep, Bandit, OWASP ZAP, Burp Suite, etc. |

Access the full paginated catalog at [`http://127.0.0.1:8000/#agents`](http://127.0.0.1:8000/#agents).

---

## 12. Investigation and Remediation

- **Investigation Timeline:** Correlation of events across network, application, and OSINT telemetry.
- **Remediation Kanban:** Interactive board organizing tickets across `DISCOVERED`, `IN_PROGRESS`, `RETEST`, `VERIFIED`, and `CLOSED`.
- **One-Click Retest:** Executes the exact original probe to verify if a patch successfully resolved the vulnerability.

---

## 13. Reports and Exports

SWA AI generates defensible assessment reports from stored SQLite data:
- **HTML:** Interactive standalone report with executive summary and finding breakdown.
- **PDF:** Formal executive report suitable for compliance and audit submission.
- **JSON & CSV:** Raw machine-readable data for ingestion into enterprise SIEMs.
- **SARIF 2.1.0:** OASIS standard Static Analysis Results Format for native integration with GitHub Code Scanning.

---

## 14. AI Lab and LLM Security Testing

- **Dataset Management:** 230 registered datasets with format validation, deduplication, and quality scoring.
- **Training Job Tracking:** 31 fine-tuning experiments with loss curves and resource metrics.
- **LLM Security Probes:** 360 automated security test suites covering:
  - Prompt injection and system prompt extraction.
  - Jailbreak evasion techniques.
  - Sensitive data and token leakage.
  - Insecure tool and function invocation.

---

## 15. Cyber Export, Cyber Test and Cyber Deploy

- **Cyber Export:** Selective archive generation for findings, assets, and audit logs.
- **Cyber Test:** Interactive automated test execution console displaying live test durations and outputs.
- **Cyber Deploy:** Deployment lifecycle engine with persistent 10-section post-deployment acceptance verification.

---

## 16. Architecture Overview

```text
+-------------------------------------------------------------------------------+
|               Frontend Client (Vanilla ES6+ SPA, Hash Routing)                |
|       Dashboard  •  Assessments  •  Assets  •  Vulnerabilities  •  Agents     |
+-------------------------------------------------------------------------------+
                                      ▲
                                      │ HTTP / REST APIs
                                      ▼
+-------------------------------------------------------------------------------+
|               FastAPI Async Backend Application (web/server.py)               |
|   Enterprise Routes  •  Scope Guard  •  Rate Limiter  •  Auth & Approval      |
+-------------------------------------------------------------------------------+
           │                                 │                    │
           ▼                                 ▼                    ▼
+-----------------------+       +-----------------------+  +--------------------+
| 85 Autonomous Agents  |       | Security Tool Adapters|  | SQLite 3.49+ (WAL) |
|  - 17 Workforce Roles |       |  - Nmap, Nuclei, Nikto|  | 27 Tables, Indexes|
|  - 9 Recon Specialists|       |  - SQLmap, REA, Trivy |  | Findings, Scans,   |
|  - 10 OWASP Plugins   |       |  - GhostJS AST Engine |  | Datasets, Checklists|
|  - 32 Core Engines    |       |  - Endpoint / EDR     |  +--------------------+
|  - 17 Tool Adapters   |       +-----------------------+
+-----------------------+
```

---

## 17. Technology Stack

- **Backend:** Python 3.10 – 3.12, FastAPI, Uvicorn (ASGI).
- **Database:** SQLite 3.49+ in WAL mode with connection pooling.
- **Networking:** HTTPX (async client), Python native socket engine, DNS asyncresolver.
- **Frontend:** Semantic HTML5, CSS3 Glassmorphism theme, Vanilla JavaScript (ES6+).
- **Cryptography & Security:** OpenSSL libcrypto (via Python `hashlib`), cryptography, Safe Subprocess Isolation.

---

## 18. Project Directory Structure

```text
SWA/
├── .github/workflows/          # CI/CD pipelines (Ubuntu, Windows, macOS, CodeQL)
├── agents/                     # 17 specialist workforce agents & reconnaissance roles
├── benchmarks/                 # Polyglot performance benchmark suites
├── config/                     # Configuration loaders & scope definitions
├── core/                       # Core autonomous engines & database layer
│   ├── agent_registry.py       # Central 85-agent discovery & execution registry
│   ├── antivirus_edr_manager.py# Endpoint security & telemetry manager
│   ├── database.py             # SQLite WAL database layer (27 tables)
│   ├── js_intelligence.py      # GhostJS AST secret analyzer
│   ├── network_scanner.py      # Async TCP socket scanner
│   ├── post_deployment_checklist.py # 10-section acceptance verifier
│   ├── rea_engine.py           # REA reverse engineering engine
│   ├── scanner_integrations.py # CLI adapters (Nmap, Nuclei, SQLmap, Nikto)
│   └── scope_policy.py         # Scope enforcement & SSRF protection
├── docs/                       # Comprehensive documentation & manuals
│   ├── WINDOWS_INSTALLATION.md # Windows setup & operations guide
│   ├── LINUX_INSTALLATION.md   # Linux setup (Debian/Ubuntu/Fedora/Arch)
│   ├── MACOS_INSTALLATION.md   # macOS setup (Apple Silicon & Intel)
│   ├── CROSS_PLATFORM_COMPATIBILITY.md # OS compatibility matrix
│   ├── ARCHITECTURE.md         # Detailed architectural specification
│   ├── FEATURES.md             # Feature inventory & capabilities
│   ├── SECURITY.md             # Security policy & disclosure
│   ├── TROUBLESHOOTING.md      # Troubleshooting guide
│   └── CONTRIBUTING.md         # Contribution guidelines
├── plugins/                    # 10 OWASP Top 10 security plugins
├── reports/                    # Generated Markdown engineering & audit reports
├── tests/                      # Automated test suite (127 test cases)
├── web/                        # Web application server & static frontend
│   ├── enterprise_api.py       # Enterprise REST endpoints
│   ├── server.py               # Main FastAPI server
│   └── static/                 # Frontend assets (index.html, styles.css, app.js)
├── install.bat                 # Windows Batch installer
├── install.ps1                 # Windows PowerShell installer
├── install.sh                  # Linux installation script
├── install_macos.sh            # macOS installation script
├── run.bat                     # Windows Batch launcher
├── run.ps1                     # Windows PowerShell launcher
├── run.sh                      # Linux launcher script
├── run_macos.sh                # macOS launcher script
├── stop.bat                    # Windows Batch shutdown script
├── stop.ps1                    # Windows PowerShell shutdown script
├── stop.sh                     # Linux shutdown script
├── stop_macos.sh               # macOS shutdown script
├── run.py                      # Multi-platform Python entry point
└── requirements.txt            # Pinned runtime dependencies
```

---

## 19. System Requirements

- **Operating System:** Windows 10/11, Windows Server 2019/2022, Ubuntu 20.04+, Debian 11+, Fedora 38+, macOS 12+ (Apple Silicon or Intel).
- **Python:** Python 3.10, 3.11, or 3.12 (64-bit recommended).
- **RAM:** Minimum 2 GB (4 GB recommended for concurrent assessments).
- **Disk Space:** 500 MB for core installation and database.

---

## 20. Windows Installation

Run via **Command Prompt**:
```cmd
git clone https://github.com/545e/SWA.git
cd SWA
install.bat
```

Or via **PowerShell**:
```powershell
Set-Location C:\Users\krish\SWA
.\install.ps1
```

For comprehensive instructions, see [`docs/WINDOWS_INSTALLATION.md`](docs/WINDOWS_INSTALLATION.md).

---

## 21. Linux Installation

```bash
git clone https://github.com/545e/SWA.git
cd SWA
chmod +x install.sh
./install.sh
```

For distribution-specific packages and systemd configuration, see [`docs/LINUX_INSTALLATION.md`](docs/LINUX_INSTALLATION.md).

---

## 22. macOS Installation

```bash
git clone https://github.com/545e/SWA.git
cd SWA
chmod +x install_macos.sh
./install_macos.sh
```

For Homebrew dependencies and launchd setup, see [`docs/MACOS_INSTALLATION.md`](docs/MACOS_INSTALLATION.md).

---

## 23. Configuration and Environment Variables

Configuration is loaded from `.env` in the project root:
```env
SWA_HOST=0.0.0.0
SWA_PORT=8000
HEADLESS=0
SWA_DB_PATH=swa_data.db
SWA_SECRET_KEY=generate_a_random_secret_key_here
```

---

## 24. Database Setup

SWA AI initializes its SQLite database automatically on first startup:
- Database file: `swa_data.db` (in project root).
- Mode: Write-Ahead Logging (`WAL`) enabled for high-concurrency read/write operations.
- Schema: 27 tables tracking scans, findings, assets, agents, datasets, audit logs, and checklists.

---

## 25. How to Start and Stop SWA AI

### Starting SWA AI:
- **Windows:** `run.bat` or `.\run.ps1`
- **Linux:** `./run.sh`
- **macOS:** `./run_macos.sh`
- **Cross-Platform Python:** `python run.py`

### Stopping SWA AI:
- **Windows:** `stop.bat` or `.\stop.ps1`
- **Linux:** `./stop.sh`
- **macOS:** `./stop_macos.sh`

---

## 26. How to Access the Application

Once launched, open your web browser to:
👉 **`http://127.0.0.1:8000`**

### Direct View Shortcuts:
- Dashboard: `http://127.0.0.1:8000/#dashboard`
- 85-Agent Workforce: `http://127.0.0.1:8000/#agents`
- Security Assessments: `http://127.0.0.1:8000/#assessments`
- Asset Inventory: `http://127.0.0.1:8000/#assets`
- Vulnerabilities: `http://127.0.0.1:8000/#vulnerabilities`

---

## 27. How to Run Tests

Run the full automated test suite (127 tests) using `pytest`:
```bash
pytest tests/ -v
```

Run targeted subsystem tests:
```bash
pytest tests/test_enterprise_platform.py -v
pytest tests/test_cyber_deploy.py -v
```

---

## 28. Troubleshooting

| Symptom | Cause | Solution |
| :--- | :--- | :--- |
| Port 8000 in use | Lingering background process | Run `stop.bat` (Windows) or `./stop.sh` (Linux/macOS), or specify `SWA_PORT=8002 python run.py`. |
| Missing Python modules | Running outside virtualenv | Ensure virtual environment is active: `venv\Scripts\activate` (Windows) or `source venv/bin/activate` (POSIX). |
| Tools not detected | Binary not in system PATH | Install tool via package manager or add binary path to PATH. SWA AI falls back to native engines automatically. |

For detailed guidance, see [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md).

---

## 29. Security and Responsible-Use Guidelines

> [!CAUTION]
> **Authorized Testing Only:** SWA AI is designed exclusively for authorized security audits of systems you own or have explicit written permission to test. Unauthorized access or probing of computer systems is strictly prohibited by law.

For reporting vulnerabilities in SWA AI itself, refer to [`docs/SECURITY.md`](docs/SECURITY.md).

---

## 30. Known Limitations

1. **TotalAV Integration:** TotalAV operates exclusively via a proprietary desktop GUI; no command-line interface or public API is provided by the vendor.
2. **Enterprise Cloud EDRs (CrowdStrike / SentinelOne):** Telemetry retrieval requires valid customer API client credentials configured in the platform settings.
3. **Raw Packet Scans on POSIX:** Running raw SYN scans (`nmap -sS`) requires root privileges (`sudo`); SWA AI defaults to unprivileged non-blocking TCP socket connect audits by default.

---

## 31. Roadmap

- [ ] Distributed scanning worker cluster support.
- [ ] Automated generation of infrastructure-as-code (Terraform) remediation templates.
- [ ] Native integration with Jira and ServiceNow incident response queues.
- [ ] Extended mobile application security testing profiles (Android APK / iOS IPA).

---

## 32. Contribution Guidelines

Contributions are welcome! Please review [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) for code style, responsible disclosure standards, and pull request procedures.

---

## 33. License Information

SWA AI is released under the **[MIT License](LICENSE)**.

---

## 34. Support and Documentation Index

- **Windows Operations Guide:** [`docs/WINDOWS_INSTALLATION.md`](docs/WINDOWS_INSTALLATION.md)
- **Linux Operations Guide:** [`docs/LINUX_INSTALLATION.md`](docs/LINUX_INSTALLATION.md)
- **macOS Operations Guide:** [`docs/MACOS_INSTALLATION.md`](docs/MACOS_INSTALLATION.md)
- **Cross-Platform Compatibility Matrix:** [`docs/CROSS_PLATFORM_COMPATIBILITY.md`](docs/CROSS_PLATFORM_COMPATIBILITY.md)
- **Architecture Specification:** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- **Platform Features & Capabilities:** [`docs/FEATURES.md`](docs/FEATURES.md)
- **Security Policy:** [`docs/SECURITY.md`](docs/SECURITY.md)
- **Troubleshooting Manual:** [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md)
- **Contribution Guide:** [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md)
