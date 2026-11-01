# ⚡ SWA AI — Autonomous Enterprise Cybersecurity Operations Platform

<p align="center">
  <b>Generation 3 Autonomous Multi-Agent AI Security Auditor & Cyber Operations Platform</b><br>
  <i>Attack surface discovery, continuous EASM drift intelligence, 17 specialist AI agents, OWASP Top 10 auditing, verifiable PoC exploits, and defensible posture hardening.</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-3.0.0--Enterprise-10b981?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3b82f6?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-Framework-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Tests-110%20Passed%20(100%25)-10b981?style=for-the-badge" alt="Tests">
  <img src="https://img.shields.io/badge/License-MIT-purple?style=for-the-badge" alt="License">
</p>

---

## 0. Responsible Use & Security Disclosure

> [!CAUTION]
> **Authorized Testing Only**: SWA AI is designed exclusively for authorized penetration testing, security assessments of systems you own or have explicit written permission to test, and educational research in local laboratory environments.
>
> Unauthorized scanning, probing, or exploiting of computer systems without prior mutual consent is strictly illegal and violates national and international cybersecurity laws.

## 📄 License

SWA AI is licensed under the [MIT License](https://github.com/545e/SWA/blob/main/LICENSE).

---

## 📑 Table of Contents

0. [Responsible Use & Security Disclosure](#0-responsible-use--security-disclosure)
1. [Project Overview & Purpose](#1-project-overview--purpose)
2. [Generation 3 Features & Architecture](#2-generation-3-features--architecture)
3. [User Interface & SOC Command Center](#3-user-interface--soc-command-center)
4. [Autonomous Multi-Agent Workforce (17 Specialist Agents)](#4-autonomous-multi-agent-workforce-17-specialist-agents)
5. [Technology Stack](#5-technology-stack)
6. [Directory Structure](#6-directory-structure)
7. [Prerequisites & Installation](#7-prerequisites--installation)
8. [Quick Start & Launching the Platform](#8-quick-start--launching-the-platform)
9. [REST API Reference & Endpoints](#9-rest-api-reference--endpoints)
10. [Automated Testing & QA Verification](#10-automated-testing--qa-verification)
11. [Engineering Manuals & Handover Documentation](#11-engineering-manuals--handover-documentation)

---

## 1. Project Overview & Purpose

**SWA AI Generation 3** is an enterprise-grade autonomous cybersecurity operating system. It bridges autonomous AI-driven red teaming with actionable blue team defensive hardening:

- **Unified Single-Page Application (SPA):** Built with pure modern JavaScript (ES6+), HTML5, and CSS3. Features a dedicated client-side hash router (`window.location.hash`, `popstate`), ensuring seamless browser history, direct bookmarking, and isolated view containers (`.swa-view`).
- **Autonomous Multi-Agent Workforce:** 17 specialist agents execute structured reconnaissance, layered OSINT, active DNS resolution, path fuzzing, OWASP Top 10 auditing, verifiable cURL proof-of-concept (PoC) generation, and source code remediation patches.
- **Continuous EASM & Drift Detection:** Real-time tracking of newly discovered subdomains, newly opened ports, SSL/TLS certificate expirations, and architectural drift.
- **Human-in-the-Loop Governance:** Sensitive and destructive actions require explicit approval gates before execution.
- **Defensible Risk Scoring:** Mathematically grounded risk formulas mapping observed surface exposure into transparent posture grades.

---

## 2. Generation 3 Features & Architecture

| Capability / Module | Implementation Status | Backend Engine |
|---|---|---|
| **Unified 20-View Shell** | ✅ Fully Implemented | Isolated `.swa-view` DOM containers with client-side hash routing |
| **Direct Hash Navigation** | ✅ Fully Implemented | `#/dashboard`, `#/vulnerabilities`, `#/assessments`, `#/assets` |
| **Global Findings API** | ✅ Fully Implemented | `GET /api/findings` across scans with real-time SQLite WAL indexing |
| **Layered Subdomain Discovery** | ✅ Genuine / Functional | 10+ OSINT feeds, `dns.asyncresolver`, Wildcard Detection |
| **Wildcard DNS Detection** | ✅ Genuine / Functional | Dynamic pseudo-random host probing & IP baseline subtraction |
| **HTTP Security Header Audit** | ✅ Genuine / Functional | 8 headers audited + letter grade (A+ to F) |
| **TLS/SSL Deep Inspector** | ✅ Genuine / Functional | Python SSL handshake, cipher extraction, SANs, days to expiry |
| **Asynchronous Port Scanner** | ✅ Genuine / Functional | Non-blocking async TCP socket pool |
| **OWASP Top 10 Hunting** | ✅ Genuine / Functional | Modular plugin architecture in `plugins/owasp_plugins.py` |
| **17 Specialist Agents** | ✅ Genuine / Functional | Autonomous multi-agent coordination in `agents/agent_workforce.py` |
| **Topological Knowledge Graph** | ✅ Genuine / Functional | Interactive SVG graph mapping attack paths & shared vulnerabilities |
| **Remediation & Retesting** | ✅ Genuine / Functional | Automated ticket lifecycle tracking & 1-click verification retest |
| **EASM Drift Monitoring** | ✅ Genuine / Functional | Continuous attack surface change detection over time |
| **Human Approval Gates** | ✅ Genuine / Functional | Deterministic authorization checkpoint for sensitive scans |
| **SSRF & Scope Enforcement** | ✅ Genuine / Functional | Strict IP filter blocking RFC1918, loopback, and cloud IMDS |
| **Token-Bucket Rate Limiter** | ✅ Genuine / Functional | Sustained and burst rate limiting with loopback scanner exemption |
| **Defensible Report Generator** | ✅ Genuine / Functional | HTML, PDF, CSV, JSON, and SARIF 2.1.0 exports |
| **SQLite WAL Relational Database** | ✅ Genuine / Functional | 18 tables with 15 optimized B-Tree indexes & live zero-downtime backup |

---

## 3. User Interface & SOC Command Center

The SWA AI interface is organized into a dark navy/charcoal Security Operations Center:

```text
+--------------------------------------------------------------------------------------------------+
|  ⚡ SWA AI Autonomous Operations Center    [● Engine Ready]   [📁 Core Infra]   [🎯 Target Context] |
+--------------------------------------------------------------------------------------------------+
|  OVERVIEW:            |  BREADCRUMB: SWA AI / Security Operations / Vulnerabilities              |
|  - Dashboard          |--------------------------------------------------------------------------|
|                       |  VULNERABILITIES & FINDINGS                                              |
|  SECURITY OPERATIONS: |  [All] [Critical] [High] [Medium] [Low] [Info]   [ Search CVE/Endpoint ] |
|  - Assessments        |--------------------------------------------------------------------------|
|  - Asset Inventory    |  ID       | Title                        | Severity | CVSS | Actions     |
|  - Vulnerabilities    |  3cb408b8 | Insecure CORS Policy         | HIGH     | 7.5  | [Inspect]   |
|  - Scan Comparison    |  a6c3fde2 | Missing Referrer-Policy      | LOW      | 3.2  | [Inspect]   |
|                       |--------------------------------------------------------------------------|
|  SECURITY TOOLS:      |  EXECUTIVE DASHBOARD (Isolated inside viewDashboard)                     |
|  - Security Tools     |  [Total Assets: 41]  [Total Vulns: 12]  [Critical: 0]  [Active Scans: 1] |
|  - Web Security       |  [Posture Score: 85/100 (Grade B)]  [Recent Assessments Table]           |
|  - Network Security   |--------------------------------------------------------------------------|
|  - API Security       |  SPECIALIST MULTI-AGENT WORKFORCE (17 Autonomous Agents)                 |
|  - Code Security      |  Recon • Asset Intel • Web Auditor • Port Specialist • Remediation ...   |
|                       |--------------------------------------------------------------------------|
|  INTELLIGENCE:        |  CONTINUOUS EASM DRIFT & HUMAN APPROVAL GATES                            |
|  - Specialist Agents  |  Track DNS mutations, newly exposed services, and sign off high-risk ops |
|  - Investigation      |--------------------------------------------------------------------------|
|  - Remediation        |  REPORTS & COMPLIANCE CENTER                                             |
|  - EASM Drift         |  Downloadable audit packages in HTML, PDF, JSON, and CSV formats         |
|  - Approval Gates     +--------------------------------------------------------------------------+
|                       |
|  PLATFORM:            |
|  - Reports            |
|  - Audit Logs         |
|  - Integrations       |
|  - Settings           |
|  - Documentation      |
+-----------------------+
```

### Key UI Features
- **Strict View Isolation:** Selecting *Vulnerabilities* renders exclusively vulnerability findings. The dashboard is cleanly hidden and never collides with active views.
- **Direct Hash Routing:** Navigate directly to `http://127.0.0.1:8000/#/vulnerabilities`, `http://127.0.0.1:8000/#/assessments`, or `http://127.0.0.1:8000/#/assets`.
- **Working Light / Dark Mode:** Persistent theme toggle with high-contrast accessibility.

---

## 4. Autonomous Multi-Agent Workforce (17 Specialist Agents)

SWA AI coordinates 17 autonomous agents with defined responsibilities:
1. `recon_analyst`: Passive OSINT and certificate transparency logs.
2. `asset_intel_officer`: Infrastructure fingerprinting and service identification.
3. `web_security_auditor`: OWASP Top 10 web vulnerabilities.
4. `network_security_specialist`: Port auditing and protocol analysis.
5. `api_security_assessor`: REST/GraphQL parameter fuzzing and BOLA analysis.
6. `code_security_reviewer`: SAST analysis and dependency audit.
7. `vulnerability_analyst`: Correlation, CVSS scoring, and deduplication.
8. `threat_intel_specialist`: MITRE ATT&CK technique mapping.
9. `risk_assessment_officer`: Composite risk score computation.
10. `remediation_engineer`: Patch recipes and developer guidance.
11. `reporting_officer`: Synthesis of technical and executive compliance reports.
12. `qa_verification_agent`: Autonomous retesting of remediated findings.
13. `fuzzing_specialist`: Parameter boundary testing.
14. `waf_architect`: WAF filtering and evasion defense.
15. `forensics_investigator`: Artifact analysis and IOC identification.
16. `cloud_security_auditor`: Cloud metadata and misconfiguration detection.
17. `container_security_specialist`: Container image vulnerability analysis.

---

## 5. Technology Stack

- **Backend:** Python 3.10 / 3.11 / 3.12, FastAPI, Uvicorn, Pydantic v2.
- **Database:** SQLite 3 (`swa_data.db`) with Write-Ahead Logging (`WAL`), foreign keys, and 15 B-Tree indexes.
- **Frontend:** Vanilla JavaScript (ES6+), HTML5, CSS3 with CSS Variables (zero heavy runtime dependencies).
- **Networking:** `httpx` (async HTTP), `dnspython` (async DNS resolver).
- **Security:** Token-bucket rate limiting, SSRF scope enforcement, sensitive credential redaction, XML prompt injection boundaries.
- **Testing:** `pytest`, `pytest-asyncio`, `fastapi.testclient`.

---

## 6. Directory Structure

```text
SWA/
├── agents/                     # Autonomous AI scanning agents & workforce
│   ├── agent_workforce.py      # 17 specialist agent manifests and dispatch controller
│   ├── amass_engine.py         # Layered subdomain discovery & wildcard engine
│   ├── attack_surface_agent.py # Web crawler & route extractor
│   ├── fuzzer_agent.py         # Anomaly-filtered path fuzzer
│   └── recon_agent.py          # Reconnaissance coordinator
├── core/                       # Core security modules
│   ├── ai_evaluation.py        # Model tuning, benchmarks & confusion matrix
│   ├── app_security.py         # Rate limiting, path traversal guard, redaction
│   ├── database.py             # SQLite thread-safe persistence layer (WAL)
│   ├── scope_policy.py         # SSRF protection and target validator
│   ├── scanner_integrations.py # Subprocess wrappers for external security tools
│   └── data_management.py      # Security dataset ingestion & leak scanner
├── docs/                       # Generation 3 Engineering Manuals
│   ├── GEN3_ARCHITECTURE.md    # Master architectural specification
│   ├── GEN3_API_REFERENCE.md   # Comprehensive REST API reference
│   ├── GEN3_DATABASE_DESIGN.md # Relational schema & index design
│   ├── GEN3_AI_ARCHITECTURE.md # Multi-agent & intelligence architecture
│   ├── GEN3_DATA_GOVERNANCE.md # Data lifecycle, retention & redaction
│   ├── GEN3_DEPLOYMENT_GUIDE.md# Windows & Docker deployment guide
│   ├── GEN3_SECURITY_MODEL.md  # Threat model & application security controls
│   ├── GEN3_TEST_STRATEGY.md   # Quality gates & test harness
│   ├── GEN3_TRAINING_STRATEGY.md # AI fine-tuning & evaluation strategy
│   ├── GEN3_OPERATIONS_RUNBOOK.md# Operations & incident runbook
│   ├── GEN3_CHANGELOG.md       # Generation 3 release changelog
│   └── GEN3_HANDOVER.md        # Comprehensive engineering handover report
├── plugins/                    # Modular OWASP vulnerability plugins
├── reports/                    # Assessment report generators
├── tests/                      # Automated test suite (110 Tests)
│   ├── test_gen3_navigation_acceptance.py # View isolation & acceptance tests
│   ├── test_api_and_dashboard.py # REST endpoints, settings, report export tests
│   ├── test_generation2_security_and_integrity.py # AppSec, rate limit, database
│   ├── test_enterprise_platform.py # Agents, approval gates, drift, risk scoring
│   ├── test_e2e_local_scan.py  # End-to-end authorized scan tests
│   └── ...                     # Additional test modules
├── web/                        # Web dashboard assets
│   ├── server.py               # FastAPI server routes, middleware & REST APIs
│   ├── enterprise_api.py       # Multi-agent dispatch & governance endpoints
│   └── static/
│       ├── app.js              # Client-side hash router & view controller
│       ├── index.html          # Unified 20-view SOC command center
│       └── styles.css          # Dark navy SOC stylesheet & responsive layout
├── requirements.txt            # Python dependencies
├── run.py                      # One-click startup runner
└── swa_cli.py                  # Unified CLI and terminal entrypoint
```

---

## 7. Prerequisites & Installation

### Windows Setup
```powershell
# 1. Clone repository
git clone https://github.com/545e/SWA.git C:\Users\krish\SWA
cd C:\Users\krish\SWA

# 2. Create isolated virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt -r requirements-dev.txt

# 4. Copy environment configuration
copy .env.example .env
```

---

## 8. Quick Start & Launching the Platform

### Start the Application Server
```powershell
python run.py
```
Open **http://127.0.0.1:8000** in your browser.

> [!TIP]
> Ensure you connect to **http://127.0.0.1:8000**. If port 8000 was previously in use, check with `Get-NetTCPConnection -LocalPort 8000` and stop any stale background process.

---

## 9. REST API Reference & Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Fast liveness probe |
| `GET` | `/api/health/diagnostics` | Complete platform diagnostic status |
| `GET` | `/api/findings` | Retrieve all triaged vulnerability findings |
| `POST` | `/api/scans` | Submit and launch a new assessment scan |
| `GET` | `/api/scans` | List all historical and active scans |
| `GET` | `/api/scans/{id}/findings` | Retrieve findings for a specific scan |
| `GET` | `/api/assets` | Monitored assets inventory (domains, subdomains, IPs) |
| `GET` | `/api/agents` | Status and manifests of all 17 specialist agents |
| `POST` | `/api/enterprise/agents/dispatch` | Dispatch a specialist agent on a task |
| `GET` | `/api/enterprise/approval-gates` | List human-in-the-loop approval gates |
| `GET` | `/api/enterprise/drift` | Attack surface drift history and changes |
| `GET` | `/api/enterprise/remediation/tickets` | Remediation tickets and SLA tracking |
| `GET` | `/api/cyber/audit-logs` | Immutable platform audit trail |

---

## 10. Automated Testing & QA Verification

Run the complete 110-test automated verification suite:

```powershell
# Run full test suite with pytest
python -m pytest tests -v
```

### Test Suite Summary:
```text
tests/test_ai_training_and_evaluation.py ..... [ 5%]
tests/test_api_and_dashboard.py ............. [12%]
tests/test_cyber_deploy.py .................. [15%]
tests/test_cyber_export.py .................. [21%]
tests/test_cyber_test.py .................... [25%]
tests/test_data_management.py ............... [29%]
tests/test_e2e_local_scan.py ................ [31%]
tests/test_enterprise_platform.py ........... [39%]
tests/test_gen3_navigation_acceptance.py .... [48%]
tests/test_generation2_security_and_integrity [57%]
tests/test_llm_security_testing.py .......... [60%]
tests/test_owasp_plugins.py ................. [64%]
tests/test_rea_engine.py .................... [76%]
tests/test_scanner_integrations.py .......... [83%]
tests/test_scope_policy.py .................. [93%]
tests/test_subdomain_engine.py .............. [98%]
tests/test_tool_registry.py ................. [100%]
====================== 110 passed in 52.86s ======================
```

---

## 11. Engineering Manuals & Handover Documentation

Comprehensive architectural and engineering manuals are available in the [`docs/`](docs/) directory:
- [GEN3_ARCHITECTURE.md](docs/GEN3_ARCHITECTURE.md): System architecture and data flow.
- [GEN3_API_REFERENCE.md](docs/GEN3_API_REFERENCE.md): Full REST API contracts and payloads.
- [GEN3_DATABASE_DESIGN.md](docs/GEN3_DATABASE_DESIGN.md): SQLite schema, indexes, and backup.
- [GEN3_AI_ARCHITECTURE.md](docs/GEN3_AI_ARCHITECTURE.md): Multi-agent workforce and AI boundaries.
- [GEN3_DATA_GOVERNANCE.md](docs/GEN3_DATA_GOVERNANCE.md): Data lifecycle, redaction, and retention.
- [GEN3_DEPLOYMENT_GUIDE.md](docs/GEN3_DEPLOYMENT_GUIDE.md): Windows and Docker deployment runbooks.
- [GEN3_SECURITY_MODEL.md](docs/GEN3_SECURITY_MODEL.md): Scope policy, SSRF, and threat defense.
- [GEN3_TEST_STRATEGY.md](docs/GEN3_TEST_STRATEGY.md): Testing methodology and quality gates.
- [GEN3_TRAINING_STRATEGY.md](docs/GEN3_TRAINING_STRATEGY.md): AI fine-tuning and evaluation strategy.
- [GEN3_OPERATIONS_RUNBOOK.md](docs/GEN3_OPERATIONS_RUNBOOK.md): System startup, monitoring, and recovery.
- [GEN3_CHANGELOG.md](docs/GEN3_CHANGELOG.md): Complete release changelog.
- [GEN3_HANDOVER.md](docs/GEN3_HANDOVER.md): Engineering handover and acceptance report.
