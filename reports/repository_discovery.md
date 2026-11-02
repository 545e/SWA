# Repository Discovery Report — SWA AI Autonomous Security Auditor

## 1. Project Identity & Architecture
- **Repository**: `https://github.com/545e/SWA.git`
- **Application**: SWA AI — Autonomous Enterprise Security Auditor & Red Team Hub
- **Branch**: `main`
- **Latest Commit**: `c63d55e`
- **Backend Framework**: Python 3.10+ / FastAPI / Uvicorn (ASGI)
- **Frontend Architecture**: Native Vanilla ES6+ SPA, CSS3 Variables, WebSocket & SSE event bus
- **Persistence**: SQLite with WAL mode, parameterized statements, dynamic column migration
- **Target Hardware**: 2 vCPU / 3 GB RAM (Linux VPS, Windows 10/11, Docker container)

## 2. Directory Layout
```
swa-ai/
├── agents/                       # Specialized Cyber Assessment Agents
│   ├── amass_engine.py           # Layered Subdomain Engine (DNS + CT + OSINT + Wildcard)
│   ├── attack_surface_agent.py   # REST/GraphQL API & URL Crawler
│   ├── dependency_confusion_agent.py # Package Registry Exposure Prober
│   ├── exploit_validator_agent.py# Non-destructive PoC verification engine
│   ├── fuzzer_agent.py           # Baseline-calibrated endpoint & parameter fuzzer
│   ├── orchestrator.py           # Multi-stage autonomous workflow coordinator
│   ├── recon_agent.py            # DNS, TCP Port, TLS, HTTP Header reconnaissance
│   ├── remediation_agent.py      # Automated code patch & mitigation synthesizer
│   └── vuln_hunter_agent.py      # OWASP Top 10 web vulnerability detector
├── core/                         # Core Architecture & Utilities
│   ├── database.py               # SQLite persistence, migrations & query layer
│   ├── models.py                 # Pydantic v2 domain models & schemas
│   ├── queue_manager.py          # Background worker tasks & event bus dispatch
│   ├── scanner_integrations.py   # Wrappers for Nmap, SQLmap, Nuclei, ZAP
│   ├── scope_policy.py           # Target authorization, SSRF & IMDS defense
│   ├── scoring.py                # Canonical security posture risk formula
│   └── version.py                # Single source of truth for semantic versioning
├── deploy/                       # Multi-platform deployment manifests
│   ├── aws/                      # ECS Fargate task definition & EC2 UserData
│   ├── azure/                    # Azure Container App manifest
│   ├── docker/                   # Production Docker Compose & env configs
│   ├── gcp/                      # Google Cloud Run service definition
│   ├── linux/                    # Systemd unit & Nginx reverse proxy configuration
│   ├── platform/                 # Render & Railway blueprints
│   └── self-hosted/              # Air-gapped offline installer & automated backup scripts
├── docs/                         # Comprehensive architectural and operator guides
├── plugins/                      # Modular security scanning plugins (OWASP checks)
├── reports/                      # Assessment report generators & deployment test registers
├── tests/                        # Automated test suites (55+ tests)
└── web/                          # Web Server & User Interface
    ├── server.py                 # FastAPI REST API, WebSocket & SSE endpoints
    └── static/                   # SOC Dashboard UI (HTML, CSS, JS)
```

## 3. Discovered Entry Points
1. **Web Dashboard Server**: `python run.py` (FastAPI + Uvicorn on `http://127.0.0.1:8000`)
2. **Unified CLI Suite**: `python swa_cli.py [OPTIONS]` (scan, probe, hash, cidr, revshell, forensics)
3. **Platform Launchers**:
   - Windows CMD: `run.bat` & `install.bat`
   - Windows PowerShell: `run.ps1` & `install.ps1`
   - Linux/POSIX: `run.sh` & `install.sh`
   - Docker Container: `docker compose up -d`
