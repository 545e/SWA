# COMPLETE REPOSITORY ARCHITECTURE
## SNMK / SWA AI — Autonomous Enterprise Cybersecurity & Threat Intelligence Platform

**Official Target Repository:** `https://github.com/545e/snmk.git`  
**Platform Version:** 2.3.0 Enterprise  
**Runtime Architecture:** Python 3.10 / 3.11 / 3.12, FastAPI, SQLite WAL, HTML5/CSS3/Vanilla JS (No external build framework dependencies)  
**Daemon Port:** `http://127.0.0.1:8000`

---

## 1. Directory Structure & System Responsibilities

```text
C:\Users\krish\SWA (snmk)
├── .github/
│   └── workflows/              # GitHub Actions CI, Docker build, CodeQL SAST, and automated release
├── agents/                     # Specialized autonomous cybersecurity agents
│   ├── agent_workforce.py      # Core agent workforce execution loop & task handoffs
│   ├── exploit_validator_agent.py # Non-destructive exploit validation & cURL PoC generation
│   ├── fuzzer_agent.py         # Adaptive boundary, parameter, and header fuzzer
│   └── vuln_hunter_agent.py    # Multi-vector vulnerability scanner and proof-of-concept synthesis
├── benchmarks/                 # Polyglot performance benchmarks across query latency & memory
├── config/                     # Configuration definitions
│   ├── 85_agents_matrix.json   # Definitive metadata registry for all 85 registered specialist agents
│   ├── scan_profiles.json      # Assessment profile definitions (Passive, Standard, Deep, Red Team)
│   └── targets.json            # Strict SSRF target scope authorization list
├── core/                       # Core application domain & business logic
│   ├── agent_memory.py         # Working, Episodic, and Semantic memory with secret scrubbing & token budgeting
│   ├── agent_registry.py       # Central agent registry managing all 85 agents across 5 operational tiers
│   ├── ai_evaluation.py        # Model benchmarking: precision, recall, F1, confusion matrices, token costs
│   ├── ai_models.py            # Model registry: OpenAI, Anthropic, Gemini, OpenRouter, Azure, Ollama
│   ├── ai_training.py          # Machine learning fine-tuning engine & checkpoint management
│   ├── credentials.py          # Cryptographic vault: Fernet AES-128 + PBKDF2HMAC key derivation
│   ├── cyber_tools.py          # 23 internal cybersecurity tool adapters & probers
│   ├── database.py             # Thread-safe SQLite engine with WAL mode and schema integrity
│   ├── integrations/           # Cloud, AI, Security Platform, and Threat Intel integration adapters
│   ├── kill_chain/             # 7-stage Lockheed Martin Cyber Kill Chain correlation engine
│   ├── knowledge_graph.py      # Relationship graph: Orgs, Domains, IPs, Services, CVEs, Assets
│   ├── llm_client.py           # SWALLMClient: multi-provider reasoning with heuristic fallback & RAG grounding
│   ├── llm_security_testing.py # 12-vector OWASP Top 10 for LLM adversarial red-team harness
│   ├── rag_engine.py           # BM25 + keyword hybrid retrieval, semantic chunking, and citation grounding
│   ├── tool_registry.py        # Centralized tool execution and parameter validation hub
│   └── version.py              # Single source of truth for platform version
├── data/                       # Local state, reports, databases, and model checkpoints
│   └── swa_data.db             # Primary persistent SQLite store (WAL mode)
├── docs/                       # Architectural, operational, API, and compliance documentation
├── plugins/                    # Dynamic scanning extensions
│   ├── owasp_plugins.py        # 10 OWASP Top 10 modernized v3.0.0 security agents
│   └── plugin_manager.py       # Plugin discovery, lifecycle toggling, and task triggers
├── reports/                    # Executive & technical report generation
│   ├── nessus_report_engine.py # Nessus v2 XML, HTML, PDF, and CSV report compiler
│   └── vulnerability_reports.py# Multi-format report builder
├── tests/                      # Pytest automated test suite (235+ passing tests)
└── web/                        # Web presentation and API routing layer
    ├── enterprise_api.py       # Extended enterprise management API routers
    ├── kill_chain_router.py    # Cyber kill chain endpoints & threat correlation routes
    ├── server.py               # Master FastAPI application, WebSocket hub, and route registry
    ├── static/                 # Frontend client assets
    │   ├── app.js              # Single-page application controller & reactive state manager
    │   ├── index.html          # Dual-theme SOC cybersecurity executive dashboard
    │   └── styles.css          # Design token architecture, responsive layout, and theme engines
    └── v1/                     # Unified /api/v1 REST architectural routes
```

---

## 2. Core Execution Lifecycle

1. **Application Startup**:
   - `web/server.py` boots via Uvicorn.
   - `core/database.py` validates SQLite database file, enforces `PRAGMA foreign_keys = ON;`, and initializes WAL journal mode (`PRAGMA journal_mode = WAL;`).
   - `core/credentials.py` loads or generates master encryption key `.swa_master.key`.
   - `core/integrations/registry.py` registers cloud, AI, security platforms, and threat intel providers.
   - `core/agent_registry.py` registers all 85 agents into operational memory tiers.
   - `core/tool_registry.py` validates tool adapters, executable paths, and parameter schemas.
   - `core/rag_engine.py` and `core/agent_memory.py` initialize persistent schema tables.

2. **Frontend-to-Backend Reactive Communication**:
   - Web client connects via REST API (`/api/*` and `/api/v1/*`) and WebSocket channels.
   - Dual-theme engine checks `localStorage.getItem('swa_theme')` immediately in `<head>` to eliminate theme flicker.
   - Asynchronous AJAX polling and event streams update executive scorecard, active agent counts, and live findings feed.

3. **Autonomous Assessment Execution**:
   - Target input is validated against `config/targets.json` and RFC 1918 / cloud metadata SSRF guardrails.
   - Orchestrator delegates tasks to specialized agents (e.g. `ReconnaissanceAgent` → `PortScannerAgent` → `VulnHunterAgent` → `ExploitValidatorAgent`).
   - Evidence is captured with raw HTTP headers, payload parameters, and verified responses.
   - Findings are inserted into `swa_data.db` with CVSS v3.1 scoring, CVE/CWE tagging, and remediation status.
   - Knowledge graph (`core/knowledge_graph.py`) automatically ingests domain, application, and vulnerability nodes.
   - Cyber Kill Chain correlation engine classifies findings across the 7 attack stages.
