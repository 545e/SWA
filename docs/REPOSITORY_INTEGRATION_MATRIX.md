# SWA AI — Repository Integration Matrix

This matrix tracks the integration status of all modules, source repositories, and tools into the unified SWA AI cybersecurity platform.

| Component / Subsystem | Primary Origin | Integration Target | Capabilities Verified | Status |
|---|---|---|---|---|
| **Multi-Agent Workforce (85 Agents)** | `origin/generation-2-complete-modernization` | `agents/agent_workforce.py`, `core/agent_registry.py` | 5 Operational Tiers, dynamic discovery, schemas, task dispatch | `INTEGRATED` |
| **Audit Log Trail** | `swa-ai/core/audit.py` | `core/audit.py` | Thread-safe append-only SQLite log, `/api/cyber/audit-logs` | `INTEGRATED` |
| **Canonical Security Scoring** | `swa-ai/core/scoring.py` | `core/scoring.py` | Unified penalty weights (-30 CRIT, -18 HIGH, -8 MED, -3 LOW, -1 INFO) | `INTEGRATED` |
| **Version & Codename** | `swa-ai/core/version.py` | `core/version.py` | Version 2.3.0 "Sentinel", synchronizing API, CLI, and docs | `INTEGRATED` |
| **Cloud & Deployment Templates** | `swa-ai/deploy/` | `deploy/` | AWS (EC2, ECS), Azure, GCP Cloud Run, Docker Compose, Linux systemd | `INTEGRATED` |
| **System & Deployment Tests** | `swa-ai/tests/` | `tests/` | `test_deployment_readiness.py`, `test_system_status.py`, `tests/e2e/` | `INTEGRATED` |
| **Database Historical Records** | `swa-ai/swa_data.db` | `swa_data.db` | 76 scans, 266 findings, 2,296 historical logs merged losslessly | `INTEGRATED` |
| **Cross-Platform Scripts** | `origin/generation-2-complete-modernization` | Root Directory | `install.bat`, `install.sh`, `install.ps1`, `install_macos.sh`, `run.*`, `stop.*` | `INTEGRATED` |
| **REA Reverse Engineering Engine** | `github.com/morluto/rea` | `core/rea_engine.py` | Binary string analysis, entropy extraction, native fallback | `INTEGRATED` |
| **Vulnerability Hunters & OWASP** | Primary codebase | `agents/vuln_hunter_agent.py`, `core/injection_suite.py` | SQLi, XSS, SSRF, Command Injection, XXE, Path Traversal | `INTEGRATED` |
| **Threat Intelligence Integrations** | API Adapters | `core/integrations/threat_intel.py` | VirusTotal, AbuseIPDB, Shodan, Censys, AlienVault OTX, URLhaus | `INTEGRATED` |
| **Enterprise SIEM / EDR Integrations** | Security Adapters | `core/integrations/security_platforms.py` | Wazuh, Splunk, Elastic, Sentinel, CrowdStrike, DefectDojo | `INTEGRATED` |
| **Encrypted API Key Management** | Security Subsystem | `core/credentials.py` | Fernet/AES-256 at rest, masked display, safe connection testing | `INTEGRATED` |
| **Configurable AI Models** | LLM Subsystem | `core/ai_models.py`, `core/llm_client.py` | Provider selection, availability test, timeouts, fallbacks | `INTEGRATED` |
| **Post-Deployment Acceptance** | Modernization | `core/post_deployment_checklist.py` | Persistent 10-section checklist, exportable markdown report | `INTEGRATED` |
| **Cyber Export & SARIF Engine** | Primary codebase | `core/cyber_export.py` | HTML, PDF, Markdown, JSON, CSV, SARIF exports | `INTEGRATED` |
| **Cyber Test Harness** | Primary codebase | `core/cyber_test.py` | Synthetic suite execution, diagnostic probes, test histories | `INTEGRATED` |
| **Cyber Deploy Orchestrator** | Primary codebase | `core/cyber_deploy.py` | Environment acceptance, migration verification, rollback gates | `INTEGRATED` |
| **14-View Main Navigation UI** | Web Subsystem | `web/static/` | Dashboard, Assessments, Assets, Vulns, Tools, Agents, etc. | `INTEGRATED` |
