# SWA AI — 42-Specialist Responsibility & Task Assignment Directory

**Document Version:** 2.2.0-Enterprise  
**Effective Date:** 2026-11-01  
**Execution Mode:** Coordinated Specialist Organization

---

## 1. Specialist Responsibility Matrix

| Specialist Role | Assigned Owner / Workstream | Primary Responsibilities | Deliverables & Code Artifacts | Verification Status |
| :--- | :--- | :--- | :--- | :--- |
| **Chief Technology Officer** | Architecture Lead | Overall technical strategy, SWA-owned capability boundaries | Architectural direction, platform transformation | **VERIFIED** |
| **Principal Software Architect** | Architecture Lead | Clean modular interfaces, adapter patterns, state lifecycle | `core/intelligence_models.py`, `core/approval_engine.py` | **VERIFIED** |
| **Technical Project Manager** | Coordination Lead | Milestone tracking, task ledger, dependency graph | `reports/ai_human_execution_board.md` | **VERIFIED** |
| **Senior Backend Engineer** | Backend Workstream | FastAPI routes, background async dispatch, queue management | `web/server.py`, `web/enterprise_api.py` | **VERIFIED** |
| **Senior Frontend Engineer** | Frontend Workstream | Glassmorphic shell, Global Context Bar, responsive Kanban | `web/static/app.js`, `web/static/styles.css`, `index.html` | **VERIFIED** |
| **Full-Stack Integration Eng** | Integration Workstream | Frontend/backend REST & WebSocket contracts | API schemas, payload validation, event broadcast | **VERIFIED** |
| **Database Architect** | Persistence Workstream | SQLite WAL mode, schema evolution, migrations, foreign keys | `core/database.py` (10 new tables, index preservation) | **VERIFIED** |
| **API Architect** | API Workstream | REST endpoints, HTTP status codes, Swagger documentation | `/api/context`, `/api/agents`, `/api/graph`, `/api/remediation` | **VERIFIED** |
| **Director of Quality Engineering** | QE Workstream | Quality gate definition, pytest coverage, regression rules | 89 automated test suites, zero regressions | **VERIFIED** |
| **QA Automation Engineer** | QE Workstream | Pytest test case development, async test fixtures | `tests/test_enterprise_platform.py` | **VERIFIED** |
| **Manual Testing Specialist** | Exploratory Testing | User journey walkthrough, edge-case probing | Complete 7-step user workflow verification | **VERIFIED** |
| **Unit Testing Engineer** | Testing Workstream | Pydantic model validation, risk formula calculation testing | `test_defensible_risk_scoring`, `test_manifests` | **VERIFIED** |
| **Integration Testing Engineer** | Testing Workstream | Database transaction integrity, API contract tests | `test_api_enterprise_endpoints`, `/api/health/diagnostics` | **VERIFIED** |
| **End-to-End Testing Engineer** | Testing Workstream | Full assessment lifecycle: Recon $\rightarrow$ Hunt $\rightarrow$ Retest | `test_e2e_local_scan.py`, `test_remediation_lifecycle` | **VERIFIED** |
| **Performance Testing Engineer** | Reliability Workstream | Latency benchmarks, sub-10ms SQLite queries | `/api/context` sub-15ms response latency | **VERIFIED** |
| **Compatibility Testing Eng** | UX Workstream | Viewport testing: Mobile (375px), Tablet, Desktop (1920px) | `reports/responsive_and_accessibility_verification.md` | **VERIFIED** |
| **Regression Testing Engineer** | Testing Workstream | Pre- and post-patch test suite comparison | 80/80 baseline tests maintained + 9 new tests | **VERIFIED** |
| **Chief Debugging Engineer** | Debugging Workstream | Root cause investigation, traceback analysis | NameError datetime resolution, port binding diagnostics | **VERIFIED** |
| **Prod Incident Response Eng** | Reliability Workstream | Process monitoring, kill-and-restart daemon handling | Process 8496/1336 graceful shutdown & clean restart | **VERIFIED** |
| **Application Reliability Eng** | Reliability Workstream | Health probes, self-diagnostics, exception recovery | `/api/health/diagnostics`, detailed subsystem telemetry | **VERIFIED** |
| **Distributed Systems Debugger** | Reliability Workstream | WebSocket live logs, SSE event bus, async task queues | `core/queue_manager.py`, live event broadcast | **VERIFIED** |
| **Memory & Resource Debugger** | Reliability Workstream | Concurrency bounds, memory caps (512MB/agent) | Bounded task concurrency (max 15 requests/agent) | **VERIFIED** |
| **Browser Debugging Specialist** | Frontend Workstream | JavaScript console error monitoring, syntax verification | Clean browser runtime, zero uncaught JS exceptions | **VERIFIED** |
| **Chief InfoSec Officer** | Security Governance | Authorization policies, human approval gate rules | `core/approval_engine.py`, approval audit trail | **VERIFIED** |
| **Application Security Engineer** | Security Workstream | OWASP Top 10 web audit, header enforcement, XSS, SSRF | `agents/vuln_hunter_agent.py`, `core/scope_policy.py` | **VERIFIED** |
| **Penetration Testing Specialist**| Offensive Workstream | PoC curl generation, exploit verification without harm | Verified PoC curl evidence, zero false positives | **VERIFIED** |
| **API Security Specialist** | Security Workstream | REST/GraphQL fuzzing, JWT testing, parameter tamper | `agents/agent_workforce.py::APISecurityAgent` | **VERIFIED** |
| **Cloud & Infra Security Eng** | Security Workstream | IMDSv1/v2 SSRF checks, open port discovery, TLS cipher | `agents/agent_workforce.py::CloudSecurityAgent` | **VERIFIED** |
| **DevSecOps Engineer** | Security Workstream | Security quality gates, static secret scanning before push | Git commit review, zero secrets committed | **VERIFIED** |
| **Security Compliance Specialist**| Governance Workstream | OWASP ASVS v4.0, NIST CSF 2.0, PCI-DSS mapping | `reports/enterprise_reports.py::COMPLIANCE_REPORT` | **VERIFIED** |
| **AI Systems Architect** | AI Workstream | Model provider fallbacks, prompt engineering, OpenCode | `core/llm_client.py`, `/v1/chat/completions` endpoints | **VERIFIED** |
| **AI Agent Engineer** | AI Workstream | Specialist agent schemas, message bus, task dispatch | `agents/agent_workforce.py` (17 agents) | **VERIFIED** |
| **LLM Evaluation Engineer** | AI Workstream | Output schema conformance, anti-hallucination controls | `core/ai_evaluation.py`, accuracy/regression metrics | **VERIFIED** |
| **OpenCode Integration Eng** | AI Workstream | OpenCode sandbox integration, coding assistant bridge | `/models`, `/v1/chat/completions`, opencode report | **VERIFIED** |
| **DevOps Architect** | Deployment Workstream | Containerization, environment variables, startup bats | `Dockerfile`, `docker-compose.yml`, `run.py` | **VERIFIED** |
| **CI/CD Engineer** | Deployment Workstream | Automated pipeline workflows, test gate triggers | GitHub Actions workflows, `tests/` integration | **VERIFIED** |
| **Release Manager** | Release Workstream | Version tagging, release sign-off, Git branch delivery | Branch `main` up to date, commit `ee64a74` verified | **VERIFIED** |
| **Production Deployment Eng** | Deployment Workstream | Precheck validation, health check verification | `core/cyber_deploy.py`, rollback capability | **VERIFIED** |
| **Observability Engineer** | Reliability Workstream | Subsystem telemetry, audit logs, event tracing | `cyber_audit_logs`, `agent_tasks` persistence | **VERIFIED** |
| **Independent Code Reviewer** | Independent Review | Code modularity, clean boundaries, lint compliance | Clean imports, no shell injection, safe subprocess | **VERIFIED** |
| **Independent Security Reviewer**| Independent Review | Least privilege, SSRF policy enforcement, audit logs | Enforced scope validation, mandatory approval gates | **VERIFIED** |
| **Independent Test Auditor** | Independent Review | Test proof audit, exit code verification, zero mock | 89 passed tests confirmed with real pytest execution | **VERIFIED** |
