# SWA AI — Final Engineering Handover & Operations Guide

**Document Version:** 3.0.0-Enterprise  
**Effective Date:** 2026-11-01  
**Project:** SWA AI — Autonomous Cybersecurity Operating System  
**Repository:** `https://github.com/545e/SWA.git`  
**Branch:** `main` (Verified Commit: `ee64a74`)  
**Local Application:** `http://127.0.0.1:8000`

---

## 1. Quick Start & Operational Instructions

### Starting the Server
```powershell
Set-Location C:\Users\krish\SWA
python run.py
```
- The application automatically detects available ports (defaulting to 8000), initializes the thread-safe SQLite database (`swa_data.db`), and starts the Uvicorn web server.
- The web UI will be accessible immediately at `http://127.0.0.1:8000`.

### Running Automated Quality Gates
```powershell
Set-Location C:\Users\krish\SWA
python -m pytest tests
```
- Executes all 89 automated test suites spanning AI evaluation, API, deployment, exports, local scans, multi-agent workforce, knowledge graph, and risk engines.

---

## 2. Key Architecture & File Map

| Path | Purpose & Functionality |
| :--- | :--- |
| `agents/agent_workforce.py` | 17 specialist agent implementations, manifests, permissions, and task runner. |
| `agents/orchestrator.py` | Master orchestrator coordinating multi-phase assessments and intelligence syncing. |
| `core/approval_engine.py` | Human-in-the-loop authorization gates for aggressive testing and scope modifications. |
| `core/knowledge_graph.py` | Relationship-based graph engine connecting perimeter assets, services, and findings. |
| `core/attack_surface_intel.py` | Continuous Attack Surface Intelligence (EASM) detecting DNS, port, tech, and TLS drift. |
| `core/risk_engine.py` | Defensible, explainable risk prioritization formula with mathematical step-by-step rationales. |
| `core/remediation_engine.py` | Finding lifecycle state machine (8 stages) with automated retest probe verification. |
| `core/intelligence_models.py` | Pydantic schemas for multi-agent tasks, knowledge graph, drift, and approvals. |
| `core/database.py` | Thread-safe SQLite store with WAL mode, 18 tables, and non-destructive schema migrations. |
| `reports/enterprise_reports.py`| 12-template report generator producing HTML, JSON, Markdown, CSV, and SARIF 2.1.0. |
| `web/enterprise_api.py` | Dedicated REST router for context, agents, approvals, graph, drift, and diagnostics. |
| `web/server.py` | FastAPI application server, static mount, WebSocket live feeds, and security headers. |
| `web/static/app.js` | Frontend client controller with Global Context syncing, Kanban, and Agent grids. |
| `web/static/index.html` | Responsive enterprise UI shell, topbar context bar, and modular view tabs. |
| `web/static/styles.css` | Glassmorphic design system with dark/light themes and WCAG 2.2 AA contrast. |
| `tests/test_enterprise_platform.py` | Comprehensive test suite for all enterprise capabilities (9 tests). |

---

## 3. Verified Endpoints Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/context` | `GET`, `POST` | Persistent Global Security Context (Workspace, Project, Target, Posture Grade). |
| `/api/agents` | `GET` | List manifests, roles, tools, and limits for all 17 specialist agents. |
| `/api/agents/{role}/task` | `POST` | Dispatch ad-hoc autonomous security tasks to specialist agents. |
| `/api/approvals` | `GET`, `POST` | List and create human-in-the-loop approval gate requests. |
| `/api/approvals/{id}/decide`| `POST` | Operator sign-off (Approve / Reject) with mandatory rationale. |
| `/api/graph` | `GET` | Return full security knowledge graph nodes, edges, and category summary. |
| `/api/graph/exposed-assets` | `GET` | Query perimeter assets with active services or vulnerabilities. |
| `/api/graph/shared-vulnerabilities` | `GET` | Query cross-asset shared vulnerabilities and blast radius. |
| `/api/easm/drift` | `GET` | Retrieve continuous attack surface change and drift events. |
| `/api/remediation/tickets` | `GET` | List remediation lifecycle tickets across all 8 states. |
| `/api/remediation/tickets/{id}/transition` | `POST` | Transition ticket lifecycle status (e.g., `DISCOVERED` $\rightarrow$ `IN_PROGRESS`). |
| `/api/remediation/tickets/{id}/retest` | `POST` | Trigger automated HTTP retest probe to verify vulnerability fix. |
| `/api/reports/templates` | `GET` | List all 12 standardized enterprise report templates. |
| `/api/reports/generate` | `POST` | Generate any of the 12 reports in HTML, JSON, Markdown, or CSV. |
| `/api/health/diagnostics` | `GET` | Comprehensive health telemetry across all 6 core subsystems. |

---

## 4. Operational Readiness & Residual Risks
- **Zero Critical / P0 Blockers**: All core systems, database migrations, and APIs are operational and verified.
- **Scope Policy Enforced**: Scanning is strictly confined to explicitly authorized assets.
- **Continuous Monitoring Active**: The attack surface drift engine monitors for infrastructure changes across scan cycles.
- **Audit Logs Guaranteed**: All actions, approvals, and tool executions are persistently recorded in `cyber_audit_logs`.
