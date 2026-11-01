# SWA AI — Generation 3 Baseline Report
**Date:** 2026-11-01  
**Project:** SWA AI — Autonomous Enterprise Cybersecurity Operations Platform  
**Repository:** https://github.com/545e/SWA  
**Local Workspace:** `C:\Users\krish\SWA`  
**Latest Commit at Baseline:** `d3e9bb0` (`feat(gen2): complete Generation 2 UI redesign, SOC dashboard, security hardening, and engineering reports`)  
**Status:** Clean working tree, 0 uncommitted changes.

---

## 1. Executive Baseline Summary

SWA AI has undergone continuous enterprise modernization through Generation 1 and Generation 2. This report documents the exact technical baseline of the repository prior to beginning Generation 3 engineering transformations.

| Metric | Baseline Value |
|---|---|
| Git Branch | `main` |
| Working Tree Status | Clean (`d3e9bb0`) |
| Python Runtime | Python 3.12.10 (win32) |
| Web Application Framework | FastAPI + Uvicorn |
| Local Application Host | `http://127.0.0.1:8000` / `http://0.0.0.0:8000` |
| Active Database | SQLite 3 (`swa_data.db`, WAL mode enabled) |
| Total Database Tables | 18 tables with 15 active B-tree performance indexes |
| Test Suite Coverage | 100 test items across 16 test files (100% pass rate) |
| Autonomous Specialist Agents | 17 registered agents |
| Integrated Security Tools | 12 tools cataloged with native execution suite |

---

## 2. Inventory of Subsystems & Entry Points

### 2.1 Backend Entry Points
- `run.py`: Primary application launcher; validates environment, initializes database, runs optional tool checks, and launches FastAPI server via Uvicorn.
- `web/server.py`: Core FastAPI application exposing REST APIs, static asset mounts, security header middleware, token-bucket rate limiter, and authentication status.
- `web/enterprise_api.py`: Enterprise endpoints for multi-agent dispatch, approval gates, EASM drift evaluation, and remediation lifecycles.
- `swa_cli.py`: Standalone CLI interface for terminal-driven scans, subdomain discovery, and export pipelines.

### 2.2 Frontend Entry Points
- `web/static/index.html`: Single-page application template containing the SOC sidebar, topbar, dashboard, and tab panes.
- `web/static/app.js`: Client-side logic for API requests, view dispatching (`navToView`), charts, modals, and dynamic data tables.
- `web/static/styles.css`: CSS styling tokens, dark navy/charcoal SOC palette, grid layouts, and responsive components.

### 2.3 Core Engines
- `core/scanner_integrations.py`: Native scanner engine (crawlers, passive recon, header auditing, port probe) and third-party tool adapters.
- `core/scope_policy.py`: Scope policy enforcement engine with SSRF guards against loopback, RFC1918 private subnets, and cloud metadata (`169.254.169.254`).
- `core/app_security.py`: Token-bucket rate limiter, credential redaction, safe file path resolution, and prompt injection delimiter wrapping.
- `core/database.py`: Thread-safe SQLite connection manager with WAL mode, foreign key enforcement, query helpers, and zero-downtime backup.
- `agents/agent_workforce.py`: Multi-agent orchestration engine with 17 specialist security agents.
- `core/ai_evaluation.py`: Machine learning and LLM evaluation harness.
- `core/data_management.py`: Dataset ingestion, validation, credential leakage scanning, and train/val/test splitting.

---

## 3. Test Suite Baseline Execution

All 100 test items in `tests/` were executed against the baseline codebase:
```text
tests/test_ai_training_and_evaluation.py ............. [5%]
tests/test_api_and_dashboard.py ...................... [13%]
tests/test_cyber_deploy.py ........................... [17%]
tests/test_cyber_export.py ........................... [23%]
tests/test_cyber_test.py ............................. [27%]
tests/test_data_management.py ........................ [32%]
tests/test_e2e_local_scan.py ......................... [34%]
tests/test_enterprise_platform.py .................... [43%]
tests/test_generation2_security_and_integrity.py ..... [54%]
tests/test_llm_security_testing.py ................... [57%]
tests/test_owasp_plugins.py .......................... [60%]
tests/test_rea_engine.py ............................. [67%]
tests/test_scanner_integrations.py ................... [72%]
tests/test_scope_policy.py ........................... [83%]
tests/test_subdomain_engine.py ....................... [95%]
tests/test_tool_registry.py .......................... [100%]
====================== 100 passed in 74.83s ======================
```

---

## 4. Root-Cause Analysis of Known UI & Navigation Problems

An exhaustive code audit of `web/static/index.html` and `web/static/app.js` revealed the exact technical root causes for the reported UI behavior:

### Problem 1: Dashboard content remains visible when switching to other views (e.g. Vulnerabilities)
- **Root Cause:** In `index.html`, the executive dashboard components (welcome hero, scan launch panel, 4 KPI cards, security posture formula card, recent assessments table, tool health grid, and activity stream) were placed as direct, unencapsulated child elements inside `<main class="swa-viewport" id="mainViewport">`.
- While other tabs (e.g. `tabFindings`, `tabSubdomains`) were wrapped inside `<div id="tabFindings" class="tab-content">`, the dashboard had no container wrapper and was never hidden when `switchTab()` or `navToView()` ran. Thus, selecting any tab merely stacked the tab content underneath the dashboard.

### Problem 2: Selecting Vulnerabilities displays Dashboard content
- **Root Cause:** In `app.js`, `navToView(view)` contained a `viewMap` mapping old view keys (`'pentest'`, `'recon'`, etc.) to `targetViewId`. When a user clicked "Vulnerabilities" or navigated to `vulnerabilities`, `viewMap['vulnerabilities']` evaluated to `undefined`, triggering the fallback: `const targetViewId = viewMap[view] || 'viewDashboard'`.
- Additionally, `document.querySelectorAll('.swa-view')` found 0 elements because views were assigned `class="tab-content"`, causing the view switching loop to be a no-op.

### Problem 3: Navigation state and page content disagree
- **Root Cause:** Sidebar links called `navToView('pentest')` while breadcrumbs and internal routes expected `vulnerabilities` or `assessments`. There was no centralized routing table or unified view registry.

### Problem 4: Direct URL access, refresh, and browser history (Back/Forward) fail
- **Root Cause:** No HTML5 History API or hash router (`window.location.hash`) was implemented. All navigation occurred solely through inline `onclick` handlers without updating the browser URL. Refreshing the browser always defaulted back to the root state.

---

## 5. Generation 3 Remediation Strategy

1. **Phase 1 Architecture:** Formally define the 24 required views, unified application shell, and API/data contracts.
2. **Phase 2 UI Replacement:**
   - Enclose the Executive Dashboard inside `<div id="viewDashboard" class="swa-view active">`.
   - Wrap every required page in its own dedicated `<div id="view..." class="swa-view">` container.
   - Implement a hash router (`window.addEventListener('hashchange', ...)` and `window.addEventListener('popstate', ...)`) that synchronizes URL hashes (e.g. `#/vulnerabilities`, `#/assessments`, `#/dashboard`), browser history, active sidebar states, breadcrumbs, and view containers.
   - Ensure `#/vulnerabilities` exclusively displays vulnerability content and hides dashboard content.
3. **Phase 3 Interaction Repair:** Ensure all 24 views have functional buttons, live data loaders, empty states, and input validation.
4. **Phase 4 - 23:** Execute data engineering, database verification, assessment engine, AI evaluation, application security, deployment profiles (low-resource 2 CPU / 3 GB RAM), automated testing, and comprehensive documentation handover.
