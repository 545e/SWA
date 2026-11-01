# SWA AI — Root Cause Analysis: The 85-versus-17 Agent Visibility Issue

**Document ID:** RCA-20261101-AGENT85  
**Generated:** 2026-11-01T07:23:49.512323+00:00  
**Classification:** Engineering Defect Analysis & Architectural Remediation  
**Status:** RESOLVED & VERIFIED  

---

## 1. Issue Description

Previous builds of SWA AI reported approximately 85 agent and engine capabilities in documentation, but the running web application displayed only 17 agents in the UI. Operators were unable to see, search, or trigger tasks on the remaining 68 specialized agents.

---

## 2. Execution Path Trace

We traced the complete execution path from source implementation to frontend rendering:

```
[85 Agent Implementations in Codebase]
                  │
                  ▼
[Discovery & Import Layer] ──❌ FAILED (Only workforce specialists imported)
                  │
                  ▼
[Registration / Directory] ──❌ FAILED (AgentWorkforceDirectory hardcoded 17 enum roles)
                  │
                  ▼
[Database Persistence] ──────❌ FAILED (No agents_inventory table existed)
                  │
                  ▼
[Backend REST API] ──────────❌ FAILED (/api/agents returned only agent_workforce.list_manifests())
                  │
                  ▼
[Frontend UI Controller] ────❌ FAILED (loadAgentsGrid() lacked pagination & tier filtering)
                  │
                  ▼
[DOM Rendering] ─────────────❌ FAILED (Rendered only 17 cards)
```

---

## 3. Four Identified Root Causes

### Root Cause 1: Registry Class Hardcoding in `agents/agent_workforce.py`
In `agents/agent_workforce.py`, `AgentWorkforceDirectory.__init__()` initialized `self._agents` strictly with the 17 `AgentRole` enum values (`SupervisorAgent` through `PlatformHealthAgent`). Standalone domain agents, OWASP security plugins, core autonomous engines, and tool integration adapters were omitted.

### Root Cause 2: Siloed Module Architecture
The other 68 agents were implemented as standalone modules across `agents/` (e.g. `AmassSubdomainEngine`, `AttackSurfaceAgent`, `VulnHunterAgent`), `plugins/owasp_plugins.py` (10 OWASP plugins), `core/` (32 autonomous engines like `GhostJsAnalyzer`, `ForensicsEngine`, `SQLiEngine`, `AntivirusEdrManager`), and `core/scanner_integrations.py` (17 tool adapters), but lacked a unified registration interface.

### Root Cause 3: API Schema and Route Restriction
In `web/enterprise_api.py`, `GET /api/agents` executed `return [m.model_dump() for m in agent_workforce.list_manifests()]`. Since `agent_workforce` only tracked workforce roles, the API output was capped at 17 items.

### Root Cause 4: Frontend UI Missing Filtering & Pagination
The frontend in `web/static/app.js` and `web/static/index.html` assumed a static 17-item workforce grid without search inputs, category filters, or pagination controls.

---

## 4. Engineering Fix & Verification

1. **Created `core/agent_registry.py`:** Implemented a central `AgentRegistry` singleton that inventories all 85 agents across 5 operational tiers.
2. **Created SQLite `agents_inventory` Table:** Added persistence in `core/database.py` with indexes on `tier` and `category`.
3. **Updated `web/enterprise_api.py`:** Enhanced `GET /api/agents` with tier filtering, search, pagination, and summary routes (`GET /api/agents/summary`).
4. **Upgraded Web UI:** Modernized `web/static/index.html` and `web/static/app.js` with KPI metrics, 6 category filter pills, live search, and pagination.
5. **Reconciled All 5 Layers:** Verified that source count (85), registry count (85), database count (85), API count (85), and UI count (85) match exactly.
