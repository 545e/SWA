# SWA AI — Agent REST API Contract & Schema Validation Report

**Generated:** 2026-11-01T07:23:49.512323+00:00  
**Base Route:** `GET /api/agents`  
**HTTP Status:** 200 OK  
**Total Items Returned:** 85  

---

## 1. Endpoint Verification Matrix

| Endpoint | Method | Query Parameters | Expected Status | Actual Result | Verification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `/api/agents` | GET | None | 200 OK | Returns all 85 agent manifests | **PASS** |
| `/api/agents/summary` | GET | None | 200 OK | Returns tier counts (17/9/10/32/17) | **PASS** |
| `/api/agents?tier=specialist_workforce` | GET | `tier` | 200 OK | Returns exactly 17 manifests | **PASS** |
| `/api/agents?tier=offensive_recon` | GET | `tier` | 200 OK | Returns exactly 9 manifests | **PASS** |
| `/api/agents?tier=owasp_plugins` | GET | `tier` | 200 OK | Returns exactly 10 manifests | **PASS** |
| `/api/agents?tier=core_engines` | GET | `tier` | 200 OK | Returns exactly 32 manifests | **PASS** |
| `/api/agents?tier=tool_adapters` | GET | `tier` | 200 OK | Returns exactly 17 manifests | **PASS** |
| `/api/agents?search=sqli` | GET | `search` | 200 OK | Returns 4 matching SQLi agents | **PASS** |
| `/api/agents?page=1&limit=10` | GET | `page`, `limit` | 200 OK | Returns 10 items, total 85, 9 pages | **PASS** |
| `/api/agents/supervisor` | GET | Path `agent_id` | 200 OK | Returns detailed manifest for supervisor | **PASS** |
| `/api/agents/invalid_id` | GET | Path `agent_id` | 404 Not Found | Returns standard error envelope | **PASS** |
| `/api/agents/supervisor/task` | POST | JSON payload | 200 OK | Dispatches task and records execution | **PASS** |

---

## 2. Schema Conformance

Every agent manifest returned by the API strictly adheres to the `ExtendedAgentManifest` Pydantic model:
- `id` (string, unique)
- `name` (string)
- `role` (string)
- `tier` (enum: `specialist_workforce`, `offensive_recon`, `owasp_plugins`, `core_engines`, `tool_adapters`)
- `category` (string)
- `description` (string)
- `version` (string)
- `module_path` (string)
- `class_name` (string)
- `status` (string)
- `capabilities` (array of strings)
- `responsibilities` (array of strings)
- `permission_boundary` (object with `allowed_tools`, `can_execute_active_probes`, `max_execution_time_sec`)
