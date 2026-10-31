# SWA AI — Route-by-Route Inspection Report
**Report ID:** ROUTE-INSPECT-001  
**Date:** 2026-10-31 14:03:30 UTC  
**Auditor:** Full-Stack Integration Engineer & API Architect  
**Status:** PASS / VERIFIED  

---

## 1. Web & API Route Inventory

| Route | Method | Component / Handler | Status | Expected Response | Verified Evidence |
| :--- | :---: | :--- | :---: | :--- | :--- |
| `/` | GET | `StaticFiles(web/static)` | **PASS** | HTML Enterprise Shell | Loads `index.html` with 200 OK |
| `/health` | GET | `health_check()` | **PASS** | JSON System Health | `{"status":"HEALTHY","app":"SWA AI"}` |
| `/v1/models` | GET | `list_v1_models()` | **PASS** | JSON Model List | OpenAI-compatible format with 4 models |
| `/v1/chat/completions` | POST | `create_chat_completion()` | **PASS** | JSON Chat Completion | Returns AI assistant security analysis |
| `/favicon.ico` | GET | `favicon()` | **PASS** | SVG Shield Icon | Returns `image/svg+xml` 200 OK |
| `/.well-known/security.txt`| GET | `security_txt()` | **PASS** | RFC 9116 Policy | Plain text security policy 200 OK |
| `/swagger.json` | GET | `swagger_json_alias()` | **PASS** | OpenAPI Schema | Returns FastAPI schema 200 OK |
| `/sitemap.xml` | GET | `sitemap_xml()` | **PASS** | XML Sitemap | Standard XML sitemap 200 OK |
| `/api/scans` | POST | `launch_scan()` | **PASS** | JSON `ScanJob` | Dispatches background worker |
| `/api/scans/{id}` | GET | `get_scan_status()` | **PASS** | JSON `ScanJob` | Returns findings and phase |
| `/api/settings` | GET | `get_settings()` | **PASS** | JSON Settings | Configuration schema 200 OK |
| `/api/tools/subdomains` | POST | `enumerate_subdomains()`| **PASS** | JSON Asset List | Passive/active DNS asset results |
| `/api/cyber/export/generate`| POST | `generate_cyber_export()`| **PASS** | JSON Export Record | Generates JSON/CSV/HTML/PDF |
| `/api/cyber/test/run` | POST | `run_cyber_test()` | **PASS** | JSON Test Run | Executes automated test profile |
| `/api/cyber/deploy/initiate`| POST | `initiate_deployment()`| **PASS** | JSON Deployment | 11-stage deployment lifecycle |
| `/ws` | WS | `websocket_endpoint()` | **PASS** | WebSocket Event Stream | Live scan events with 15s heartbeat |

---

## 2. In-App Navigation Routes (Dispatched via `navToView`)

All 19 in-app views were tested via Playwright browser automation:
1. `navToView('dashboard')` $\rightarrow$ Highlights sidebar, renders Executive KPI summary, Posture Score, and Scanner Launcher.
2. `navToView('recon')` $\rightarrow$ Switches to Subdomain Discovery console (`tabSubdomains`).
3. `navToView('pentest')` $\rightarrow$ Switches to Vulnerability Findings and PoCs console (`tabFindings`).
4. `navToView('fuzzer')` $\rightarrow$ Switches to Path & Param Fuzzer (`tabFuzzing`).
5. `navToView('waf')` $\rightarrow$ Switches to WAF Analysis and Rule Generator (`tabDefenses`).
6. `navToView('forensics')` $\rightarrow$ Switches to Threat Forensics and Footprint Analysis (`tabForensics`).
7. `navToView('tools')` $\rightarrow$ Switches to Cyber Toolkit Hub (`tabPlugins`).
8. `navToView('registry')` $\rightarrow$ Switches to Integrated Tool Catalog (`tabToolRegistry`).
9. `navToView('cyber_export')` $\rightarrow$ Switches to Cyber Export Management (`tabCyberExport`).
10. `navToView('cyber_test')` $\rightarrow$ Switches to Automated Testing Harness (`tabCyberTest`).
11. `navToView('cyber_deploy')` $\rightarrow$ Switches to Deployment Pipeline (`tabCyberDeploy`).
12. `navToView('cyber_audit')` $\rightarrow$ Switches to Audit Trail & Logs (`tabCyberAudit`).
13. `navToView('assets')` $\rightarrow$ Switches to Asset Inventory (`tabAssets`).
14. `navToView('compare')` $\rightarrow$ Switches to Scan Posture Diff Engine (`tabCompare`).
15. `navToView('aisec')` $\rightarrow$ Switches to AI Security & LLM Red Teaming (`tabAiDatasets`).
16. `navToView('reports')` $\rightarrow$ Switches to Reports Center (`tabReports`).
17. `navToView('siem')` $\rightarrow$ Switches to SIEM Live Telemetry (`tabLogs`).
18. `navToView('settings')` $\rightarrow$ Opens Platform Settings dialog and view (`settingsModal`).
19. `navToView('docs')` $\rightarrow$ Opens CLI & API Documentation (`commandRefModal`).
