# SWA AI — API Integration Matrix
**Document ID:** SEC-API-MATRIX-2026  
**Generated:** 2026-11-01T06:57:46.575012+00:00  

---

## 1. Complete API Route & Contract Inventory

| Route Path | HTTP Method | Auth Required | Request Schema | Response Schema | Purpose | Status |
|:---|:---|:---|:---|:---|:---|:---|
| `/` | GET | None | None | HTML | Master Enterprise SOC Dashboard | PASS |
| `/api/health` | GET | None | None | JSON | Lightweight liveness probe | PASS |
| `/api/health/diagnostics` | GET | None | None | JSON | Comprehensive health diagnostics | PASS |
| `/api/scans` | GET | Optional | `limit, status` | JSON | List past and active scans | PASS |
| `/api/scans` | POST | None | `target_url, profile` | JSON | Launch new autonomous scan | PASS |
| `/api/scans/{id}` | GET | None | `scan_id` | JSON | Retrieve scan details and telemetry | PASS |
| `/api/findings` | GET | None | `severity, category` | JSON | List discovered vulnerabilities | PASS |
| `/api/tools` | GET | None | None | JSON | List all registered security tools | PASS |
| `/api/tools/run` | POST | Authorized | `tool_id, target` | JSON | Execute specific security tool | PASS |
| `/api/cyber/audit/logs` | GET | None | `limit` | JSON | Live platform operational audit feed | PASS |
| `/api/cyber/export/generate`| POST | None | `export_type, format` | JSON | Generate multi-format export | PASS |
| `/api/cyber/export/download/{id}`| GET | None | `export_id` | FileStream | Secure export deliverable download | PASS |
| `/api/cyber/test/run` | POST | None | `profile, target_url` | JSON | Execute cyber test profile | PASS |
| `/api/cyber/deploy/initiate` | POST | None | `environment, method` | JSON | Initiate 11-stage deployment | PASS |
| `/api/cyber/deploy/{id}/approve` | POST | Admin | `approver` | JSON | Approve deployment held at gate | PASS |
| `/api/cyber/deploy/{id}/rollback` | POST | Admin | `operator` | JSON | Instant rollback to target release | PASS |
| `/api/cyber/deploy/{id}/acceptance-checklist` | GET | None | `deployment_id` | JSON | Section 52 acceptance checklist | PASS |
| `/api/cyber/antivirus/status` | GET | None | None | JSON | Live host AV telemetry & matrix | PASS |
| `/api/cyber/identity/audit-jwt` | POST | None | `token` | JSON | JWT cryptographic security audit | PASS |
| `/api/cyber/identity/audit-cookie`| POST | None | `cookie_header` | JSON | Session cookie security flags audit| PASS |
