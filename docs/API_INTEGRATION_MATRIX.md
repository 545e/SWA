# SWA AI — REST API Integration Matrix & Schema Specification
**Base URL:** `http://127.0.0.1:8000`  
**API Specification:** OpenAPI 3.0 (Interactive docs at `/docs`, raw schema at `/openapi.json`)  
**Security Model:** Session-governed, CORS restricted, strict input validation  

---

## 1. Assessment & Scan Lifecycle Endpoints

| Method | Endpoint | Description | Request Body | Response Schema |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/scans` | Create and launch assessment | `{"target_url": str, "profile": str}` | `ScanJob` object with `id`, `status: "RUNNING"` |
| `GET` | `/api/scans` | List all historical assessments | None (query: `limit`, `offset`) | `{"scans": [ScanJob, ...]}` |
| `GET` | `/api/scans/{id}` | Get real-time scan telemetry | None | Detailed `ScanJob` with progress, phase, findings |
| `POST` | `/api/scans/{id}/cancel` | Abort a running assessment | None | `{"status": "CANCELLED"}` |
| `DELETE`| `/api/scans/{id}` | Delete scan record & data | None | `{"status": "DELETED"}` |
| `GET` | `/api/scans/{id}/findings` | Discovered findings for scan | None | `[VulnerabilityFinding, ...]` |
| `GET` | `/api/scans/{id}/defenses` | Blue Team defense rules | None | WAF rules, IDS signatures, hardening conf |
| `GET` | `/api/scans/{id}/forensics`| Threat hunt queries & DFIR | None | Linux grep & PowerShell threat hunt profiles |
| `GET` | `/api/scans/{id}/report` | Export formatted audit report| Query: `format=html\|pdf\|json\|csv\|sarif` | Binary / Text download with Content-Disposition |

---

## 2. Intelligence & Multi-Agent Workforce Endpoints

| Method | Endpoint | Description | Request Body | Response Schema |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/agents` | List 17 specialist agents | None | Array of `AgentManifest` schemas |
| `POST` | `/api/agents/{role}/task`| Dispatch targeted task | `{"title": str, "inputs": dict}` | `AgentTask` with status, duration, output |
| `GET` | `/api/graph` | Knowledge graph topology | None | Node & edge list of assets, vulns, services |
| `GET` | `/api/remediation/tickets`| Remediation Kanban board | None | Array of `RemediationTicket` items |
| `POST` | `/api/remediation/tickets/{id}/retest` | Trigger autonomous retest | None | Retest result & evidence |
| `GET` | `/api/approvals` | Human approval gates | None | Array of `ApprovalRequest` items |
| `POST` | `/api/approvals/{id}/decide` | Approve / reject gate | `{"approved": bool, "reason": str}` | Decision confirmation |

---

## 3. Standalone Security Toolkit Endpoints

| Method | Endpoint | Description | Request Body | Response Schema |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/tools/dns` | DNS records & email spoofing| `{"domain": str}` | SPF, DMARC, MX, A, AAAA, TXT records |
| `POST` | `/api/tools/headers` | HTTP security headers audit | `{"target_url": str}` | Grade (`A+` to `F`), missing headers, advice |
| `POST` | `/api/tools/ssl` | TLS certificate inspection | `{"target": str}` | Expiry, cipher suite, SANs, CA trust |
| `POST` | `/api/tools/subdomains`| Subdomain harvesting (OSINT)| `{"domain": str, "recursive": bool}`| Discovered domains, IPs, HTTP status |
| `POST` | `/api/tools/probe` | Active vulnerability probe | `{"target_url": str, "vuln_type": str}`| Verification status, evidence, cURL PoC |
| `GET` | `/api/tools/status` | System binary health checks | None | Installed status of Nmap, Nuclei, ZAP, etc. |
| `POST` | `/api/tools/scan-file`| Direct JS secret scanner | `{"filename": str, "content": str}` | Entropy score, leaked tokens, API routes |
