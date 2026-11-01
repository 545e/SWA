# SWA AI — Generation 3 API Reference

## 1. Authentication & Session Endpoints

### `GET /api/auth/status`
Returns current session authentication status, active role, and identity.
- **Response `200 OK`:**
  ```json
  {
    "authenticated": true,
    "role": "auditor",
    "identity": "auditor@swa.internal",
    "auth_enabled": false
  }
  ```

### `POST /api/auth/login`
Authenticates a user and generates a cryptographic session token.
- **Request Body:** `{"username": "admin"}`
- **Response `200 OK`:**
  ```json
  {
    "status": "authenticated",
    "token": "swa_sess_...",
    "role": "auditor",
    "identity": "admin"
  }
  ```

---

## 2. Assessment & Scanning Endpoints

### `POST /api/scans`
Launches an authorized security assessment against a target.
- **Request Body:**
  ```json
  {
    "target_url": "https://example.com",
    "profile": "standard",
    "lab_mode": false,
    "max_depth": 2,
    "concurrency": 5
  }
  ```
- **Responses:**
  - `200 OK`: `{"id": "scan_abc123", "status": "queued", "target_url": "https://example.com"}`
  - `400 Bad Request`: Invalid URL scheme or format.
  - `403 Forbidden`: Scope refusal (e.g., SSRF target without lab mode authorization).

### `GET /api/scans`
Lists all recent assessments with pagination.

### `GET /api/scans/{scan_id}`
Returns details, metrics, and progress for a specific assessment.

### `GET /api/scans/{scan_id}/findings`
Returns all normalized vulnerability findings discovered by the scan.

---

## 3. Asset & Attack Surface Endpoints

### `GET /api/assets`
Lists monitored enterprise assets (domains, subdomains, IPs, ports).

### `POST /api/tools/subdomains`
Runs standalone passive/active subdomain enumeration.
- **Request Body:** `{"domain": "example.com", "passive_only": true}`
- **Response `200 OK`:** Returns structured counts (`discovered_count`, `live_count`, `takeover_count`) and subdomain array.

---

## 4. Multi-Agent & Intelligence Endpoints

### `GET /api/agents`
Returns status, capabilities, and system health of all 17 specialist agents.

### `POST /api/enterprise/agents/dispatch`
Dispatches a specialist agent to perform an autonomous task.
- **Request Body:** `{"agent_id": "recon_analyst", "scan_id": "scan_123", "parameters": {}}`

### `GET /api/enterprise/approval-gates`
Lists active and pending human-in-the-loop approval gates.

### `POST /api/enterprise/approval-gates/{gate_id}/decide`
Approves or rejects a high-impact operation.

### `GET /api/enterprise/drift`
Evaluates attack surface drift and new asset/service exposures.

---

## 5. Remediation & Reporting Endpoints

### `GET /api/enterprise/remediation/tickets`
Lists vulnerability remediation tickets, assignees, and SLA deadlines.

### `POST /api/enterprise/remediation/{ticket_id}/retest`
Triggers an automated verification scan to validate vulnerability remediation.

### `GET /api/reports` / `POST /api/reports/generate`
Generates defensible audit reports in JSON, CSV, HTML, and PDF formats.

### `GET /api/health/diagnostics`
Comprehensive platform diagnostics covering database, agents, tools, graph, and approval gates.
