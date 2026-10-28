# SWA AI — REST API Documentation

The SWA AI platform exposes an asynchronous REST API running on port 8000. All responses return standard JSON.

---

## 1. Assessment & Scan Management

### `POST /api/scans`
Launches an autonomous security assessment against an authorized target.

**Request Headers**:
`Content-Type: application/json`

**Request Body**:
```json
{
  "target_url": "http://127.0.0.1:8000",
  "profile": "quick",
  "max_depth": 2,
  "concurrency": 5,
  "lab_mode": true,
  "enable_sqlmap_lab": false,
  "auth_bearer_token": "optional_token",
  "custom_headers": {
    "X-Security-Scan": "SWA-AI"
  }
}
```

**Responses**:
- `200 OK`: Returns created `ScanJob` object with `PENDING` status.
- `400 Bad Request`: Invalid protocol scheme or target syntax.
- `403 Forbidden`: Target violates Scope Policy or SSRF guard (e.g. attempting to scan private network/IMDS without `lab_mode`).

---

### `GET /api/scans`
Returns a paginated list of all assessment jobs.

**Response**:
```json
[
  {
    "id": "scan_17bc0ca10e",
    "target_url": "http://127.0.0.1:8000",
    "profile": "quick",
    "status": "COMPLETED",
    "progress_percent": 100,
    "current_phase": "Completed",
    "findings_count": 6,
    "created_at": "2026-10-28T18:25:03.951566+00:00"
  }
]
```

---

### `GET /api/scans/{scan_id}`
Returns real-time scan job telemetry, progress percentage, current agent phase, and execution logs.

---

### `GET /api/scans/{scan_id}/findings`
Returns all verified vulnerability findings discovered during the assessment.

**Response**:
```json
[
  {
    "id": "find_9f21b7c124",
    "scan_id": "scan_17bc0ca10e",
    "title": "Insecure Cross-Origin Resource Sharing (CORS) Policy",
    "severity": "HIGH",
    "cwe_id": "CWE-942",
    "endpoint": "http://127.0.0.1:8000",
    "method": "GET",
    "description": "The endpoint mirrors arbitrary origins or specifies Access-Control-Allow-Origin: * alongside Access-Control-Allow-Credentials: true.",
    "poc_curl": "curl -i -H 'Origin: https://evil.com' 'http://127.0.0.1:8000'",
    "remediation_advice": "Maintain an explicit whitelist of trusted origins.",
    "verified": true
  }
]
```

---

### `GET /api/scans/{scan_id}/report?format={format}`
Exports the complete penetration testing report.

**Supported Formats**:
- `html`: Executive HTML assessment presentation.
- `sarif`: SARIF 2.1.0 output compatible with GitHub Advanced Security and DefectDojo.
- `json`: Normalized raw findings and reconnaissance metadata.
- `csv`: RFC 4180 spreadsheet.
- `markdown`: Penetration test summary report.

---

## 2. Tools & Environment Inventory

### `GET /api/tools/status`
Returns real-time binary presence, version, and capability status for all 11 security tools.

### `GET /api/tools/reference`
Returns the comprehensive searchable command encyclopedia with option breakdowns, safe lab examples, and troubleshooting guides.

### `POST /api/tools/{tool_id}/health-check`
Triggers a safe ping / version verification for a specific security tool and returns latency in milliseconds.

### `GET /api/scope/targets`
Returns configured approved target allowlists, default lab targets, and global lab mode authorization state.

---

## 3. Semi-Automatic Cyber Diagnostic Endpoints

- `POST /api/tools/dns`: Resolve DNS records (A, AAAA, MX, TXT, NS, CNAME) and SPF/DMARC email security.
- `POST /api/tools/headers`: Evaluate 8 HTTP security headers and server banner disclosure.
- `POST /api/tools/ssl`: Deep TLS/SSL inspection (issuer, cipher, SANs, days to expiration).
- `POST /api/tools/ports`: Async TCP port scanner and service banner grabber.
- `POST /api/tools/probe`: Single-vector test for SQLi, XSS, LFI, SSRF, or CORS with reproducible cURL PoC.
- `POST /api/tools/js-scan`: Scan target website and client-side JavaScript bundles for 150+ secret signatures.
- `POST /api/tools/scan-file`: Upload local JavaScript bundle or manifest for offline audit.
