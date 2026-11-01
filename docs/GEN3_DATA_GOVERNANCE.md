# SWA AI — Generation 3 Data Governance & Lifecycle

## 1. Data Lifecycle

SWA AI enforces a structured data lifecycle across all security intelligence and scan artifacts:

```text
Ingestion → Validation → Normalization → Storage (WAL) → Indexing → Analysis → Retention/Deletion
```

### 1.1 Ingestion & Provenance
Every imported asset, vulnerability, or raw scan log retains provenance metadata:
- Originating tool/engine (e.g. `native_crawler`, `amass_subdomain_engine`, `nmap_adapter`).
- Scan identifier (`scan_id`) and timestamp.
- Target scope context and collection method.

### 1.2 Normalization (Canonical Finding Model)
Disparate scanner outputs are normalized into a unified finding schema containing:
- `id`: Unique finding identifier (`f_...`).
- `scan_id`: Parent assessment identifier.
- `title` & `description`: Clear technical description.
- `severity`: Standardized classification (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- `cvss_score`: Defensible base score (0.0 - 10.0).
- `cwe_id` & `owasp_category`: Standard taxonomic mappings.
- `endpoint` & `method`: Affected URI and HTTP method.
- `evidence`: Proof of concept with sensitive credentials redacted.

### 1.3 Data Redaction & Protection
The redaction engine in `core/app_security.py` masks authorization tokens, bearer keys, passwords, private keys, and session cookies prior to persistence in logs or reports.

### 1.4 Retention & Deletion
- Scans and findings are retained according to organizational compliance policy (default: 365 days).
- Deletion operations cascade across findings, logs, and remediation tickets while recording an immutable event in `audit_log_entries`.
