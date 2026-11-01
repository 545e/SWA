# SWA AI — Tool Integration Report
**Document ID:** SEC-INT-2026-006  
**Generated:** 2026-11-01T06:13:28.585946+00:00  

---

## 1. Architecture of Unified Adapter Framework
All tools interface through a standardized abstraction layer:
- **Interface Base:** `core/scanner_integrations.py` -> `ToolAdapter`
- **Output Standardization:** All tool outputs normalize to `FindingRecord` schema with:
  - `id`: Unique UUID
  - `vuln_type`: Standard CWE / OWASP categorization
  - `severity`: Standardized CVSS v3.1 rating (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`)
  - `evidence`: Redacted request/response transcripts or file offsets
  - `remediation`: Actionable patch guidance

## 2. Scope Policy Enforcement
Prior to invoking any tool, `core/scope_policy.py` validates the target against:
- Configured allowlists.
- RFC-1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) unless explicitly whitelisted in local testing profile.
- Cloud metadata service (`169.254.169.254`) unconditionally blocked to prevent SSRF exploitation.
