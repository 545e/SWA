# SWA AI — API Security Assessment Report
**Document ID:** SEC-API-2026-012  
**Generated:** 2026-11-01T06:13:28.585946+00:00  

---

## 1. OWASP API Top 10 Audit Results

| Vulnerability Type | Description | SWA AI Safeguard | Audit Status |
|:---|:---|:---|:---|
| **API1: BOLA** | Broken Object Level Authorization | UUID-based IDs with tenant-isolation checks in `core/database.py` | PASS |
| **API2: Broken Authentication** | Flawed token handling | HMAC-SHA256 session tokens with automatic TTL expiration | PASS |
| **API3: BOPL** | Broken Object Property Level Auth | Pydantic strict schemas filtering unauthorized fields | PASS |
| **API4: Unrestricted Resource Cons.** | Rate-limit exhaustion | In-memory token bucket rate limiters on scanning endpoints | PASS |
| **API5: BFLA** | Broken Function Level Auth | Dual-control approval gates on intrusive actions | PASS |
| **API6: SSRF** | Server-Side Request Forgery | `core/scope_policy.py` blocks loopback and 169.254.169.254 | PASS |
| **API7: Security Misconfiguration** | Verbose error stack traces | Standardized JSON error envelopes suppressing internal paths | PASS |
| **API8: Lack of Protection from Automated Threats** | Bot attacks | Target throttling and CAPTCHA hooks | PASS |
| **API9: Improper Inventory Mgmt** | Shadow APIs | Automated OpenAPI schema generation at `/openapi.json` | PASS |
| **API10: Unsafe Consumption of APIs** | Flawed third-party integrations | Timeout-bound HTTP client sessions with strict parsing | PASS |
