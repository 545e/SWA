# SWA AI — Cybersecurity & Defensive Security Audit

**Assessment Type:** Defensive Security Posture & Application Security Audit  
**Standards Evaluated:** OWASP Top 10, OWASP API Security Top 10, SSRF Guidelines  
**Audited Target:** SWA AI Autonomous Platform  
**Overall Security Rating:** HIGH DEFENSIVE RESILIENCE  

---

## 1. Vulnerability Findings & Risk Summary

| Category | Finding | Severity | Status | Remediation / Verification |
| :--- | :--- | :---: | :---: | :--- |
| **SSRF** | Potential internal network scanning | Critical | Resolved | Enforced in `core/scope_policy.py`; blocks RFC1918 & IMDS |
| **Command Injection** | External scanner wrapper execution | High | Resolved | Subprocess calls use argument lists, avoiding `shell=True` |
| **Path Traversal** | REA / Artifact local file analysis | High | Resolved | Strict path validation and canonicalization check |
| **Resource Leak** | SQLite unclosed file descriptors | Medium | Resolved | Context-managed connections with auto-close |
| **Container Security** | Default root container execution | Medium | Resolved | Hardened Dockerfile with dedicated unprivileged user `swa` |
| **CORS Policy** | Permissive wildcard origins in dev | Low | Addressed | Configurable via environment; strict security headers added |

---

## 2. In-Depth Scope & SSRF Enforcement Evaluation

The platform's SSRF and scope policy was subjected to 10 automated adversary test scenarios (`tests/test_scope_policy.py`):

1. **Cloud Metadata Protection:**
   - Probed `169.254.169.254`, `169.254.170.2`, and `fd00:ec2::254`.
   - **Result:** Blocked immediately with `is_allowed=False`.
2. **IPv4-Mapped IPv6 Bypasses:**
   - Probed `::ffff:169.254.169.254` and `::ffff:127.0.0.1`.
   - **Result:** Successfully normalized to canonical IPv4 and blocked.
3. **Dangerous Schemes:**
   - Probed `file:///etc/passwd`, `gopher://127.0.0.1:6379`, `dict://`.
   - **Result:** Rejected at schema validation level with HTTP 400.
4. **DNS Rebinding Guard:**
   - Targets resolve to IP prior to dispatch; IP is cross-checked against allowlist.
5. **Lab Mode Authorization:**
   - Localhost and 127.0.0.1 require operator to explicitly supply `--lab-mode` or choose `Authorized Lab Assessment` profile, preventing accidental internal network scanning.

---

## 3. HTTP Security Headers Audit

The FastAPI server enforces strict defense-in-depth security headers on all responses via middleware:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: geolocation=(), microphone=(), camera=()`
- `Content-Security-Policy: default-src 'self' 'unsafe-inline' ...`
