# SWA AI — Production Security Configuration & Hardening

## Overview
This document specifies the production security controls, scope policy rules, SSRF defenses, and authentication mechanisms built into the SWA AI platform.

---

## 1. Scope Enforcement & Target Authorization

SWA AI is strictly scoped to authorized penetration testing and vulnerability auditing. The application enforces a dual-mode scope policy in [`core/scope_policy.py`](../core/scope_policy.py):

### Strict Production Mode (`SWA_ALLOW_LAB_MODE=0`, Default)
- **Localhost & Loopback Blocked**: Scanning `127.0.0.1`, `localhost`, `0.0.0.0`, or loopback ranges is refused with HTTP 403 / `ScopeViolationError`.
- **Private RFC 1918 Ranges Blocked**: `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16` are rejected.
- **Cloud Metadata (IMDS) Blocked**: AWS, Azure, GCP, and DigitalOcean metadata endpoints (`169.254.169.254`, `metadata.google.internal`) are blocked unconditionally to eliminate SSRF escalation.
- **Allowed Targets**: Scans are restricted exclusively to explicit targets configured in `config/targets.json` or pre-authorized domains.

### Isolated Lab Mode (`SWA_ALLOW_LAB_MODE=1`)
- Permitted strictly in isolated staging, local development, or CTF environments.
- Permits scanning pre-approved local targets (`127.0.0.1:8000`, `127.0.0.1:8001`, PortSwigger labs).
- **IMDS and link-local ranges remain blocked even in Lab Mode.**

---

## 2. HTTP Security Headers
All web responses pass through security middleware enforcing defense-in-depth headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: geolocation=(), microphone=(), camera=()`
- `Content-Security-Policy: default-src 'self' ...; frame-ancestors 'self';`

---

## 3. Subprocess & Command Injection Defense
- All integrated cybersecurity tools (Nmap, Nuclei, OWASP ZAP, SQLmap, Nikto, TShark, Semgrep, Bandit, Trivy, Gitleaks, REA) are invoked via `asyncio.create_subprocess_exec` using explicit argument arrays (`List[str]`).
- Shell interpreters (`shell=True`) are strictly prohibited across the entire codebase.

---

## 4. Reverse Engineering (REA) Artifact Controls
- Explicit operator confirmation (`authorized=True`) is required for every inspection.
- Path traversal sequences, null bytes, and sensitive system files (`SAM`, `shadow`, `.env`, `.ssh/id_rsa`, `.aws/credentials`) are blocked before analysis.
