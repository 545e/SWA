# SWA AI — Identity & Access Security Assessment Report
**Document ID:** SEC-ID-2026  
**Generated:** 2026-11-01T06:57:46.575012+00:00  

---

## 1. Identity Vulnerability Findings & Audits
- **JWT Alg None Flaw (CVE-2015-9235):** Prober detects unsigned token bypass; rejection enforced in production.
- **Session Cookie Flags:** Audits HttpOnly, Secure, and SameSite attributes on all session identifiers.
- **OAuth 2.0 PKCE & State:** Validates authorization requests for state CSRF mitigation and PKCE S256 code challenges.
