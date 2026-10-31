# SWA AI — Dependency Inventory & Security Audit
**Report ID:** DEP-INV-001  
**Date:** 2026-10-31 07:49:28 UTC  

## 1. Runtime Python Dependencies (Python 3.12.10)
| Package | Installed Version | Purpose | Security Status |
| :--- | :--- | :--- | :--- |
| `fastapi` | 0.162.0 | Asynchronous REST API framework | PASS — Up to date |
| `pydantic` | 2.14.2 | Data validation and type safety | PASS — Verified clean |
| `pydantic-core` | 2.50.2 (cp312) | Rust-backed parsing engine | PASS — Fixed wheel mismatch |
| `uvicorn` | 0.54.0 | ASGI web server | PASS — Up to date |
| `websockets` | 17.3 | WebSocket transport protocol | PASS — Up to date |
| `httpx` | 0.28.1 | Async HTTP client | PASS — Clean |
| `requests` | 2.34.2 | Synchronous HTTP client | PASS — Clean |
| `beautifulsoup4`| 4.15.0 | HTML parsing and inspection | PASS — Clean |
| `cryptography` | 50.0.2 | TLS and cryptographic operations | PASS — Clean |
| `dnspython` | 2.9.0 | Asynchronous DNS resolution | PASS — Clean |
| `pytest` | 9.2.0 | Automated testing framework | PASS — Clean |
| `pytest-cov` | 7.1.0 | Code coverage reporter | PASS — Clean |

## 2. Dependency Audit Notes
- Replaced mismatched `pydantic_core` Python 3.15 wheel with native Python 3.12 wheel.
- Verified zero CVE vulnerabilities in production dependencies via `ScannerIntegrations.scan_dependency_manifest`.
