# SWA AI — Attack Surface Assessment Report
**Document ID:** SEC-SURF-2026-010  
**Generated:** 2026-11-01T06:13:28.585946+00:00  

---

## 1. Assessment Parameters
- **Target Environment:** SWA AI Enterprise Local Host
- **Evaluation Port:** `8000` (FastAPI / Uvicorn)
- **Network Interface:** Loopback (`127.0.0.1`)

## 2. Attack Surface Findings
1. **Exposed Endpoints:**
   - Public: `/`, `/api/health`, `/api/health/diagnostics`, `/api/scans`, `/api/tools/run`, `/api/cyber/*`.
   - Administrative / Gated: `/api/deploy/approve`, `/api/deploy/rollback` (protected by role authorization).
2. **Transport Security:**
   - Loopback HTTP without TLS (acceptable for local development; TLS termination mandated for production reverse proxy).
3. **CORS & Header Exposure:**
   - Strict CORS policy restricting cross-origin requests to configured origins.
   - Header `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY` applied to API responses.
