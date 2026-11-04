# SWA AI — API Architecture & Technical Design

## 1. Architectural Overview
SWA AI employs a high-performance, asynchronous, multi-tiered API architecture built on FastAPI, Starlette, and AnyIO. The design cleanly decouples user-facing endpoints, orchestration logic, autonomous agent scheduling, and low-level security tool executions.

```
       +-------------------------------------------------------+
       |               SWA AI Client / Web SOC UI              |
       +-------------------------------------------------------+
                                  |
                                  v
+---------------------------------------------------------------------+
|                      SWA Security Middleware Stack                  |
|  - RateLimiter (TokenBucket)     - CORS Strict Origin Isolation     |
|  - Request Signature / Session   - SSRF Target Validator           |
|  - Redaction Filter (Masking)    - Audit Logger                    |
+---------------------------------------------------------------------+
                                  |
       +--------------------------+--------------------------+
       |                                                     |
       v                                                     v
+-------------------------------+             +-------------------------------+
|    Legacy & Core Endpoints    |             |       Unified API v1 Engine   |
|   /api/scans, /api/findings   |             |           /api/v1/*           |
|   /api/tools, /api/plugins    |             |    (Full Subsytem Envelope)   |
+-------------------------------+             +-------------------------------+
                                  |
       +--------------------------+--------------------------+
       |                          |                          |
       v                          v                          v
+------------------+     +-------------------+     +------------------+
|  Agent Workforce |     | Security Scanners |     | Integrations Hub |
|  (85 Specialists)|     |   (15 Integrated) |     |  (23 Adapters)   |
+------------------+     +-------------------+     +------------------+
                                  |
                                  v
+---------------------------------------------------------------------+
|                     Encrypted Database & Storage Layer              |
|        SQLite WAL Mode • AES-256 Fernet Vault • Audit Journal       |
+---------------------------------------------------------------------+
```

## 2. Standardized Response Envelope
All `/api/v1/*` responses adhere to a predictable contract:

```json
{
  "success": true,
  "data": { ... },
  "meta": {
    "timestamp": "2026-11-04T12:00:00Z",
    "api_version": "v1",
    "total": 85,
    "offset": 0,
    "limit": 50
  },
  "message": "Operation completed successfully"
}
```

### Error Envelope
```json
{
  "detail": "Target Scope Refusal: Target '169.254.169.254' is blocked by SSRF protection policy.",
  "status_code": 403,
  "error_code": "SSRF_RESTRICTED_IP"
}
```

## 3. Asynchronous Concurrency Model
- **Non-blocking Dispatch**: Heavy scans and multi-tool executions run asynchronously in background tasks (`asyncio.create_task`).
- **Telemetry Buffering**: Log events and telemetry streams buffer in memory and flush periodically without degrading HTTP throughput.
- **Connection Pooling**: External third-party integrations utilize shared `httpx.AsyncClient` instances with bounded timeouts (8.0s) and keep-alive pools.
