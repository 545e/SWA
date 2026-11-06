# SWA AI / SNMK — API Connection Testing Architecture & Batch Test Suite

## Overview
Connection testing ensures that every configured credential in the SWA AI / SNMK cryptographic vault is live, authenticated, and capable of network communication with the remote service provider.

Testing operates in three distinct modes:
1. **Ad-Hoc Pre-flight Test** (`POST /api/integrations/test`): Verifies uncommitted credentials in real-time inside the "Add API Key" modal before storing them to disk.
2. **Individual Connection Test** (`POST /api/integrations/{id}/test`): Re-tests an already saved integration using decrypted in-memory credentials and updates its SQLite status.
3. **Batch Test All Connections** (`POST /api/integrations/test-all`): Concurrently runs connection tests across all active integrations using bounded concurrency (`asyncio.Semaphore(5)`).

---

## Connection Testing Workflow

```
[ Operator clicks "Test All Connections" ]
                │
                ▼
[ POST /api/integrations/test-all ]
                │
   ┌────────────┴────────────┐
   │ asyncio.Semaphore(5)    │
   └────────────┬────────────┘
                ▼
   [ Parallel Asynchronous Workers ]
   ├── Worker 1: Anthropic Adapter Handshake
   ├── Worker 2: OpenAI Adapter Handshake
   ├── Worker 3: VirusTotal Adapter Handshake
   ├── Worker 4: Shodan Adapter Handshake
   └── Worker 5: AWS Adapter Handshake
                │
                ▼
   [ SQLite State Updates ]
   UPDATE integrations SET status = ?, last_tested_at = ?, last_error = ?
                │
                ▼
   [ JSON Batch Response ]
   { "total": 5, "passed": 5, "failed": 0, "results": [...] }
```

---

## Result Schema & Status Codes
Each connection test returns a structured payload:
```json
{
  "integration_id": "integ_abc123",
  "provider_id": "gemini",
  "display_name": "Production Gemini",
  "category": "ai_provider",
  "success": true,
  "status": "CONNECTED",
  "latency_ms": 142.5,
  "message": "Connection verified successfully.",
  "tested_at": "2026-11-06T18:30:00Z"
}
```

### Supported Status Codes:
- `CONNECTED`: Remote server confirmed valid credentials and granted API authorization.
- `AUTHENTICATION_FAILED`: Server replied with HTTP 401 or 403. Key is invalid or expired.
- `UNREACHABLE`: Connection timeout, DNS failure, or TCP connection refused.
- `CONFIGURED`: Saved in vault but not yet tested over the wire.
- `ERROR`: Unexpected parsing exception or unhandled socket error.
