# Architecture Analysis — SWA AI Autonomous Security Auditor

## 1. Request & Execution Flow
```
User (Browser / CLI)
       │
       ▼
[Target Input / Scope Normalizer] ───► [Scope Policy Engine]
                                              │ (SSRF / IMDS Guard)
                                              ▼
                                    [FastAPI REST / WS API]
                                              │
                                              ▼
                                    [SWA Orchestrator]
                                              │
               ┌──────────────────────────────┼──────────────────────────────┐
               ▼                              ▼                              ▼
      [ReconAgent / Amass]           [AttackSurfaceAgent]              [FuzzerAgent]
      - Passive CT Logs              - HTTP/HTTPS Crawler             - Baseline 404/200
      - dnspython Async DNS          - REST & GraphQL Routes          - Anomaly Probing
      - Wildcard Baseline Detection  - Endpoint Normalization         - Parameter Mining
               │                              │                              │
               └──────────────────────────────┼──────────────────────────────┘
                                              ▼
                                    [VulnHunterAgent]
                                    - OWASP Top 10 Plugins
                                    - CORS / CSP / Headers
                                    - Cleartext / Banner Leak
                                              │
                                              ▼
                                  [ExploitValidatorAgent]
                                  - Non-destructive PoC Validation
                                  - Verified vs Suspected Classification
                                              │
                                              ▼
                                    [QueueManager & DB]
                                    - SQLite WAL Persistence
                                    - Real-Time WS / SSE Event Bus
                                              │
                                              ▼
                                 [Live SOC Dashboard & Reports]
```

## 2. Event Bus & Real-Time Communication
- **Dual-Transport Event Bus**: The backend utilizes an asynchronous `QueueManager` with per-client queues.
- **WebSocket Protocol**: `/ws` handles bidirectional messaging:
  - Immediate `CONNECTED` greeting on handshake completion.
  - Heartbeat ping/pong (`{"type": "ping"}` ↔ `{"type": "pong"}`) prevents NAT and reverse proxy idle socket disconnects.
  - Concurrent `sender` and `receiver` coroutines ensure client disconnects are detected instantaneously via ASGI `receive_text()` without task leaks.
- **Server-Sent Events (SSE)**: `/api/events/sse` provides fallback streaming when WebSockets are blocked by strict enterprise proxies.
- **HTTP Fallback Polling**: Automatic polling every 4 seconds when both WebSocket and SSE are unavailable.

## 3. Storage & Persistence
- **Engine**: SQLite 3 with Write-Ahead Logging (`PRAGMA journal_mode=WAL`).
- **Data Integrity**: Foreign key constraints enabled, parameterized SQL queries against SQL injection.
- **Auto-Migration**: Schema updates dynamically inspect existing tables via `PRAGMA table_info` and add new columns without dropping data.
- **Online Backup**: Automated database checkpointing and online backup support via `sqlite3.Connection.backup()`.
