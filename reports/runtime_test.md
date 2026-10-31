# SWA AI — Startup & Runtime Engineering Report

**Date:** 2026-10-30  
**Host:** Windows 10/11 Enterprise x64  
**Target Runtime:** FastAPI / Uvicorn ASGI Server  
**Result:** PASS  

---

## 1. Server Initialization

### Entry Points Tested
- `python run.py`: Operational
- `uvicorn web.server:app --host 127.0.0.1 --port 8000`: Operational
- `swa --help`: Operational

### Startup Execution Output
```text
INFO:     Started server process [3760]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

---

## 2. Real-Time Telemetry & WebSocket Connection
- **Endpoint:** `ws://127.0.0.1:8000/ws`
- **Client Handler:** `initWebSocket()` in `web/static/app.js`
- **Behavior:**
  - On WebSocket connection open: Status badge displays green pulse with `Engine Ready`.
  - On disconnection/server shutdown: Status badge displays red indicator with `Reconnecting...` and retries every 2,000ms.
  - Broadcasts scan progress, log events, and newly discovered vulnerabilities to all registered clients without event drops.

---

## 3. Database Concurrency & Lifecycle
- **Engine:** SQLite 3 with Thread-Safe connection context manager.
- **Connection Test:** Tested multiple concurrent API requests and long-running scans simultaneously.
- **Result:**
  - Zero database locking errors (`database is locked`).
  - Zero unclosed database connection warnings.
  - Automatic transaction rollback verified on simulated error injection.

---

## 4. Graceful Shutdown & Process Cleanup
- `SIGINT` (Ctrl+C) handling verified:
  - Uvicorn server initiates graceful shutdown.
  - Active background threads and async loops terminate cleanly.
  - Zero orphaned Python or socket listener processes remaining on port 8000.
