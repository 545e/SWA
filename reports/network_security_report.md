# SWA AI — Network Security Architecture Report
**Document ID:** SEC-NET-2026-014  
**Generated:** 2026-11-01T06:13:28.585946+00:00  

---

## 1. Socket Architecture & Protocols
- Non-blocking asynchronous TCP socket connections implemented via `asyncio`.
- Socket timeout boundaries enforce a 2.5-second cap on connection attempts to prevent hanging threads.
- Half-open detection handles resets, connection refusals, and unreachable gateway packets gracefully without platform panic.
