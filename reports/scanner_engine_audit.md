# SWA AI — Scanner Engine Architecture Audit
**Document ID:** SEC-SCAN-2026-009  
**Generated:** 2026-11-01T06:13:28.585946+00:00  

---

## 1. Scanner Engine Mechanics
The core scanning engine (`core/scanner.py`) executes through an asynchronous event-driven loop:
1. **Target Ingestion & Validation:** Ensures target adheres to `ScopePolicy`.
2. **Phase 1: Surface Discovery:** Fast concurrent TCP SYN/Connect socket probing across top 1000 ports.
3. **Phase 2: Service Fingerprinting:** Banner grabbing and TLS handshake interrogation.
4. **Phase 3: Active Vulnerability Probing:** Thread-pooled request dispatching with rate-limiting and jitter.
5. **Phase 4: Heuristic Finding Deduplication:** Normalizes findings against URI fingerprints to eliminate duplicate alerts.
6. **Phase 5: Persistent Storage:** Writes to `scans` and `findings` tables in `swa_data.db` under ACID transactions.
