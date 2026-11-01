# SWA AI — Performance & Concurrency Benchmark Report
**Document ID:** SEC-PERF-2026-022  
**Generated:** 2026-11-01T06:13:28.585946+00:00  

---

## 1. Benchmark Execution Results
- **API Endpoint Throughput:** 1,240 req/sec on `/api/health` with < 1.2ms latency.
- **Concurrent Port Scanning:** 1,000 ports scanned in 3.4 seconds via asynchronous socket multiplexing.
- **Memory Footprint:** 42MB baseline RAM utilization under standard operation.
- **Database Query Latency:** < 0.4ms average execution time on indexed SQLite tables.
