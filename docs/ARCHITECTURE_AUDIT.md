# SWA AI — Architecture Audit & System Specification

**Audited Version:** 2.1.0  
**Architectural Style:** Autonomous Multi-Agent Asynchronous Event-Driven Pipeline  
**Target Environment:** 2 vCPU / 3 GB RAM Deployment Server  

---

## 1. System Architecture Diagram

```text
+-----------------------------------------------------------------------------------+
|                                  USER INTERFACES                                  |
|     +-------------------------+                     +-----------------------+     |
|     |  Web SOC Dashboard      |                     |  Unified CLI (swa)    |     |
|     |  (HTML5 / ES6 / CSS3)   |                     |  (Argparse / Subcmd)  |     |
|     +------------+------------+                     +-----------+-----------+     |
+------------------|----------------------------------------------|-----------------+
                   | HTTP / JSON / WebSocket                      | Direct Dispatch
                   v                                              v
+-----------------------------------------------------------------------------------+
|                                FASTAPI ASGI ENGINE                                |
|  - CORS & Security Headers Middleware                                             |
|  - Rate Limiting & Scope Policy Guard                                             |
|  - Asynchronous REST Routes (/api/scans, /api/tools/*, /api/ai/*)                 |
|  - WebSocket Dispatcher (/ws)                                                     |
+-----------------------------------------------------------------------------------+
                   |                                              |
                   v                                              v
+--------------------------------------+      +-------------------------------------+
|        AUTONOMOUS ORCHESTRATOR       |      |          QUEUE MANAGER              |
|  - SWAOrchestrator                   |      |  - Async Task Queue                 |
|  - Multi-Agent Pipeline Coordinator  |<---->|  - Event Fan-Out (WebSockets)       |
|  - Scope Policy SSRF Enforcement     |      |  - Cancellation & Progress Tracker  |
+--------------------------------------+      +-------------------------------------+
                   |
         +---------+--------------------+---------------------+
         |                              |                     |
         v                              v                     v
+--------------------+        +--------------------+  +--------------------+
| ReconAgent         |        | AttackSurfaceAgent |  | VulnHunterAgent    |
| - Amass OSINT      |        | - HTML Crawling    |  | - OWASP Top 10     |
| - Async DNS Resolv |------->| - Route Mapping    |->| - ExploitValidator |
| - Wildcard Filter  |        | - JS Endpoint Extr |  | - cURL PoC Builder |
+--------------------+        +--------------------+  +--------------------+
                                        |                     |
                                        v                     v
                              +--------------------+  +--------------------+
                              | FuzzerAgent        |  | BlueTeamDefense    |
                              | - Path Probing     |  | - ModSec / AWS WAF |
                              | - SPA Anomaly Det  |  | - Snort / Sigma    |
                              +--------------------+  +--------------------+
                                        |                     |
                                        +----------+----------+
                                                   |
                                                   v
+-----------------------------------------------------------------------------------+
|                                PERSISTENCE LAYER                                  |
|   Thread-Safe SQLite 3 (swa_data.db)                                              |
|   - Tables: scans, findings, logs, assets, ai_jobs, evaluations, redteam_results  |
|   - Bounded Context Manager with Strict Cleanup (Zero FD Leaks)                   |
|   - Busy Timeout: 30.0s for High-Concurrency Windows/Linux Support                |
+-----------------------------------------------------------------------------------+
```

---

## 2. Core Subsystems

### 2.1 Autonomous Multi-Agent Pipeline
1. **Reconnaissance (`ReconAgent` & `AmassSubdomainEngine`)**:
   - Collects subdomains across 10+ passive OSINT feeds.
   - Detects wildcard DNS patterns using pseudo-random hostname baselines.
   - Asynchronously resolves DNS A, AAAA, MX, TXT, NS, and CNAME records.
   - Identifies subdomain takeover risks against known cloud CNAME signatures.
2. **Attack Surface Discovery (`AttackSurfaceAgent`)**:
   - Extracts hyperlinks, forms, scripts, and endpoints.
   - Parses inline and external JavaScript bundles using regex pattern matchers.
3. **Anomaly-Filtered Fuzzing (`FuzzerAgent`)**:
   - Compares HTTP responses against dual 404 baselines to avoid Single Page Application (SPA) wildcard false positives.
4. **Vulnerability Hunting & PoC Validation (`VulnHunterAgent` & `ExploitValidatorAgent`)**:
   - Dispatches modular security plugins for SQL Injection, Reflected XSS, Path Traversal, SSRF, CORS Misconfigurations, and Open Redirects.
   - Executes non-destructive proof-of-concept validations and formats verified reproducibility artifacts into standardized cURL commands.
5. **Defensive Blue Team Translation (`BlueTeamDefenseEngine`)**:
   - Automatically translates confirmed vulnerability findings into production ModSecurity rules, AWS WAF rules, Cloudflare WAF expressions, Snort/Suricata rules, and Sigma SIEM detection rules.

### 2.2 Security Architecture & Scope Policy
- **SSRF Defense:** Strict enforcement in `core/scope_policy.py`. Automatically rejects dangerous protocol schemes (`file://`, `gopher://`, `dict://`).
- **Cloud Metadata Protection:** Outright blocks requests targeting IMDS IPv4 (`169.254.169.254`), AWS ECS (`169.254.170.2`), and IPv6 (`fd00:ec2::254`).
- **Private & Loopback Filtering:** Restricts access to RFC1918 private subnets and localhost unless explicit `--lab-mode` / `Authorized Lab Assessment` profile is toggled.

### 2.3 Database Engine & Concurrency Model
- Storage: Thread-safe SQLite 3 utilizing `WAL` mode and dynamic connection lifecycle management.
- Context-managed transactions eliminate unclosed connection warnings and prevent descriptor exhaustion.
- Automatic schema migration checks on startup.
