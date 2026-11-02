# Initial Failure Register & Defect Log — SWA AI

| ID | Module | Reported Symptom | Severity | Status |
|:---|:---|:---|:---:|:---:|
| **DEF-01** | Frontend Connection | Persistent "Reconnecting..." badge in SOC dashboard header | **CRITICAL** | **RESOLVED** |
| **DEF-02** | Subdomain Engine | Reporting 0 subdomains or missing discovered candidates | **CRITICAL** | **RESOLVED** |
| **DEF-03** | Server WebSocket | Leaking tasks on client disconnect; hanging on `await q.get()` | **HIGH** | **RESOLVED** |
| **DEF-04** | Python Environment | Global Python resolver picking up Python 3.15 without installed dependencies | **HIGH** | **RESOLVED** |
| **DEF-05** | Finding Schema | Missing `confidence`, `detection_method`, `affected_asset`, and `reproduction_steps` in database | **MEDIUM** | **RESOLVED** |
| **DEF-06** | Posture Formula | Inconsistency between backend report scoring and frontend deduction points | **MEDIUM** | **RESOLVED** |
| **DEF-07** | Scope Enforcement | CI failure regression on IPv4-mapped IPv6 loopback / IMDS endpoints | **HIGH** | **RESOLVED** |
| **DEF-08** | Scan Cancellation | `QueueManager.cancel_scan()` throwing RuntimeError when running outside an active event loop | **LOW** | **RESOLVED** |
