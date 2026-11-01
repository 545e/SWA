# SWA AI — Integration Conflict & Resolution Log

**Document Version:** 2.2.0-Enterprise  
**Effective Date:** 2026-11-01  
**Lead Reviewer:** Chief Debugging Engineer & Integration Lead

---

## 1. Discovered Integration Conflicts & Root Cause Analysis

### Conflict INC-001: SQLite Database Method Naming Discrepancies
- **Observation:** `AttributeError: 'Database' object has no attribute 'get_scans'. Did you mean: 'get_scan'?` encountered during initial context endpoint invocation.
- **Root Cause:** Historical code in `core/database.py` implemented `list_scans()` and `list_findings()`, while new enterprise modules expected `get_scans()` and `get_findings_by_scan()`.
- **Resolution:** Added backward-compatible aliases in `core/database.py`:
  ```python
  def get_scans(self, limit: Optional[int] = None) -> List[ScanJob]:
      return self.list_scans(limit=limit)

  def get_findings_by_scan(self, scan_id: str) -> List[VulnerabilityFinding]:
      return self.list_findings(scan_id=scan_id)
  ```
- **Verification:** Live test call to `/api/context` returned 200 OK with accurate scan telemetry.
- **Status:** **RESOLVED & VERIFIED**

---

### Conflict INC-002: Missing `datetime` Import in Extended Database Methods
- **Observation:** `NameError: name 'datetime' is not defined` when saving remediation tickets with UTC timestamps.
- **Root Cause:** `datetime` was utilized in new ticket and graph persistence methods but was not imported at the module root of `core/database.py`.
- **Resolution:** Added `import datetime` to module header in `core/database.py`.
- **Verification:** Pytest unit test `test_remediation_lifecycle_and_retest` passed cleanly.
- **Status:** **RESOLVED & VERIFIED**

---

### Conflict INC-003: Pytest Asyncio Marker Execution in Synchronous Harness
- **Observation:** Pytest reported `async def functions are not natively supported` when executing `tests/test_enterprise_platform.py`.
- **Root Cause:** The host Python environment does not have the third-party `pytest-asyncio` plugin installed, while `anyio` was the only active plugin.
- **Resolution:** Standardized async test execution using native `asyncio.run(_run())` closures, aligning with the existing test conventions in `tests/test_ai_training_and_evaluation.py` and `tests/test_llm_security_testing.py`.
- **Verification:** All 9 enterprise tests passed in 2.30 seconds with zero plugin errors.
- **Status:** **RESOLVED & VERIFIED**

---

### Conflict INC-004: Incomplete Technology Name Extraction in Knowledge Graph
- **Observation:** `AttributeError: 'NoneType' object has no attribute 'lower'` when processing recon results containing empty or non-standard technology metadata.
- **Root Cause:** `t.get("name")` returned `None` for unclassified technologies.
- **Resolution:** Added strict null-safety checks:
  ```python
  val = (t.get("name") if isinstance(t, dict) else str(t)) if t else None
  if val:
      tech_id = f"tech_{str(val).lower().replace(' ', '_')}"
  ```
- **Verification:** Knowledge Graph ingestion successfully synchronized 35 nodes and 40 edges from historical scans.
- **Status:** **RESOLVED & VERIFIED**
