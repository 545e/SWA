# SWA AI — Fix Changelog & Engineering Remediation Log

**Date:** 2026-10-30  
**Repository Version:** 2.1.0  
**Auditor:** Principal Software Architect & QA Automation Lead  

---

## 1. Summary of Changes

| Identifier | Target File | Component | Category | Status |
| :--- | :--- | :--- | :--- | :---: |
| **FIX-01** | `core/database.py` | Connection Lifecycle | Database & Resource Management | Resolved |
| **FIX-02** | `web/static/index.html` | DOM Layout & Structure | Frontend & Performance | Resolved |
| **FIX-03** | Virtual Environment | Binary Wheels | Runtime & Dependencies | Resolved |
| **FIX-04** | `setup.py` & `requirements-dev.txt` | Package Specification | Build & Packaging | Resolved |
| **FIX-05** | `run.bat` | Windows Startup Script | DevOps & Diagnostics | Resolved |
| **FIX-06** | `Dockerfile` | Containerization | Security & Container Hardening | Resolved |
| **FIX-07** | `docker-compose.yml` | Compose Service Definition | Resource Optimization | Resolved |

---

## 2. Detailed Fix Records

### FIX-01: SQLite Connection Lifecycle & Resource Leak Fix
- **File:** `core/database.py`
- **Root Cause:**
  `Database.get_connection()` returned a raw `sqlite3.Connection`. Calling `with self.get_connection() as conn:` only triggered transaction management (`__enter__` starts transaction, `__exit__` commits/rolls back); it never called `conn.close()`. Across 30+ database methods, every read/write operation leaked an open SQLite connection object, generating dozens of `ResourceWarning: unclosed database in <sqlite3.Connection>` warnings and risking Windows file descriptor locking.
- **Change Implemented:**
  Wrapped `get_connection()` in `@contextlib.contextmanager`. Initialized connection with `timeout=30.0` and guaranteed `conn.close()` inside a `finally` block:
  ```python
  @contextlib.contextmanager
  def get_connection(self):
      conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
      conn.row_factory = sqlite3.Row
      try:
          with conn:
              yield conn
      finally:
          conn.close()
  ```
- **Verification:**
  Executed `pytest -W error::ResourceWarning tests/test_api_and_dashboard.py`. Zero warnings, zero leaks, 100% tests passed.

---

### FIX-02: Removal of 5,222 Redundant Lines & Duplicate DOM IDs
- **File:** `web/static/index.html`
- **Root Cause:**
  Commit `4562fb3` mistakenly performed a bulk regex/sed insertion that pasted the extended SOC tabs (`tabAssets`, `tabCompare`, `tabAiDatasets`, `tabAiTraining`, `tabAiEvaluation`, `tabLlmRedTeam`, `tabToolRegistry`) 14 times across multiple tab containers and tool panels. This bloated `index.html` to 8,485 lines and broke DOM query selectors due to duplicate element IDs.
- **Change Implemented:**
  Identified and removed all 14 duplicate code ranges (5,222 lines) while preserving the single valid instance in the main tab content container. Restored `index.html` to 3,263 lines of clean, standards-compliant HTML.
- **Verification:**
  Verified that `id="tabAssets"`, `id="tabCompare"`, `id="tabAiDatasets"`, `id="tabAiTraining"`, `id="tabAiEvaluation"`, `id="tabLlmRedTeam"`, and `id="tabToolRegistry"` now occur exactly once. Dashboard navigation and modal controls verified operational.

---

### FIX-03: Python C-Extension Binary Wheel Repair
- **File:** `venv/Lib/site-packages/pydantic_core`
- **Root Cause:**
  A wheel compiled for Python 3.12 (`_pydantic_core.cp312-win_amd64.pyd`) was present in a Python 3.15 virtual environment. Python could not load the C extension and fell back to the `_pydantic_core` directory namespace, raising `ImportError: cannot import name 'ArgsKwargs' from 'pydantic_core._pydantic_core'`.
- **Change Implemented:**
  Executed forced binary wheel reinstallation for `pydantic` and `pydantic_core` matching the target Python interpreter environment.
- **Verification:**
  Command `swa --help` executed with return code 0 and displayed complete CLI manual.

---

### FIX-04: Automated Testing Package Declarations
- **Files:** `setup.py`, `requirements-dev.txt`
- **Root Cause:**
  `pytest` and `pytest-cov` were not registered in `requirements.txt` or `setup.py`, leading to missing module errors when running automated tests in fresh environments.
- **Change Implemented:**
  Added `extras_require={"test": ["pytest>=8.0.0", "pytest-cov>=5.0.0"]}` in `setup.py` and created standalone `requirements-dev.txt`.
- **Verification:**
  Tested `pip install -e .[test]` and ran full pytest suite with 100% pass rate.

---

### FIX-05: Windows Launcher Diagnostic & Resilience Enhancement
- **File:** `run.bat`
- **Root Cause:**
  When essential dependencies failed to import, `run.bat` ran `pip install -r requirements.txt`. If pip found all requirements satisfied without fixing a broken wheel, `run.bat` failed without printing the actual Python traceback.
- **Change Implemented:**
  Enhanced `run.bat` to re-test the import after pip execution and print the exact Python import traceback if it fails, guiding the operator to run a force-reinstall repair.
- **Verification:**
  Simulated dependency failure and confirmed clear diagnostic instructions are displayed.

---

### FIX-06: Container Security Hardening (Non-Root User)
- **File:** `Dockerfile`
- **Root Cause:**
  Container executed as the root user (`uid=0`), which represents an unnecessary security exposure.
- **Change Implemented:**
  Added dedicated system group and unprivileged user `swa` (`groupadd -r swa && useradd -r -g swa`). Set ownership of `/app` and `/data` to `swa:swa`, and specified `USER swa`.
- **Verification:**
  Syntax and Dockerfile structure validated against OCI container security best practices.

---

### FIX-07: Container Resource Limits & Health Checks
- **File:** `docker-compose.yml`
- **Root Cause:**
  No resource limits were specified, risking CPU and memory starvation on a 2 vCPU / 3 GB RAM host.
- **Change Implemented:**
  Added `deploy.resources.limits` capping CPUs to `2.0` and memory to `3072M`, with container health check targeting `/api/settings`.
- **Verification:**
  Compose configuration validated for standard multi-core constrained deployments.
