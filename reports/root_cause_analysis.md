# SWA AI — Root Cause Analysis (RCA)
**Report ID:** RCA-001  
**Date:** 2026-10-31 07:49:28 UTC  

## Defect 1: Virtual Environment `pydantic_core` ABI Incompatibility
- **Observed Behavior:** Pytest execution crashed during test collection with: `ImportError: cannot import name 'ArgsKwargs' from 'pydantic_core._pydantic_core'`.
- **Root Cause:** A wheel compiled for Python 3.15 (`_pydantic_core.cp315-win_amd64.pyd`) had been installed into a Python 3.12 virtual environment. Python 3.12 skipped the incompatible `.pyd` and fell back to the stub directory containing only `.pyi` files.
- **Resolution:** Reinstalled `pydantic` and `pydantic-core` using `--force-reinstall`, acquiring the official `pydantic_core-2.50.2-cp312-cp312-win_amd64.whl`.
- **Outcome:** All 65 original tests collected and executed successfully.

## Defect 2: Incomplete Cyber Modules (Export, Test, Deploy)
- **Observed Behavior:** OpenCode session terminated with: `! General failed - Build Cyber Export module`, `! General failed - Build Cyber Deploy module`, `! General failed - Build Cyber Test module`.
- **Root Cause:** Token limits caused OpenCode to halt before authoring the backend engines, database schemas, and frontend hooks for Phases 8, 9, and 10.
- **Resolution:** 
  1. Authored `core/cyber_export.py` with multi-format export, redaction, and SHA-256 verification.
  2. Authored `core/cyber_test.py` with 6-category automated testing.
  3. Authored `core/cyber_deploy.py` with 11-step deployment lifecycle and approval gate.
  4. Added database tables and schema migrations in `core/database.py`.
  5. Added REST endpoints in `web/server.py`.
  6. Added UI tabs and interactive controls in `web/static/index.html` and `web/static/app.js`.

## Defect 3: Stale Runner Reference in `docs/TESTING.md`
- **Observed Behavior:** `docs/TESTING.md` documented running tests solely via `py -3.12 -m unittest discover tests/` with a stale count of 23 tests.
- **Root Cause:** Documentation lagged behind pytest adoption and expanded test coverage.
- **Resolution:** Rewrote `docs/TESTING.md` documenting both `pytest` (79 tests) and `unittest`.
