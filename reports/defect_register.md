# SWA AI — Central Defect Register
**Report ID:** DEF-REG-001  
**Date:** 2026-10-31 07:49:28 UTC  

| Defect ID | Title | Module | Severity | Priority | Root Cause | Status | Verification |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **DEF-0001** | `pydantic_core` Python 3.15 wheel ABI mismatch | venv / runtime | CRITICAL | P0 | Incompatible .pyd wheel installed in Python 3.12 venv | FIXED | Verified via pytest (79 passed) |
| **DEF-0002** | Stale runner command in `docs/TESTING.md` | docs | LOW | P3 | Outdated documentation referencing 23 unittest tests | FIXED | Verified in docs/TESTING.md |
| **DEF-0003** | Missing Cyber Export module | core/export | HIGH | P1 | OpenCode session halted before module creation | FIXED | Tested in test_cyber_export.py |
| **DEF-0004** | Missing Cyber Test module | core/test | HIGH | P1 | OpenCode session halted before module creation | FIXED | Tested in test_cyber_test.py |
| **DEF-0005** | Missing Cyber Deploy module | core/deploy | HIGH | P1 | OpenCode session halted before module creation | FIXED | Tested in test_cyber_deploy.py |
| **DEF-0006** | Database missing `get_settings()` method | core/db | MEDIUM | P2 | DB had `get_setting(key)` but not dictionary `get_settings()` | FIXED | Added method & verified |
| **DEF-0007** | `ScopePolicy.validate_target` missing `lab_mode` kwarg | core/scope | MEDIUM | P2 | Argument named `explicit_lab_authorization` without alias | FIXED | Added `lab_mode` alias & `.allowed` |
| **DEF-0008** | `ToolRegistry` missing `list_tools()` method | core/tools | MEDIUM | P2 | Method was named `list_all()` | FIXED | Added alias method & verified |
| **DEF-0009** | WebSocket infinite reconnect without backoff | web/ui | MEDIUM | P2 | Fixed 2s reconnection loop caused UI flicker | FIXED | Exponential backoff + heartbeat |
| **DEF-0010** | Secret redaction regex missing capturing group | core/export | MEDIUM | P2 | Regex for private keys lacked group 1 | FIXED | Updated redaction logic |
