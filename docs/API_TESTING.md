# SWA AI — API Testing & Verification Guide

## 1. Automated Test Architecture
SWA AI includes a comprehensive, automated pytest test suite covering all platform modules:
- Unit tests: Schema validation, token buckets, secret encryption, hashing.
- Integration tests: Database transactions, third-party adapters, tool registries.
- End-to-End tests: Autonomous scanner lifecycle, agent coordination, report exports.

## 2. Running Test Suites
```powershell
# Run the complete test suite across all 206 test cases
pytest -v

# Run the dedicated API v1 test suite
pytest tests/test_v1_api_suite.py -v

# Run threat intelligence and external integration tests
pytest tests/test_integrations_and_ai_models.py -v
```

## 3. Test Suites Inventory
- `tests/test_v1_api_suite.py`: Master test suite for all `/api/v1/*` endpoints.
- `tests/test_integrations_and_ai_models.py`: Validates 23 integration adapters.
- `tests/test_all_tools_integration.py`: Validates 15 security tools.
- `tests/test_report_engine.py`: Validates Nessus-style reports.
- `tests/test_e2e_local_scan.py`: Validates end-to-end autonomous pentesting.
- `tests/test_scope_policy.py`: Validates SSRF protection and allowlists.
