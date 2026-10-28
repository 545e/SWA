# SWA AI — Automated Testing & Quality Assurance Guide

SWA AI includes an automated test suite located in `tests/`. All tests run using Python's standard `unittest` framework with no external test runners required.

---

## 1. Running the Test Suite

Execute all tests from the repository root:

```powershell
py -3.12 -m unittest discover tests/
```

Expected output:
```text
Ran 22 tests in 7.8s

OK
```

---

## 2. Test Structure & Coverage

### A. Scope Policy & SSRF Defense (`tests/test_scope_policy.py`)
- **`test_normalize_hostname`**: Verifies URL parsing, port stripping, and IPv6 bracket handling.
- **`test_reject_dangerous_schemes`**: Ensures non-HTTP protocols (`file://`, `gopher://`, `ftp://`) are rejected.
- **`test_empty_target`**: Validates graceful rejection of blank target inputs.
- **`test_cloud_metadata_blocked`**: Confirms that AWS, Azure, GCP, and OpenStack IMDS endpoints (`169.254.169.254`, `169.254.170.2`, `fd00:ec2::254`) are blocked.
- **`test_private_and_loopback_classification`**: Verifies RFC 1918 and loopback address detection.
- **`test_ssrf_blocking_without_lab_mode`**: Proves `127.0.0.1` is blocked with HTTP 403 when `lab_mode=False`.
- **`test_lab_mode_authorization_positive`**: Confirms `127.0.0.1` is permitted when `lab_mode=True`.
- **`test_invalid_domain_syntax`**: Validates regex enforcement for FQDN RFC syntax.

### B. Cybersecurity Tool Integrations (`tests/test_scanner_integrations.py`)
- **`test_tool_inventory_structure`**: Verifies presence of all 11 security tools with required metadata.
- **`test_command_reference_structure`**: Confirms the command reference contains all required fields (command, options, lab example, safety notes, common errors).
- **`test_health_check_native`**: Confirms native Python engines return `status: HEALTHY`.
- **`test_health_check_uninstalled`**: Verifies missing tools return `status: UNAVAILABLE` with actionable installation guidance without raising exceptions.
- **`test_health_check_invalid`**: Confirms unknown tool IDs return `status: NOT_FOUND`.
- **`test_sqlmap_refusal_without_lab_mode`**: Proves SQLmap execution is refused unless `lab_mode=True`.
- **`test_dependency_manifest_scan_python`**: Tests detection of outdated Django in `requirements.txt` (CWE-1104).
- **`test_dependency_manifest_scan_node`**: Tests detection of lodash prototype pollution in `package.json` (CWE-1321).
- **`test_dependency_manifest_clean`**: Confirms modern dependencies yield 0 false positives.

### C. OWASP Top 10 Security Plugins (`tests/test_owasp_plugins.py`)
- **`test_all_10_plugins_instantiate`**: Confirms all 10 OWASP plugins load, enable, and map to their respective OWASP categories.
- **`test_sql_error_signatures`**: Tests regex signature matching for MySQL, Postgres, Oracle, and SQLite error leaks.
- **`test_stack_trace_signatures`**: Tests detection of Python, Java, and .NET runtime exception dumps.

### D. End-to-End Local Lab Scan (`tests/test_e2e_local_scan.py`)
- **`test_01_ssrf_protection_blocks_unauthorized_local_scan`**: Live API test verifying that `POST /api/scans` returns HTTP 403 on loopback targets when `lab_mode=False`.
- **`test_02_e2e_authorized_scan_execution`**:
  - Submits authorized scan to `http://127.0.0.1:8000` with `lab_mode=True`.
  - Polls status transitions: `PENDING` $\rightarrow$ `RUNNING` $\rightarrow$ `COMPLETED`.
  - Verifies SQLite persistence and validates that findings contain real evidence, CWE identifiers, and remediation advice.
  - Verifies report generation across all 5 formats (**HTML**, **JSON**, **SARIF 2.1.0**, **CSV**, and **Markdown**).
