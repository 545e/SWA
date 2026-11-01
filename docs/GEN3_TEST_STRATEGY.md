# SWA AI — Generation 3 Test Strategy & Quality Gates

## 1. Quality Objectives

1. **Zero Regressions:** Maintain 100% pass rate across the comprehensive test suite.
2. **Defensible Verification:** Every major subsystem (scanners, agents, database, security gates, export) must have automated regression tests.
3. **End-to-End Validation:** Verify complete scan execution against local targets with lab authorization.

---

## 2. Test Pyramid & Directory Structure

```text
tests/
├── test_api_and_dashboard.py                    # REST APIs, SOC structure & navigation dispatch
├── test_e2e_local_scan.py                       # Full scan lifecycle & SSRF verification
├── test_enterprise_platform.py                  # Agent dispatch, approval gates, drift & risk scoring
├── test_generation2_security_and_integrity.py   # Security headers, rate limiting, indexes & backup
├── test_scope_policy.py                         # Target scope validation and SSRF defenses
├── test_subdomain_engine.py                     # Passive/active enumeration & DNS resilience
├── test_tool_registry.py                        # Tool metadata, asset inventory & health checks
├── test_cyber_export.py                         # Multi-format report generation (JSON, CSV, HTML, PDF)
├── test_cyber_deploy.py                         # CI/CD deployment verification & rollback
├── test_cyber_test.py                           # Automated cyber test harness execution
├── test_data_management.py                      # Dataset validation, leakage detection & splits
├── test_ai_training_and_evaluation.py           # ML hardware checks & classifier evaluation
├── test_rea_engine.py                           # Remediation engine & ticket lifecycles
├── test_owasp_plugins.py                        # Security scanner plugin rules & detections
├── test_scanner_integrations.py                 # External tool wrappers & error handling
└── test_llm_security_testing.py                 # LLM red-teaming & prompt injection checks
```

---

## 3. Continuous Execution Commands

```powershell
# Run full test suite
python -m pytest tests -v

# Run targeted fast test suite
python -m pytest tests/test_api_and_dashboard.py tests/test_generation2_security_and_integrity.py -q
```
