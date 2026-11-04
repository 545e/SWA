# SWA AI — API Changelog

## [2.3.0] — 2026-11-04 (Generation-2 Master API Modernization)

### Added
- **Unified Master API v1 (`/api/v1/*`)**:
  - Implemented 76 versioned routes covering all platform subsystems with standardized JSON response envelopes.
  - Subsystems: `/auth`, `/users`, `/organizations`, `/workspaces`, `/projects`, `/dashboard`, `/assessments`, `/assets`, `/vulnerabilities`, `/findings`, `/verification`, `/remediation`, `/security-tools`, `/integrations`, `/threat-intelligence`, `/ai`, `/investigations`, `/easm`, `/incidents`, `/approvals`, `/reports`, `/exports`, `/audit`, `/system`.
- **System Health Probes**:
  - Added `/health/live` for container liveness probing.
  - Added `/health/ready` for database readiness checking.
  - Added `/health/dependencies` for full dependency introspection without leaking secrets.
- **Threat Intelligence Extensions**:
  - Added `CisaKevAdapter` for US CISA Known Exploited Vulnerabilities catalog.
  - Added `FirstEpssAdapter` for FIRST.org EPSS exploit probability scoring.
  - Expanded integrations registry to 23 supported providers.
- **Target Scope Auto-Authorization**:
  - Verified public domains entered by operators (e.g. `starasia.org`) are automatically authorized and persisted to `config/targets.json`.
- **Comprehensive API Documentation Suite**:
  - Authored 13 production documentation files in `docs/`.
  - Added `tests/test_v1_api_suite.py` test suite.

### Fixed
- Fixed agents grid rendering so that all 85 agents load and display reliably with fail-safe recovery.
- Fixed target scope refusal on operator-entered targets.
- Preserved 100% backward compatibility for all existing `/api/*` routes.
