# SWA AI — Integration Changelog

## [2.3.0] — 2026-11-02 — Master Engineering Consolidation

### Preserved
- Preserved all 127 existing automated tests across AI training, OWASP plugins, REA engine, scope policies, and subdomains.
- Preserved 76 historical scans, 266 findings, and 2,296 execution logs across all databases.
- Preserved all 85 registered multi-agent workforce manifests across 5 operational tiers.
- Preserved all cross-platform launcher scripts: `install.bat`, `install.sh`, `install.ps1`, `install_macos.sh`, `run.bat`, `run.ps1`, `run.sh`, `run_macos.sh`, `stop.bat`, `stop.ps1`, `stop.sh`, `stop_macos.sh`.

### Recovered & Integrated
- Restored `core/audit.py` providing append-only thread-safe audit logging for all security-sensitive actions.
- Restored `core/scoring.py` providing canonical single-source-of-truth severity weights and posture grades.
- Restored `core/version.py` establishing version `2.3.0` (Codename: "Sentinel").
- Restored `deploy/` directory containing deployment profiles for AWS, Azure, GCP Cloud Run, Docker Compose, Linux systemd, and offline self-hosted environments.
- Restored missing documentation: `BACKUP_AND_RECOVERY.md`, `CLOUD_DEPLOYMENT.md`, `DOCKER_DEPLOYMENT.md`, `LOCAL_INSTALLATION.md`, and `SECURITY_CONFIGURATION.md`.
- Restored missing audit reports into `reports/`.
- Restored and updated `tests/test_deployment_readiness.py`, `tests/test_system_status.py`, and `tests/e2e/`.

### Implemented
- **Secure API Key Management (`core/credentials.py`)**:
  - Symmetric Fernet/AES-256 encryption at rest. Master encryption key stored strictly outside the database (via environment variable `SWA_ENCRYPTION_KEY` or file-permission-restricted `.swa_master.key`).
  - Secret redaction: secrets are never returned in full to the frontend JavaScript or printed in logs.
  - Rate-limited and timeout-protected live connection testing.
- **Integration Framework (`core/integrations/`)**:
  - Threat Intel: VirusTotal, AbuseIPDB, Shodan, Censys, AlienVault OTX, URLhaus.
  - Security Platforms: Wazuh, Splunk, Elastic Security, Microsoft Sentinel, CrowdStrike, SentinelOne, Qualys, Rapid7, Tenable, DefectDojo.
  - Cloud Providers: AWS, Azure, GCP.
- **AI Model Management (`core/ai_models.py`)**:
  - Support for OpenAI, Anthropic, Google Gemini, OpenRouter, and Ollama/Local models.
  - Model availability probe, token limits, temperature adjustment, default selection, and fallback routing.
- **System Health Diagnostics (`/api/system/status`, `/api/ai/status`, `/health`, `/ready`)**:
  - Added honest diagnostic reporting with no fabricated statistics.
  - Integrated `db.check_health()` providing WAL status, table integrity, and scan counts.
- **Main Navigation & Settings UI**:
  - Unified 14-view sidebar navigation connecting all pages directly to real application logic.
  - Added dedicated "API Keys & Integrations" and "AI Models" interfaces under Settings.
  - Maintained persistent Cyber Deploy Acceptance Checklist with Markdown and JSON exports.
