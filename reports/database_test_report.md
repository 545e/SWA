# Database & Persistence Test Report — SWA AI Autonomous Security Auditor

## 1. Storage Architecture
- **Engine**: SQLite 3 (`swa_data.db`)
- **Journal Mode**: `WAL` (Write-Ahead Logging) enables concurrent reads during active scan writes
- **Synchronous Mode**: `NORMAL` (optimal trade-off between disk performance and crash durability)
- **Foreign Keys**: Enabled (`PRAGMA foreign_keys = ON`)

## 2. Dynamic Schema Migrations
The `findings` table dynamically inspects its columns using `PRAGMA table_info(findings)`.
Verified extension columns added without data destruction:
- `confidence TEXT DEFAULT 'HIGH'`
- `detection_method TEXT DEFAULT 'AUTOMATED_PROBE'`
- `affected_asset TEXT`
- `reproduction_steps TEXT`
- `impact TEXT`

## 3. Test Verification
All database lifecycle operations verified via `tests/test_api_and_dashboard.py` and `tests/test_deployment_readiness.py`:
1. **Finding Insertion & Retrieval**: Verified persistence of enriched metadata fields.
2. **Scan Status & Counts**: Verified updates to `critical_count`, `high_count`, `medium_count`, `low_count`.
3. **Scan Re-conciliation**: `reconcile_interrupted_scans()` marks orphaned `RUNNING` scans as `FAILED` upon server restart with detailed crash notes.
4. **Online Backup**: `backup_database(destination_path)` executes non-blocking online backup via SQLite Backup API.
