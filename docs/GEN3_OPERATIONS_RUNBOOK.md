# SWA AI — Generation 3 Operations Runbook

## 1. Service Lifecycle Commands

### Starting the Platform
```powershell
# Windows PowerShell
Set-Location C:\Users\krish\SWA
.\venv\Scripts\Activate.ps1
python run.py
```

### Stopping the Platform
- Press `Ctrl + C` in the console running `run.py`.
- Graceful shutdown persists pending WAL transactions and releases port 8000.

---

## 2. Health & Telemetry Verification

### Health Check Endpoint
```bash
curl -s http://127.0.0.1:8000/health
# Response: {"status":"healthy","service":"swa-ai"}
```

### Subsystems Diagnostic Inspection
```bash
curl -s http://127.0.0.1:8000/api/health/diagnostics
# Returns status for database, 17 agents, tool catalog, knowledge graph, and approval gates.
```

---

## 3. Database Backup & Disaster Recovery

### Online Live Backup
```python
from core.database import db
backup_file = db.backup_database("C:/Users/krish/SWA/data/backup_live.db")
print(f"Database backed up to: {backup_file}")
```

### Database Restore Procedure
1. Stop application: `python run.py` (stop process).
2. Copy backup file over `swa_data.db`.
3. Restart application: `python run.py`.
4. Verify WAL mode and indexes: `python -m pytest tests/test_generation2_security_and_integrity.py -k test_database`.

---

## 4. Troubleshooting Guide

| Issue | Root Cause | Resolution |
|---|---|---|
| HTTP 429 Too Many Requests | Rate limit bucket exhausted | Verify client IP; loopback (`127.0.0.1`) is exempted |
| HTTP 403 Target Scope Refusal | Target is loopback/private/metadata without lab authorization | Set `"lab_mode": true` in scan request or target an authorized public domain |
| Port 8000 Already in Use | Stray background Uvicorn instance | Run `Stop-Process -Id (Get-NetTCPConnection -LocalPort 8000).OwningProcess -Force` |
| View switching issues | Browser cache or stale hash | Hard refresh (`Ctrl + F5`) or navigate to `#/dashboard` |
