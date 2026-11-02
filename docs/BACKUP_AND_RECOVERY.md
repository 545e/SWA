# SWA AI — Database Backup, Persistence & Disaster Recovery Guide

## Overview
SWA AI utilizes an optimized, thread-safe SQLite database (`swa_data.db`) configured with:
- **Write-Ahead Logging (WAL mode)** for high concurrency between web queries and background scanner workers.
- **Busy timeout (5,000ms)** to eliminate database lock contention.
- **Foreign key constraints** to maintain relational data integrity.

---

## 1. Zero-Downtime Online Backup API

Because WAL mode separates active writes into `.wal` files, standard file copying while scans are running can result in inconsistent snapshots. SWA AI provides a native backup engine utilizing SQLite's online backup API (`sqlite3.Connection.backup()`).

### Trigger Backup via Python Script
```python
from core.database import db

# Creates a timestamped backup in backups/swa_backup_YYYYMMDD_HHMMSS.db
backup_file = db.backup_database()
print(f"Backup created at: {backup_file}")
```

### Trigger Backup via REST API
```bash
curl -X POST http://127.0.0.1:8000/api/database/backup
```
**Response**:
```json
{
  "success": true,
  "backup_path": "/opt/swa-ai/backups/swa_backup_20261030_101925.db",
  "backup_size_bytes": 638976
}
```

### Trigger Backup via Docker Container
```bash
docker exec -it swa-ai-cyber-hub python -c "from core.database import db; print(db.backup_database())"
```

---

## 2. Automated Scheduled Backups (Cron)

Set up a daily cron job using the backup script in [`deploy/self-hosted/backup.sh`](../deploy/self-hosted/backup.sh):

```bash
# Add to crontab: sudo crontab -e
0 2 * * * /opt/swa-ai/deploy/self-hosted/backup.sh >> /var/log/swa-backup.log 2>&1
```

---

## 3. Disaster Recovery & Database Restoration

If the primary database file becomes corrupted or needs to be rolled back to a previous checkpoint:

1. **Stop the Application**:
   ```bash
   # Systemd
   sudo systemctl stop swa
   # Docker
   docker compose down
   ```
2. **Archive Current State**:
   ```bash
   mv swa_data.db swa_data.db.corrupt.$(date +%s)
   rm -f swa_data.db-wal swa_data.db-shm
   ```
3. **Restore from Snapshot**:
   ```bash
   cp backups/swa_backup_20261030_101925.db swa_data.db
   ```
4. **Verify Integrity**:
   ```bash
   python -c "from core.database import db; print(db.check_health())"
   ```
5. **Restart Service**:
   ```bash
   sudo systemctl start swa
   ```

---

## 4. PostgreSQL / MySQL Migration Strategy

If enterprise requirements demand horizontal scaling across a distributed cluster of worker nodes, SQLite can be transitioned to PostgreSQL:
1. Maintain existing Pydantic schemas in [`core/models.py`](../core/models.py).
2. Configure `DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/swa_ai` in `.env`.
3. Use the export script `scripts/export_to_sql.py` to dump existing scans and findings into PostgreSQL-compatible INSERT statements.
