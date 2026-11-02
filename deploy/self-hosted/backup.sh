#!/usr/bin/env bash
# ======================================================================
#   SWA AI - Automated SQLite Database Backup Script
#   Suitable for daily cron execution: 0 2 * * * /opt/swa-ai/deploy/self-hosted/backup.sh
# ======================================================================

set -euo pipefail

BACKUP_DIR="${SWA_BACKUP_DIR:-/opt/swa-ai/backups}"
mkdir -p "$BACKUP_DIR"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="$BACKUP_DIR/swa_backup_${TIMESTAMP}.db"

echo "[*] Triggering live online SQLite backup..."
if [ -f "/opt/swa-ai/.venv/bin/python" ]; then
    /opt/swa-ai/.venv/bin/python -c "from core.database import db; db.backup_database('$BACKUP_FILE')"
else
    python3 -c "from core.database import db; db.backup_database('$BACKUP_FILE')"
fi

echo "[+] Backup successfully written to $BACKUP_FILE"

# Retention: Remove backups older than 14 days
find "$BACKUP_DIR" -name "swa_backup_*.db" -type f -mtime +14 -delete
echo "[+] Retention policy applied (14 days retained)."
