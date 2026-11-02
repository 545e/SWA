"""
SWA AI Audit Log
Append-only record of security-relevant actions performed through the platform
(exports, test runs, deployments, settings changes, scope refusals).

The table is created additively (CREATE TABLE IF NOT EXISTS) — existing
databases are never altered destructively.
"""

import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.database import db


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AuditLog:
    """Thread-safe append-only audit trail backed by SQLite."""

    def __init__(self):
        self._lock = threading.Lock()
        self._ensured = False

    # ------------------------------------------------------------------ init
    def ensure_table(self) -> None:
        """Create the audit table if it does not exist (additive only)."""
        if self._ensured:
            return
        with self._lock:
            if self._ensured:
                return
            with db.get_connection() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        created_at TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        action TEXT NOT NULL,
                        resource TEXT,
                        status TEXT,
                        detail TEXT,
                        client TEXT
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log (created_at DESC)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log (action)"
                )
            self._ensured = True

    # ---------------------------------------------------------------- record
    def record(
        self,
        action: str,
        resource: Optional[str] = None,
        status: str = "OK",
        detail: Optional[str] = None,
        actor: str = "local",
        client: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Append one audit entry.

        Never raises: audit collection must not break the operation being
        audited, but failures are surfaced through the returned payload.
        """
        self.ensure_table()
        try:
            created = _utc_now()
            with self._lock:
                with db.get_connection() as conn:
                    cur = conn.execute(
                        """
                        INSERT INTO audit_log
                            (created_at, actor, action, resource, status, detail, client)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            created,
                            str(actor or "local")[:64],
                            str(action or "unknown")[:128],
                            (str(resource)[:512] if resource else None),
                            str(status or "OK")[:32],
                            (str(detail)[:2000] if detail else None),
                            (str(client)[:128] if client else None),
                        ),
                    )
                    row_id = cur.lastrowid
            return {"recorded": True, "id": row_id, "created_at": created}
        except Exception as exc:  # pragma: no cover - defensive
            return {"recorded": False, "error": str(exc)}

    # ------------------------------------------------------------------ list
    def entries(
        self,
        limit: int = 100,
        action: Optional[str] = None,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Return recent audit entries, newest first."""
        self.ensure_table()
        limit = max(1, min(int(limit or 100), 1000))
        offset = max(0, int(offset or 0))
        try:
            with db.get_connection() as conn:
                if action:
                    rows = conn.execute(
                        """
                        SELECT * FROM audit_log
                        WHERE action = ?
                        ORDER BY id DESC LIMIT ? OFFSET ?
                        """,
                        (str(action)[:128], limit, offset),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?",
                        (limit, offset),
                    ).fetchall()
            return [dict(r) for r in rows]
        except Exception as exc:
            return [{"error": str(exc)}]

    def count(self) -> int:
        self.ensure_table()
        try:
            with db.get_connection() as conn:
                return int(conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0])
        except Exception:
            return 0


audit = AuditLog()

# Ensure the table exists at import time so callers never race on first use.
try:
    audit.ensure_table()
except Exception:  # pragma: no cover - database may be unavailable at import
    pass

__all__ = ["audit", "AuditLog"]
