"""
SWA AI Database Store
Thread-safe SQLite storage for scans, vulnerability findings, logs, and system settings.
"""

import sqlite3
import json
import os
from typing import List, Optional, Dict, Any
from core.models import ScanJob, VulnerabilityFinding, LogEvent, ScanStatus, ScanProfile, Severity, ScanConfig, ReconResult

DB_PATH = os.getenv("SWA_DB_PATH", os.path.join(os.path.dirname(os.path.dirname(__file__)), "swa_data.db"))

class Database:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Scans table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                status TEXT NOT NULL,
                profile TEXT NOT NULL,
                progress_percent INTEGER DEFAULT 0,
                current_phase TEXT DEFAULT 'Initialized',
                findings_count INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                duration_seconds REAL,
                error_message TEXT,
                config_json TEXT,
                recon_json TEXT,
                endpoints_count INTEGER DEFAULT 0
            )
            """)

            # Vulnerabilities / Findings table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                cvss_score REAL DEFAULT 0.0,
                cvss_vector TEXT,
                cwe_id TEXT,
                owasp_category TEXT,
                endpoint TEXT NOT NULL,
                method TEXT DEFAULT 'GET',
                parameter TEXT,
                description TEXT,
                poc_curl TEXT,
                poc_explanation TEXT,
                request_evidence TEXT,
                response_evidence TEXT,
                remediation_advice TEXT,
                remediation_patch TEXT,
                verified INTEGER DEFAULT 1,
                created_at TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            )
            """)

            # Live Scan Logs table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                agent TEXT NOT NULL,
                message TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            )
            """)

            # System settings table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """)
            conn.commit()

    def save_scan(self, job: ScanJob):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO scans (
                id, target_url, status, profile, progress_percent, current_phase,
                findings_count, critical_count, high_count, medium_count, low_count, info_count,
                created_at, started_at, completed_at, duration_seconds, error_message,
                config_json, recon_json, endpoints_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                job.id, job.target_url, job.status.value, job.profile.value,
                job.progress_percent, job.current_phase,
                job.findings_count, job.critical_count, job.high_count,
                job.medium_count, job.low_count, job.info_count,
                job.created_at, job.started_at, job.completed_at, job.duration_seconds,
                job.error_message, job.config.model_dump_json(),
                job.recon_data.model_dump_json() if job.recon_data else None,
                job.endpoints_count
            ))
            conn.commit()

    def update_scan_progress(self, scan_id: str, progress: int, phase: str, error: Optional[str] = None):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE scans
            SET progress_percent = ?, current_phase = ?, error_message = COALESCE(?, error_message)
            WHERE id = ?
            """, (progress, phase, error, scan_id))
            conn.commit()

    def update_scan_status(self, scan_id: str, status: ScanStatus, started_at: Optional[str] = None, completed_at: Optional[str] = None, duration_seconds: Optional[float] = None):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if started_at:
                cursor.execute("UPDATE scans SET status = ?, started_at = ? WHERE id = ?", (status.value, started_at, scan_id))
            elif completed_at:
                cursor.execute("""
                UPDATE scans 
                SET status = ?, completed_at = ?, duration_seconds = ?
                WHERE id = ?
                """, (status.value, completed_at, duration_seconds, scan_id))
            else:
                cursor.execute("UPDATE scans SET status = ? WHERE id = ?", (status.value, scan_id))
            conn.commit()

    def update_scan_counts(self, scan_id: str):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT severity, COUNT(*) as cnt FROM findings WHERE scan_id = ? GROUP BY severity", (scan_id,))
            rows = cursor.fetchall()
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            total = 0
            for r in rows:
                sev = (r["severity"] or "").strip().upper()
                cnt = r["cnt"]
                if sev in counts:
                    counts[sev] = cnt
                total += cnt

            cursor.execute("""
            UPDATE scans SET
                findings_count = ?,
                critical_count = ?,
                high_count = ?,
                medium_count = ?,
                low_count = ?,
                info_count = ?
            WHERE id = ?
            """, (total, counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"], counts["INFO"], scan_id))
            conn.commit()

    def update_scan_recon(self, scan_id: str, recon_data: ReconResult, endpoints_count: int = 0):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE scans
            SET recon_json = ?, endpoints_count = ?
            WHERE id = ?
            """, (recon_data.model_dump_json(), endpoints_count, scan_id))
            conn.commit()

    def get_scan(self, scan_id: str) -> Optional[ScanJob]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_scan(row)

    def list_scans(self) -> List[ScanJob]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans ORDER BY created_at DESC")
            rows = cursor.fetchall()
            return [self._row_to_scan(r) for r in rows]

    def delete_scan(self, scan_id: str) -> bool:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            cursor.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            cursor.execute("DELETE FROM logs WHERE scan_id = ?", (scan_id,))
            conn.commit()
            return cursor.rowcount > 0

    def add_finding(self, finding: VulnerabilityFinding):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO findings (
                id, scan_id, title, severity, cvss_score, cvss_vector, cwe_id, owasp_category,
                endpoint, method, parameter, description, poc_curl, poc_explanation,
                request_evidence, response_evidence, remediation_advice, remediation_patch,
                verified, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding.id, finding.scan_id, finding.title, finding.severity.value,
                finding.cvss_score, finding.cvss_vector, finding.cwe_id, finding.owasp_category,
                finding.endpoint, finding.method, finding.parameter, finding.description,
                finding.poc_curl, finding.poc_explanation, finding.request_evidence,
                finding.response_evidence, finding.remediation_advice, finding.remediation_patch,
                1 if finding.verified else 0, finding.created_at
            ))
            conn.commit()
        self.update_scan_counts(finding.scan_id)

    def save_finding(self, finding: VulnerabilityFinding):
        """Alias for add_finding to support both naming styles."""
        return self.add_finding(finding)

    def list_findings(self, scan_id: Optional[str] = None) -> List[VulnerabilityFinding]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if scan_id:
                cursor.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY cvss_score DESC, created_at DESC", (scan_id,))
            else:
                cursor.execute("SELECT * FROM findings ORDER BY cvss_score DESC, created_at DESC")
            rows = cursor.fetchall()
            return [self._row_to_finding(r) for r in rows]

    def get_finding(self, finding_id: str) -> Optional[VulnerabilityFinding]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_finding(row)

    def add_log(self, event: LogEvent):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO logs (scan_id, timestamp, level, agent, message)
            VALUES (?, ?, ?, ?, ?)
            """, (event.scan_id, event.timestamp, event.level, event.agent, event.message))
            conn.commit()

    def get_logs(self, scan_id: str, limit: int = 500) -> List[LogEvent]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT * FROM logs WHERE scan_id = ? ORDER BY id ASC LIMIT ?
            """, (scan_id, limit))
            rows = cursor.fetchall()
            return [LogEvent(
                timestamp=r["timestamp"],
                scan_id=r["scan_id"],
                level=r["level"],
                agent=r["agent"],
                message=r["message"]
            ) for r in rows]

    def set_setting(self, key: str, value: str):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
            conn.commit()

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
            row = cursor.fetchone()
            if row:
                return row["value"]
            return default

    def _row_to_scan(self, row: sqlite3.Row) -> ScanJob:
        config_data = json.loads(row["config_json"]) if row["config_json"] else {}
        config = ScanConfig(**config_data) if config_data else ScanConfig(target_url=row["target_url"])
        recon_data = None
        if row["recon_json"]:
            try:
                recon_data = ReconResult.model_validate(json.loads(row["recon_json"]))
            except Exception:
                try:
                    recon_data = ReconResult(target=row["target_url"], **json.loads(row["recon_json"]))
                except Exception:
                    recon_data = None
        
        return ScanJob(
            id=row["id"],
            target_url=row["target_url"],
            status=ScanStatus(row["status"]),
            profile=ScanProfile(row["profile"]),
            progress_percent=row["progress_percent"],
            current_phase=row["current_phase"],
            findings_count=row["findings_count"],
            critical_count=row["critical_count"],
            high_count=row["high_count"],
            medium_count=row["medium_count"],
            low_count=row["low_count"],
            info_count=row["info_count"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            duration_seconds=row["duration_seconds"],
            error_message=row["error_message"],
            config=config,
            recon_data=recon_data,
            endpoints_count=row["endpoints_count"] or 0
        )

    def _row_to_finding(self, row: sqlite3.Row) -> VulnerabilityFinding:
        return VulnerabilityFinding(
            id=row["id"],
            scan_id=row["scan_id"],
            title=row["title"],
            severity=Severity(row["severity"]),
            cvss_score=row["cvss_score"],
            cvss_vector=row["cvss_vector"],
            cwe_id=row["cwe_id"],
            owasp_category=row["owasp_category"],
            endpoint=row["endpoint"],
            method=row["method"],
            parameter=row["parameter"],
            description=row["description"],
            poc_curl=row["poc_curl"] or "",
            poc_explanation=row["poc_explanation"] or "",
            request_evidence=row["request_evidence"] or "",
            response_evidence=row["response_evidence"] or "",
            remediation_advice=row["remediation_advice"] or "",
            remediation_patch=row["remediation_patch"],
            verified=bool(row["verified"]),
            created_at=row["created_at"]
        )

db = Database()
