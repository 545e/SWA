"""
SWA AI Database Store
Thread-safe SQLite storage for scans, vulnerability findings, logs, and system settings.
"""

import sqlite3
import json
import os
import contextlib
from typing import List, Optional, Dict, Any
from core.models import ScanJob, VulnerabilityFinding, LogEvent, ScanStatus, ScanProfile, Severity, ScanConfig, ReconResult

DB_PATH = os.getenv("SWA_DB_PATH", os.path.join(os.path.dirname(os.path.dirname(__file__)), "swa_data.db"))

class Database:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.init_db()

    @contextlib.contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

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
                confidence TEXT DEFAULT 'HIGH',
                detection_method TEXT DEFAULT 'AUTOMATED_PROBE',
                affected_asset TEXT,
                reproduction_steps TEXT,
                impact TEXT,
                created_at TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            )
            """)

            # Migrate missing columns in findings table if old schema exists
            cursor.execute("PRAGMA table_info(findings)")
            existing_cols = {col[1] for col in cursor.fetchall()}
            for col_name, col_def in [
                ("confidence", "TEXT DEFAULT 'HIGH'"),
                ("detection_method", "TEXT DEFAULT 'AUTOMATED_PROBE'"),
                ("affected_asset", "TEXT"),
                ("reproduction_steps", "TEXT"),
                ("impact", "TEXT")
            ]:
                if col_name not in existing_cols:
                    try:
                        cursor.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_def}")
                    except Exception:
                        pass

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

            # Subdomain & Asset Inventory table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                subdomain TEXT NOT NULL UNIQUE,
                parent_domain TEXT NOT NULL,
                ip_addresses TEXT,
                aaaa_records TEXT,
                cname TEXT,
                status_code INTEGER,
                http_responsive INTEGER DEFAULT 0,
                dns_confirmed INTEGER DEFAULT 0,
                validation_status TEXT DEFAULT 'unresolved',
                confidence TEXT DEFAULT 'low',
                title TEXT,
                server TEXT,
                sources TEXT,
                takeover_risk INTEGER DEFAULT 0,
                takeover_provider TEXT,
                first_seen TEXT,
                last_seen TEXT,
                scan_id TEXT
            )
            """)

            # Datasets table (Phase 4)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS datasets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_type TEXT NOT NULL,
                record_count INTEGER DEFAULT 0,
                file_size_bytes INTEGER DEFAULT 0,
                fields_json TEXT,
                target_label_field TEXT,
                missing_values_count INTEGER DEFAULT 0,
                duplicate_count INTEGER DEFAULT 0,
                leakage_warnings_json TEXT,
                source TEXT,
                license TEXT,
                provenance TEXT,
                permitted_use TEXT,
                train_split_count INTEGER DEFAULT 0,
                val_split_count INTEGER DEFAULT 0,
                test_split_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """)

            # AI Training Jobs table (Phase 5)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_training_jobs (
                id TEXT PRIMARY KEY,
                model_name TEXT NOT NULL,
                base_model TEXT NOT NULL,
                dataset_id TEXT NOT NULL,
                task_type TEXT DEFAULT 'vulnerability_classification',
                status TEXT NOT NULL,
                progress_percent INTEGER DEFAULT 0,
                current_epoch INTEGER DEFAULT 0,
                total_epochs INTEGER DEFAULT 3,
                config_json TEXT NOT NULL,
                loss_history_json TEXT,
                accuracy_history_json TEXT,
                val_loss_history_json TEXT,
                val_accuracy_history_json TEXT,
                resource_usage_json TEXT,
                logs_json TEXT,
                checkpoint_path TEXT,
                model_artifact_path TEXT,
                started_at TEXT,
                completed_at TEXT,
                duration_seconds REAL DEFAULT 0.0,
                error_message TEXT,
                created_at TEXT NOT NULL
            )
            """)

            # AI Model Evaluations table (Phase 6)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_evaluations (
                id TEXT PRIMARY KEY,
                model_name TEXT NOT NULL,
                baseline_model_name TEXT,
                dataset_id TEXT,
                task_type TEXT NOT NULL,
                test_sample_count INTEGER DEFAULT 0,
                accuracy REAL DEFAULT 0.0,
                precision REAL DEFAULT 0.0,
                recall REAL DEFAULT 0.0,
                f1_score REAL DEFAULT 0.0,
                confusion_matrix_json TEXT,
                latency_ms_per_request REAL DEFAULT 0.0,
                throughput_tokens_per_sec REAL DEFAULT 0.0,
                prompt_tokens INTEGER DEFAULT 0,
                completion_tokens INTEGER DEFAULT 0,
                total_tokens INTEGER DEFAULT 0,
                estimated_cost_usd REAL DEFAULT 0.0,
                regression_detected INTEGER DEFAULT 0,
                improvement_percent REAL DEFAULT 0.0,
                comparison_summary TEXT,
                created_at TEXT NOT NULL
            )
            """)

            # LLM Red-Teaming Results table (Phase 7)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS llm_security_tests (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                test_case_id TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                model_target TEXT NOT NULL,
                prompt_sent TEXT NOT NULL,
                expected_behavior TEXT NOT NULL,
                actual_response TEXT,
                status TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT DEFAULT 'HIGH',
                evidence TEXT,
                mitigation TEXT,
                created_at TEXT NOT NULL
            )
            """)
            
            # Cyber Export persistence table (Phase 8)
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS cyber_exports (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                format TEXT NOT NULL,
                export_type TEXT NOT NULL,
                file_path TEXT,
                file_size INTEGER DEFAULT 0,
                findings_count INTEGER DEFAULT 0,
                filter_criteria TEXT,
                status TEXT NOT NULL,
                sha256 TEXT,
                download_url TEXT,
                created_at TEXT NOT NULL
            )
            ''')

            # Cyber Test Runs table (Phase 9)
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS cyber_test_runs (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                profile TEXT NOT NULL,
                status TEXT NOT NULL,
                total_tests INTEGER DEFAULT 0,
                passed_count INTEGER DEFAULT 0,
                failed_count INTEGER DEFAULT 0,
                blocked_count INTEGER DEFAULT 0,
                duration_seconds REAL DEFAULT 0.0,
                summary TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT
            )
            ''')

            # Cyber Test Individual Results table (Phase 9)
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS cyber_test_results (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                test_id TEXT NOT NULL,
                test_name TEXT NOT NULL,
                category TEXT NOT NULL,
                status TEXT NOT NULL,
                severity TEXT NOT NULL,
                duration_seconds REAL DEFAULT 0.0,
                evidence TEXT,
                error_details TEXT,
                remediation TEXT,
                created_at TEXT NOT NULL
            )
            ''')

            # Cyber Deployments table (Phase 10)
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS cyber_deployments (
                id TEXT PRIMARY KEY,
                release_id TEXT NOT NULL,
                environment TEXT NOT NULL,
                method TEXT NOT NULL,
                status TEXT NOT NULL,
                current_step TEXT NOT NULL,
                approved_by TEXT,
                approval_timestamp TEXT,
                health_status TEXT,
                logs TEXT,
                rollback_target TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT
            )
            ''')

            # Cyber Audit Logs table (Phase 11/16)
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS cyber_audit_logs (
                id TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                timestamp TEXT NOT NULL
            )
            ''')

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
                verified, confidence, detection_method, affected_asset, reproduction_steps,
                impact, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding.id, finding.scan_id, finding.title, finding.severity.value,
                finding.cvss_score, finding.cvss_vector, finding.cwe_id, finding.owasp_category,
                finding.endpoint, finding.method, finding.parameter, finding.description,
                finding.poc_curl, finding.poc_explanation, finding.request_evidence,
                finding.response_evidence, finding.remediation_advice, finding.remediation_patch,
                1 if finding.verified else 0,
                finding.confidence,
                finding.detection_method,
                finding.affected_asset,
                finding.reproduction_steps,
                finding.impact,
                finding.created_at
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

    def get_settings(self) -> Dict[str, Any]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM settings")
            rows = cursor.fetchall()
            st = {r["key"]: r["value"] for r in rows}
            # Provide standard defaults
            st.setdefault("ai_provider", "auto")
            st.setdefault("ai_model", "openrouter/z-ai/glm-5.3")
            st.setdefault("ai_base_url", "")
            st.setdefault("default_budget", 10)
            return st

    def get_all_settings(self) -> Dict[str, Any]:
        return self.get_settings()

    def _row_to_scan(self, row: sqlite3.Row) -> ScanJob:
        config_data = json.loads(row["config_json"]) if row["config_json"] else {}
        config = ScanConfig(**config_data) if config_data else ScanConfig(target_url=row["target_url"])
        recon_data = None
        if row["recon_json"]:
            try:
                raw_recon = json.loads(row["recon_json"])
                recon_data = ReconResult.model_validate(raw_recon)
            except Exception:
                try:
                    raw_recon = json.loads(row["recon_json"])
                    if "subdomain_metrics" in raw_recon and isinstance(raw_recon["subdomain_metrics"], dict):
                        for k, v in list(raw_recon["subdomain_metrics"].items()):
                            if isinstance(v, float) and v.is_integer():
                                raw_recon["subdomain_metrics"][k] = int(v)
                    recon_data = ReconResult.model_validate(raw_recon)
                except Exception:
                    try:
                        raw_recon = json.loads(row["recon_json"])
                        raw_recon.pop("subdomain_metrics", None)
                        recon_data = ReconResult.model_validate(raw_recon)
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
        keys = row.keys() if hasattr(row, "keys") else []
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
            confidence=row["confidence"] if "confidence" in keys and row["confidence"] else "HIGH",
            detection_method=row["detection_method"] if "detection_method" in keys and row["detection_method"] else "AUTOMATED_PROBE",
            affected_asset=row["affected_asset"] if "affected_asset" in keys else None,
            reproduction_steps=row["reproduction_steps"] if "reproduction_steps" in keys else None,
            impact=row["impact"] if "impact" in keys else None,
            created_at=row["created_at"]
        )

    # -------------------------------------------------------------
    # Asset & Subdomain Management
    # -------------------------------------------------------------
    def save_asset(self, asset: Dict[str, Any]):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO assets (
                id, subdomain, parent_domain, ip_addresses, aaaa_records, cname,
                status_code, http_responsive, dns_confirmed, validation_status,
                confidence, title, server, sources, takeover_risk, takeover_provider,
                first_seen, last_seen, scan_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                asset.get("id") or asset.get("subdomain"),
                asset.get("subdomain"),
                asset.get("parent_domain", ""),
                json.dumps(asset.get("ip_addresses") or ([asset.get("ip")] if asset.get("ip") else [])),
                json.dumps(asset.get("aaaa_records") or []),
                asset.get("cname", ""),
                asset.get("status") or asset.get("status_code"),
                1 if asset.get("http_responsive") or asset.get("status") else 0,
                1 if asset.get("dns_confirmed") else 0,
                asset.get("validation_status", "unresolved"),
                asset.get("confidence", "low"),
                asset.get("title", ""),
                asset.get("server", ""),
                json.dumps(asset.get("sources") or []),
                1 if asset.get("takeover_risk") else 0,
                asset.get("takeover_provider", ""),
                asset.get("first_seen") or "",
                asset.get("last_seen") or "",
                asset.get("scan_id", "")
            ))
            conn.commit()

    def get_assets(self, parent_domain: Optional[str] = None, limit: int = 200, offset: int = 0) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if parent_domain:
                cursor.execute("SELECT * FROM assets WHERE parent_domain = ? ORDER BY http_responsive DESC, subdomain ASC LIMIT ? OFFSET ?", (parent_domain, limit, offset))
            else:
                cursor.execute("SELECT * FROM assets ORDER BY http_responsive DESC, subdomain ASC LIMIT ? OFFSET ?", (limit, offset))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                try:
                    item["ip_addresses"] = json.loads(item["ip_addresses"]) if item["ip_addresses"] else []
                except Exception:
                    item["ip_addresses"] = []
                try:
                    item["sources"] = json.loads(item["sources"]) if item["sources"] else []
                except Exception:
                    item["sources"] = []
                results.append(item)
            return results

    def count_assets(self, parent_domain: Optional[str] = None) -> int:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if parent_domain:
                cursor.execute("SELECT COUNT(*) FROM assets WHERE parent_domain = ?", (parent_domain,))
            else:
                cursor.execute("SELECT COUNT(*) FROM assets")
            return cursor.fetchone()[0]

    # -------------------------------------------------------------
    # Dataset Management (Phase 4)
    # -------------------------------------------------------------
    def save_dataset(self, meta: Any):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO datasets (
                id, name, filename, file_type, record_count, file_size_bytes,
                fields_json, target_label_field, missing_values_count, duplicate_count,
                leakage_warnings_json, source, license, provenance, permitted_use,
                train_split_count, val_split_count, test_split_count, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                meta.id, meta.name, meta.filename, meta.file_type,
                meta.record_count, meta.file_size_bytes,
                json.dumps(meta.fields), meta.target_label_field,
                meta.missing_values_count, meta.duplicate_count,
                json.dumps(meta.leakage_warnings), meta.source, meta.license,
                meta.provenance, meta.permitted_use,
                meta.train_split_count, meta.val_split_count, meta.test_split_count,
                meta.created_at, meta.updated_at
            ))
            conn.commit()

    def get_dataset(self, dataset_id: str) -> Optional[Any]:
        from core.data_management import DatasetMetadata
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM datasets WHERE id = ?", (dataset_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return DatasetMetadata(
                id=row["id"],
                name=row["name"],
                filename=row["filename"],
                file_type=row["file_type"],
                record_count=row["record_count"],
                file_size_bytes=row["file_size_bytes"],
                fields=json.loads(row["fields_json"] or "[]"),
                target_label_field=row["target_label_field"],
                missing_values_count=row["missing_values_count"],
                duplicate_count=row["duplicate_count"],
                leakage_warnings=json.loads(row["leakage_warnings_json"] or "[]"),
                source=row["source"],
                license=row["license"],
                provenance=row["provenance"],
                permitted_use=row["permitted_use"],
                train_split_count=row["train_split_count"],
                val_split_count=row["val_split_count"],
                test_split_count=row["test_split_count"],
                created_at=row["created_at"],
                updated_at=row["updated_at"]
            )

    def list_datasets(self) -> List[Any]:
        from core.data_management import DatasetMetadata
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM datasets ORDER BY created_at DESC")
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append(DatasetMetadata(
                    id=row["id"],
                    name=row["name"],
                    filename=row["filename"],
                    file_type=row["file_type"],
                    record_count=row["record_count"],
                    file_size_bytes=row["file_size_bytes"],
                    fields=json.loads(row["fields_json"] or "[]"),
                    target_label_field=row["target_label_field"],
                    missing_values_count=row["missing_values_count"],
                    duplicate_count=row["duplicate_count"],
                    leakage_warnings=json.loads(row["leakage_warnings_json"] or "[]"),
                    source=row["source"],
                    license=row["license"],
                    provenance=row["provenance"],
                    permitted_use=row["permitted_use"],
                    train_split_count=row["train_split_count"],
                    val_split_count=row["val_split_count"],
                    test_split_count=row["test_split_count"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"]
                ))
            return results

    def delete_dataset(self, dataset_id: str) -> bool:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM datasets WHERE id = ?", (dataset_id,))
            conn.commit()
            return cursor.rowcount > 0

    # -------------------------------------------------------------
    # AI Training Jobs Management (Phase 5)
    # -------------------------------------------------------------
    def save_training_job(self, job: Any):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO ai_training_jobs (
                id, model_name, base_model, dataset_id, task_type, status,
                progress_percent, current_epoch, total_epochs, config_json,
                loss_history_json, accuracy_history_json, val_loss_history_json,
                val_accuracy_history_json, resource_usage_json, logs_json,
                checkpoint_path, model_artifact_path, started_at, completed_at,
                duration_seconds, error_message, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                job.id, job.config.model_name, job.config.base_model, job.config.dataset_id,
                job.config.task_type, job.status, job.progress_percent,
                job.current_epoch, job.total_epochs, job.config.model_dump_json(),
                json.dumps(job.loss_history), json.dumps(job.accuracy_history),
                json.dumps(job.val_loss_history), json.dumps(job.val_accuracy_history),
                json.dumps(job.resource_usage), json.dumps(job.logs),
                job.checkpoint_path, job.model_artifact_path, job.started_at,
                job.completed_at, job.duration_seconds, job.error_message, job.created_at
            ))
            conn.commit()

    def get_training_job(self, job_id: str) -> Optional[Any]:
        from core.ai_training import TrainingJob, TrainingConfig
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ai_training_jobs WHERE id = ?", (job_id,))
            row = cursor.fetchone()
            if not row:
                return None
            cfg_dict = json.loads(row["config_json"])
            return TrainingJob(
                id=row["id"],
                config=TrainingConfig(**cfg_dict),
                status=row["status"],
                progress_percent=row["progress_percent"],
                current_epoch=row["current_epoch"],
                total_epochs=row["total_epochs"],
                loss_history=json.loads(row["loss_history_json"] or "[]"),
                accuracy_history=json.loads(row["accuracy_history_json"] or "[]"),
                val_loss_history=json.loads(row["val_loss_history_json"] or "[]"),
                val_accuracy_history=json.loads(row["val_accuracy_history_json"] or "[]"),
                resource_usage=json.loads(row["resource_usage_json"] or "{}"),
                logs=json.loads(row["logs_json"] or "[]"),
                checkpoint_path=row["checkpoint_path"],
                model_artifact_path=row["model_artifact_path"],
                started_at=row["started_at"],
                completed_at=row["completed_at"],
                duration_seconds=row["duration_seconds"] or 0.0,
                error_message=row["error_message"],
                created_at=row["created_at"]
            )

    def list_training_jobs(self) -> List[Any]:
        from core.ai_training import TrainingJob, TrainingConfig
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ai_training_jobs ORDER BY created_at DESC")
            rows = cursor.fetchall()
            results = []
            for row in rows:
                cfg_dict = json.loads(row["config_json"])
                results.append(TrainingJob(
                    id=row["id"],
                    config=TrainingConfig(**cfg_dict),
                    status=row["status"],
                    progress_percent=row["progress_percent"],
                    current_epoch=row["current_epoch"],
                    total_epochs=row["total_epochs"],
                    loss_history=json.loads(row["loss_history_json"] or "[]"),
                    accuracy_history=json.loads(row["accuracy_history_json"] or "[]"),
                    val_loss_history=json.loads(row["val_loss_history_json"] or "[]"),
                    val_accuracy_history=json.loads(row["val_accuracy_history_json"] or "[]"),
                    resource_usage=json.loads(row["resource_usage_json"] or "{}"),
                    logs=json.loads(row["logs_json"] or "[]"),
                    checkpoint_path=row["checkpoint_path"],
                    model_artifact_path=row["model_artifact_path"],
                    started_at=row["started_at"],
                    completed_at=row["completed_at"],
                    duration_seconds=row["duration_seconds"] or 0.0,
                    error_message=row["error_message"],
                    created_at=row["created_at"]
                ))
            return results

    # -------------------------------------------------------------
    # AI Model Evaluations Management (Phase 6)
    # -------------------------------------------------------------
    def save_ai_evaluation(self, res: Any):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO ai_evaluations (
                id, model_name, baseline_model_name, dataset_id, task_type,
                test_sample_count, accuracy, precision, recall, f1_score,
                confusion_matrix_json, latency_ms_per_request, throughput_tokens_per_sec,
                prompt_tokens, completion_tokens, total_tokens, estimated_cost_usd,
                regression_detected, improvement_percent, comparison_summary, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                res.id, res.model_name, res.baseline_model_name, res.dataset_id, res.task_type,
                res.test_sample_count, res.accuracy, res.precision, res.recall, res.f1_score,
                res.confusion_matrix.model_dump_json(), res.latency_ms_per_request,
                res.throughput_tokens_per_sec, res.prompt_tokens, res.completion_tokens,
                res.total_tokens, res.estimated_cost_usd, 1 if res.regression_detected else 0,
                res.improvement_percent, res.comparison_summary, res.created_at
            ))
            conn.commit()

    def list_ai_evaluations(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ai_evaluations ORDER BY created_at DESC")
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                try:
                    item["confusion_matrix"] = json.loads(item["confusion_matrix_json"]) if item["confusion_matrix_json"] else {}
                except Exception:
                    item["confusion_matrix"] = {}
                results.append(item)
            return results

    # -------------------------------------------------------------
    # LLM Security Red-Teaming Results (Phase 7)
    # -------------------------------------------------------------
    def save_llm_security_test(self, item: Any):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO llm_security_tests (
                id, run_id, test_case_id, category, title, model_target,
                prompt_sent, expected_behavior, actual_response, status,
                severity, confidence, evidence, mitigation, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                item.id, item.run_id, item.test_case_id, item.category, item.title,
                item.model_target, item.prompt_sent, item.expected_behavior,
                item.actual_response, item.status, item.severity, item.confidence,
                item.evidence, item.mitigation, item.created_at
            ))
            conn.commit()

    def get_llm_security_tests(self, run_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if run_id:
                cursor.execute("SELECT * FROM llm_security_tests WHERE run_id = ? ORDER BY created_at ASC", (run_id,))
            else:
                cursor.execute("SELECT * FROM llm_security_tests ORDER BY created_at DESC LIMIT 200")
            rows = cursor.fetchall()
            return [dict(r) for r in rows]


    # -------------------------------------------------------------
    # Cyber Export Methods (Phase 8)
    # -------------------------------------------------------------
    def save_cyber_export(self, item: Dict[str, Any]):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
            INSERT OR REPLACE INTO cyber_exports (
                id, title, format, export_type, file_path, file_size,
                findings_count, filter_criteria, status, sha256, download_url, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                item.get('id'), item.get('title'), item.get('format'), item.get('export_type'),
                item.get('file_path'), item.get('file_size', 0), item.get('findings_count', 0),
                json.dumps(item.get('filter_criteria', {})) if isinstance(item.get('filter_criteria'), dict) else item.get('filter_criteria'),
                item.get('status', 'COMPLETED'), item.get('sha256', ''),
                item.get('download_url', ''), item.get('created_at', '')
            ))
            conn.commit()

    def get_cyber_exports(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM cyber_exports ORDER BY created_at DESC LIMIT ?', (limit,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_cyber_export_by_id(self, export_id: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM cyber_exports WHERE id = ?', (export_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    # -------------------------------------------------------------
    # Cyber Test Methods (Phase 9)
    # -------------------------------------------------------------
    def save_cyber_test_run(self, item: Dict[str, Any]):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
            INSERT OR REPLACE INTO cyber_test_runs (
                id, title, profile, status, total_tests, passed_count,
                failed_count, blocked_count, duration_seconds, summary, created_at, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                item.get('id'), item.get('title'), item.get('profile'), item.get('status'),
                item.get('total_tests', 0), item.get('passed_count', 0),
                item.get('failed_count', 0), item.get('blocked_count', 0),
                item.get('duration_seconds', 0.0), item.get('summary', ''),
                item.get('created_at'), item.get('completed_at')
            ))
            conn.commit()

    def get_cyber_test_runs(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM cyber_test_runs ORDER BY created_at DESC LIMIT ?', (limit,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_cyber_test_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM cyber_test_runs WHERE id = ?', (run_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def save_cyber_test_results(self, results: List[Dict[str, Any]]):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            for r in results:
                cursor.execute('''
                INSERT OR REPLACE INTO cyber_test_results (
                    id, run_id, test_id, test_name, category, status,
                    severity, duration_seconds, evidence, error_details, remediation, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    r.get('id'), r.get('run_id'), r.get('test_id'), r.get('test_name'),
                    r.get('category'), r.get('status'), r.get('severity', 'MEDIUM'),
                    r.get('duration_seconds', 0.0), r.get('evidence', ''),
                    r.get('error_details', ''), r.get('remediation', ''), r.get('created_at', '')
                ))
            conn.commit()

    def get_cyber_test_results(self, run_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if run_id:
                cursor.execute('SELECT * FROM cyber_test_results WHERE run_id = ? ORDER BY created_at ASC', (run_id,))
            else:
                cursor.execute('SELECT * FROM cyber_test_results ORDER BY created_at DESC LIMIT 200')
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    # -------------------------------------------------------------
    # Cyber Deploy Methods (Phase 10)
    # -------------------------------------------------------------
    def save_cyber_deployment(self, item: Dict[str, Any]):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
            INSERT OR REPLACE INTO cyber_deployments (
                id, release_id, environment, method, status, current_step,
                approved_by, approval_timestamp, health_status, logs, rollback_target, created_at, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                item.get('id'), item.get('release_id'), item.get('environment'),
                item.get('method'), item.get('status'), item.get('current_step'),
                item.get('approved_by'), item.get('approval_timestamp'),
                item.get('health_status', ''), item.get('logs', ''),
                item.get('rollback_target', ''), item.get('created_at'), item.get('completed_at')
            ))
            conn.commit()

    def get_cyber_deployments(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM cyber_deployments ORDER BY created_at DESC LIMIT ?', (limit,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_cyber_deployment(self, dep_id: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM cyber_deployments WHERE id = ?', (dep_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    # -------------------------------------------------------------
    # Cyber Audit Logs (Phase 11/16)
    # -------------------------------------------------------------
    def record_audit_log(self, action: str, actor: str = 'system', details: str = '', ip_address: str = '127.0.0.1') -> str:
        import datetime
        log_id = f"aud_{int(datetime.datetime.now().timestamp() * 1000)}"
        now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO cyber_audit_logs (id, action, actor, details, ip_address, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (log_id, action, actor, details, ip_address, now_ts))
            conn.commit()
        return log_id

    def get_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM cyber_audit_logs ORDER BY timestamp DESC LIMIT ?', (limit,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

db = Database()
