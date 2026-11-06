"""



SWA AI Database Store



Thread-safe SQLite storage for scans, vulnerability findings, logs, and system settings.



"""







import sqlite3



import json



import os



import uuid



import contextlib



import datetime



from typing import List, Optional, Dict, Any, Tuple



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



        conn.execute("PRAGMA foreign_keys = ON;")



        conn.execute("PRAGMA journal_mode = WAL;")



        try:



            with conn:



                yield conn



        finally:



            conn.close()







    def check_health(self) -> Dict[str, Any]:

        """Validates database connectivity and returns table integrity metrics."""

        try:

            with self.get_connection() as conn:

                cursor = conn.cursor()

                cursor.execute("SELECT COUNT(*) FROM scans")

                scans_count = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM findings")

                findings_count = cursor.fetchone()[0]

                cursor.execute("PRAGMA quick_check(1)")

                quick_check = cursor.fetchone()[0]

                return {

                    "status": "healthy" if quick_check == "ok" else "corrupt",

                    "database_path": os.path.abspath(self.db_path),

                    "scans_count": scans_count,

                    "findings_count": findings_count,

                    "journal_mode": "WAL",

                    "integrity": quick_check

                }

        except Exception as e:

            return {

                "status": "unhealthy",

                "database_path": os.path.abspath(self.db_path),

                "error": str(e)

            }





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



            if "confidence" not in existing_cols:



                try:



                    cursor.execute("ALTER TABLE findings ADD COLUMN confidence TEXT DEFAULT 'HIGH'")



                except Exception:



                    pass



            if "detection_method" not in existing_cols:



                try:



                    cursor.execute("ALTER TABLE findings ADD COLUMN detection_method TEXT DEFAULT 'AUTOMATED_PROBE'")



                except Exception:



                    pass



            if "affected_asset" not in existing_cols:



                try:



                    cursor.execute("ALTER TABLE findings ADD COLUMN affected_asset TEXT")



                except Exception:



                    pass



            if "reproduction_steps" not in existing_cols:



                try:



                    cursor.execute("ALTER TABLE findings ADD COLUMN reproduction_steps TEXT")



                except Exception:



                    pass



            if "impact" not in existing_cols:



                try:



                    cursor.execute("ALTER TABLE findings ADD COLUMN impact TEXT")



                except Exception:



                    pass



            if "lifecycle_status" not in existing_cols:



                try:



                    cursor.execute("ALTER TABLE findings ADD COLUMN lifecycle_status TEXT DEFAULT 'DISCOVERED'")



                except Exception:



                    pass



            if "owner" not in existing_cols:



                try:



                    cursor.execute("ALTER TABLE findings ADD COLUMN owner TEXT DEFAULT 'Unassigned'")



                except Exception:



                    pass



            if "triage_note" not in existing_cols:



                try:



                    cursor.execute("ALTER TABLE findings ADD COLUMN triage_note TEXT")



                except Exception:



                    pass



            if "suppression_reason" not in existing_cols:



                try:



                    cursor.execute("ALTER TABLE findings ADD COLUMN suppression_reason TEXT")



                except Exception:



                    pass



            if "risk_breakdown_json" not in existing_cols:



                try:



                    cursor.execute("ALTER TABLE findings ADD COLUMN risk_breakdown_json TEXT")



                except Exception:



                    pass



            if "epss_score" not in existing_cols:



                try:



                    cursor.execute("ALTER TABLE findings ADD COLUMN epss_score REAL DEFAULT 0.0")



                except Exception:



                    pass



            if "cisa_kev" not in existing_cols:



                try:



                    cursor.execute("ALTER TABLE findings ADD COLUMN cisa_kev INTEGER DEFAULT 0")



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



                status TEXT DEFAULT 'COMPLETED',



                status_reason TEXT,



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







            # Migrate ai_evaluations on databases created before the



            # honest-evaluation fields existed.



            cursor.execute("PRAGMA table_info(ai_evaluations)")



            eval_cols = {col[1] for col in cursor.fetchall()}



            if "status" not in eval_cols:



                try:



                    cursor.execute("ALTER TABLE ai_evaluations ADD COLUMN status TEXT DEFAULT 'COMPLETED'")



                except Exception:



                    pass



            if "status_reason" not in eval_cols:



                try:



                    cursor.execute("ALTER TABLE ai_evaluations ADD COLUMN status_reason TEXT")



                except Exception:



                    pass







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







            # Workspaces & Projects



            cursor.execute('''



            CREATE TABLE IF NOT EXISTS workspaces (



                id TEXT PRIMARY KEY,



                name TEXT NOT NULL,



                description TEXT,



                organization TEXT,



                created_at TEXT NOT NULL



            )



            ''')







            cursor.execute('''



            CREATE TABLE IF NOT EXISTS projects (



                id TEXT PRIMARY KEY,



                workspace_id TEXT NOT NULL,



                name TEXT NOT NULL,



                description TEXT,



                authorized_domains TEXT,



                business_criticality TEXT DEFAULT 'HIGH',



                owner TEXT,



                created_at TEXT NOT NULL,



                FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE



            )



            ''')







            # Global Application Security Context



            cursor.execute('''



            CREATE TABLE IF NOT EXISTS global_contexts (



                user_id TEXT PRIMARY KEY,



                workspace_id TEXT NOT NULL,



                workspace_name TEXT,



                project_id TEXT NOT NULL,



                project_name TEXT,



                target TEXT,



                target_authorized INTEGER DEFAULT 1,



                updated_at TEXT



            )



            ''')







            # Human-in-the-Loop Approval Requests



            cursor.execute('''



            CREATE TABLE IF NOT EXISTS approval_requests (



                id TEXT PRIMARY KEY,



                action_type TEXT NOT NULL,



                target TEXT NOT NULL,



                requested_by TEXT NOT NULL,



                agent_role TEXT,



                rationale TEXT NOT NULL,



                impact_assessment TEXT,



                scope_details_json TEXT,



                status TEXT NOT NULL,



                decided_by TEXT,



                decision_reason TEXT,



                created_at TEXT NOT NULL,



                decided_at TEXT



            )



            ''')







            # Security Knowledge Graph Nodes & Edges



            cursor.execute('''



            CREATE TABLE IF NOT EXISTS knowledge_nodes (



                id TEXT PRIMARY KEY,



                type TEXT NOT NULL,



                label TEXT NOT NULL,



                properties_json TEXT,



                criticality TEXT,



                created_at TEXT NOT NULL



            )



            ''')







            cursor.execute('''



            CREATE TABLE IF NOT EXISTS knowledge_edges (



                id TEXT PRIMARY KEY,



                source_id TEXT NOT NULL,



                target_id TEXT NOT NULL,



                relationship TEXT NOT NULL,



                properties_json TEXT,



                created_at TEXT NOT NULL



            )



            ''')







            # Continuous Attack Surface Intelligence (EASM Drift)



            cursor.execute('''



            CREATE TABLE IF NOT EXISTS asset_drift_events (



                id TEXT PRIMARY KEY,



                project_id TEXT NOT NULL,



                target TEXT NOT NULL,



                asset_name TEXT NOT NULL,



                drift_type TEXT NOT NULL,



                title TEXT NOT NULL,



                description TEXT,



                previous_state_json TEXT,



                current_state_json TEXT,



                confidence TEXT DEFAULT 'CONFIRMED',



                is_genuine_change INTEGER DEFAULT 1,



                detected_at TEXT NOT NULL



            )



            ''')







            # Remediation Lifecycle Tickets



            cursor.execute('''



            CREATE TABLE IF NOT EXISTS remediation_tickets (



                id TEXT PRIMARY KEY,



                finding_id TEXT NOT NULL,



                scan_id TEXT NOT NULL,



                target TEXT NOT NULL,



                title TEXT NOT NULL,



                severity TEXT NOT NULL,



                lifecycle_status TEXT NOT NULL,



                owner TEXT DEFAULT 'Unassigned',



                due_date TEXT,



                patch_code TEXT,



                mitigation_guidance TEXT,



                retest_status TEXT,



                retest_evidence TEXT,



                suppression_reason TEXT,



                history_json TEXT,



                created_at TEXT NOT NULL,



                updated_at TEXT NOT NULL



            )



            ''')







            # 12-Template Enterprise Report Records



            cursor.execute('''



            CREATE TABLE IF NOT EXISTS report_records (



                id TEXT PRIMARY KEY,



                template_type TEXT NOT NULL,



                title TEXT NOT NULL,



                target TEXT NOT NULL,



                scan_id TEXT,



                format TEXT NOT NULL,



                summary TEXT,



                findings_count INTEGER DEFAULT 0,



                risk_score REAL DEFAULT 0.0,



                generated_by TEXT,



                content TEXT NOT NULL,



                created_at TEXT NOT NULL



            )



            ''')

            # Professional Vulnerability Assessment Reports (Nessus-Style Engine)
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerability_assessment_reports (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                report_type TEXT NOT NULL,
                template_type TEXT NOT NULL,
                scan_id TEXT,
                target_scope TEXT NOT NULL,
                grouping_mode TEXT DEFAULT 'host',
                format TEXT NOT NULL,
                status TEXT DEFAULT 'COMPLETED',
                findings_count INTEGER DEFAULT 0,
                file_path TEXT,
                file_size INTEGER DEFAULT 0,
                config_json TEXT,
                created_by TEXT DEFAULT 'SWA Vulnerability Assessment Engine',
                created_at TEXT NOT NULL
            )
            ''')








            # Multi-Agent Workforce Task Execution History



            cursor.execute('''



            CREATE TABLE IF NOT EXISTS agent_tasks (



                id TEXT PRIMARY KEY,



                agent_role TEXT NOT NULL,



                scan_id TEXT NOT NULL,



                title TEXT NOT NULL,



                status TEXT NOT NULL,



                inputs_json TEXT,



                outputs_json TEXT,



                evidence_json TEXT,



                error_message TEXT,



                started_at TEXT,



                completed_at TEXT,



                duration_seconds REAL



            )



            ''')







            # Autonomous Cybersecurity 85-Agent Inventory



            cursor.execute('''



            CREATE TABLE IF NOT EXISTS agents_inventory (



                id TEXT PRIMARY KEY,



                name TEXT NOT NULL,



                role TEXT NOT NULL,



                tier TEXT NOT NULL,



                category TEXT NOT NULL,



                description TEXT,



                module_path TEXT NOT NULL,



                class_name TEXT NOT NULL,



                status TEXT NOT NULL,



                version TEXT DEFAULT '2.2.0',



                capabilities_json TEXT,



                responsibilities_json TEXT,



                permission_boundary_json TEXT,



                installed INTEGER DEFAULT 1,



                available INTEGER DEFAULT 1,



                last_executed TEXT,



                last_result TEXT,



                created_at TEXT DEFAULT CURRENT_TIMESTAMP



            )



            ''')



            cursor.execute('CREATE INDEX IF NOT EXISTS idx_agents_tier ON agents_inventory(tier)')



            cursor.execute('CREATE INDEX IF NOT EXISTS idx_agents_category ON agents_inventory(category)')



            # AI Agents configuration and custom integration table

            cursor.execute('''

            CREATE TABLE IF NOT EXISTS ai_agents (

                id TEXT PRIMARY KEY,

                name TEXT NOT NULL,

                provider TEXT NOT NULL,

                model TEXT NOT NULL,

                base_url TEXT,

                api_key_encrypted TEXT,

                api_key_masked TEXT,

                description TEXT,

                role TEXT DEFAULT 'Cybersecurity Specialist',

                enabled INTEGER DEFAULT 1,

                is_default INTEGER DEFAULT 0,

                connection_status TEXT DEFAULT 'DISCONNECTED',

                last_tested_at TEXT,

                last_error TEXT,

                created_at TEXT DEFAULT CURRENT_TIMESTAMP,

                updated_at TEXT DEFAULT CURRENT_TIMESTAMP

            )

            ''')

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ai_agents_provider ON ai_agents(provider)')

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ai_agents_is_default ON ai_agents(is_default)')



            cursor.execute("SELECT COUNT(*) FROM ai_agents")

            if cursor.fetchone()[0] == 0:

                cursor.execute("""

                INSERT INTO ai_agents (

                    id, name, provider, model, base_url, api_key_encrypted, api_key_masked,

                    description, role, enabled, is_default, connection_status, created_at, updated_at

                ) VALUES (

                    'agent_default_swa',

                    'SWA Autonomous Cyber Copilot',

                    'heuristic',

                    'swa-cyber-reasoning-v2',

                    NULL,

                    '',

                    'built-in (no key required)',

                    'Native high-precision deterministic security reasoning agent with full OWASP and zero false-positive evaluation.',

                    'Senior Penetration Tester & Security Architect',

                    1,

                    1,

                    'CONNECTED',

                    CURRENT_TIMESTAMP,

                    CURRENT_TIMESTAMP

                )

                """)







            # Seed default workspace and project if not present



            cursor.execute("SELECT COUNT(*) FROM workspaces")



            if cursor.fetchone()[0] == 0:



                cursor.execute("""



                INSERT INTO workspaces (id, name, description, organization, created_at)



                VALUES ('ws_default', 'Default Enterprise', 'Primary SWA security testing and production monitoring workspace', 'Enterprise Security Inc.', datetime('now'))



                """)



                cursor.execute("""



                INSERT INTO projects (id, workspace_id, name, description, authorized_domains, business_criticality, owner, created_at)



                VALUES ('proj_default', 'ws_default', 'Core Infrastructure', 'Production web services, API gateways, and external perimeter', '["127.0.0.1:8000", "localhost", "*.internal.corp"]', 'CRITICAL', 'SecOps Lead', datetime('now'))



                """)



                cursor.execute("""



                INSERT INTO global_contexts (user_id, workspace_id, workspace_name, project_id, project_name, target, target_authorized, updated_at)



                VALUES ('default_user', 'ws_default', 'Default Enterprise', 'proj_default', 'Core Infrastructure', '127.0.0.1:8000', 1, datetime('now'))



                """)







            



            # Performance & Query Indexes



            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans (status);")



            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC);")



            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings (scan_id);")



            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity);")



            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_endpoint ON findings (endpoint);")



            cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_scan_id ON logs (scan_id);")



            cursor.execute("CREATE INDEX IF NOT EXISTS idx_assets_subdomain ON assets (subdomain);")



            cursor.execute("CREATE INDEX IF NOT EXISTS idx_assets_parent ON assets (parent_domain);")



            cursor.execute("CREATE INDEX IF NOT EXISTS idx_knowledge_nodes_type ON knowledge_nodes (type);")



            cursor.execute("CREATE INDEX IF NOT EXISTS idx_knowledge_edges_source ON knowledge_edges (source_id);")



            cursor.execute("CREATE INDEX IF NOT EXISTS idx_knowledge_edges_target ON knowledge_edges (target_id);")



            cursor.execute("CREATE INDEX IF NOT EXISTS idx_remediation_lifecycle ON remediation_tickets (lifecycle_status);")



            cursor.execute("CREATE INDEX IF NOT EXISTS idx_remediation_finding ON remediation_tickets (finding_id);")



            cursor.execute("CREATE INDEX IF NOT EXISTS idx_drift_project ON asset_drift_events (project_id);")



            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON cyber_audit_logs (timestamp DESC);")







            

            # Incident Management Table (Blue Team Ops)

            cursor.execute("""

            CREATE TABLE IF NOT EXISTS incidents (

                id TEXT PRIMARY KEY,

                title TEXT NOT NULL,

                severity TEXT NOT NULL,

                status TEXT NOT NULL DEFAULT 'NEW',

                assigned_analyst TEXT DEFAULT 'Unassigned',

                affected_assets TEXT,

                description TEXT,

                timeline_json TEXT,

                containment_actions_json TEXT,

                lessons_learned TEXT,

                created_at TEXT NOT NULL,

                updated_at TEXT

            );

            """)



            # Detection Rules Table (SIEM / EDR / Heuristics)

            cursor.execute("""

            CREATE TABLE IF NOT EXISTS detection_rules (

                id TEXT PRIMARY KEY,

                name TEXT NOT NULL,

                severity TEXT NOT NULL,

                rule_type TEXT NOT NULL,

                rule_content TEXT NOT NULL,

                category TEXT NOT NULL,

                enabled INTEGER DEFAULT 1,

                trigger_count INTEGER DEFAULT 0,

                created_at TEXT NOT NULL,

                updated_at TEXT

            );

            """)



            # Live Security Events Stream Table

            cursor.execute("""

            CREATE TABLE IF NOT EXISTS security_events (

                id TEXT PRIMARY KEY,

                source TEXT NOT NULL,

                event_type TEXT NOT NULL,

                severity TEXT NOT NULL,

                target_asset TEXT,

                details_json TEXT,

                timestamp TEXT NOT NULL

            );

            """)



            # Threat Intelligence Indicators (IOCs) Table

            cursor.execute("""

            CREATE TABLE IF NOT EXISTS threat_indicators (

                id TEXT PRIMARY KEY,

                indicator_value TEXT NOT NULL,

                indicator_type TEXT NOT NULL,

                reputation_score INTEGER DEFAULT 0,

                source_feed TEXT NOT NULL,

                confidence REAL DEFAULT 0.8,

                description TEXT,

                first_seen TEXT NOT NULL,

                last_seen TEXT NOT NULL

            );

            """)



            # Cloud Assets Table (AWS / Azure / GCP)

            cursor.execute("""

            CREATE TABLE IF NOT EXISTS cloud_assets (

                id TEXT PRIMARY KEY,

                provider TEXT NOT NULL,

                account_id TEXT,

                region TEXT NOT NULL,

                service_type TEXT NOT NULL,

                resource_id TEXT NOT NULL,

                resource_name TEXT NOT NULL,

                exposure_level TEXT NOT NULL,

                misconfiguration_findings_count INTEGER DEFAULT 0,

                last_synced TEXT NOT NULL

            );

            """)



            # Container Assets Table (Docker / Kubernetes / Registries)

            cursor.execute("""

            CREATE TABLE IF NOT EXISTS container_assets (

                id TEXT PRIMARY KEY,

                image_name TEXT NOT NULL,

                tag TEXT NOT NULL,

                digest TEXT NOT NULL,

                registry TEXT NOT NULL,

                critical_vulns INTEGER DEFAULT 0,

                high_vulns INTEGER DEFAULT 0,

                medium_vulns INTEGER DEFAULT 0,

                sbom_generated INTEGER DEFAULT 0,

                scan_status TEXT NOT NULL,

                last_scanned TEXT NOT NULL

            );

            """)



            # Indexes for new enterprise tables

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);")

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents (severity);")

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_detection_rules_enabled ON detection_rules (enabled);")

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_timestamp ON security_events (timestamp DESC);")

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_indicators_type ON threat_indicators (indicator_type);")

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_assets_provider ON cloud_assets (provider);")

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_container_assets_status ON container_assets (scan_status);")



            # Seed initial operational records if empty

            cursor.execute("SELECT COUNT(*) FROM incidents;")

            if cursor.fetchone()[0] == 0:

                cursor.execute("""

                INSERT INTO incidents (id, title, severity, status, assigned_analyst, affected_assets, description, timeline_json, containment_actions_json, created_at, updated_at)

                VALUES 

                ('inc_2026_001', 'Credential Spraying Detected on Internal SSO', 'HIGH', 'INVESTIGATING', 'SecOps Lead', 'api.internal.swa, auth.swa.local', 'Repeated failed authentication bursts originating from suspicious subnet 198.51.100.0/24.', '[{"time":"2026-11-04T05:12:00Z","entry":"Alert triggered by Auth Rate Limiter Rule"},{"time":"2026-11-04T05:20:00Z","entry":"Analyst assigned; IP block submitted to WAF"}]', '["Enforced temporary IP blacklist on edge gateway", "Forced MFA session invalidation for 14 targeted accounts"]', '2026-11-04T05:12:00Z', '2026-11-04T05:25:00Z'),

                ('inc_2026_002', 'High-Entropy Secret Discovered in Public S3 Bucket', 'CRITICAL', 'CONTAINED', 'Cloud Security Architect', 's3://prod-swa-telemetry-exports', 'AWS IAM access key and PostgreSQL connection URI exposed in unauthenticated read bucket.', '[{"time":"2026-11-03T18:04:00Z","entry":"Discovered during automated EASM bucket discovery run"},{"time":"2026-11-03T18:15:00Z","entry":"Bucket ACL modified to Block Public Access"}]', '["Applied S3 Block Public Access", "Rotated compromised IAM credentials in Secrets Manager"]', '2026-11-03T18:04:00Z', '2026-11-03T18:30:00Z');

                """)



            cursor.execute("SELECT COUNT(*) FROM detection_rules;")

            if cursor.fetchone()[0] == 0:

                cursor.execute("""

                INSERT INTO detection_rules (id, name, severity, rule_type, rule_content, category, enabled, trigger_count, created_at, updated_at)

                VALUES

                ('rule_sql_union_01', 'Generic SQLi UNION SELECT Injection Detection', 'HIGH', 'SIGMA', 'selection:\n  http.uri|contains: ["UNION SELECT", "UNION ALL SELECT"]\ncondition: selection', 'Web Application Security', 1, 14, '2026-10-15T00:00:00Z', '2026-11-01T00:00:00Z'),

                ('rule_ssrf_imds_01', 'Cloud Metadata IMDS v1 Exfiltration Attempt', 'CRITICAL', 'SIGMA', 'selection:\n  http.request.body|contains: ["169.254.169.254", "latest/meta-data"]\ncondition: selection', 'Cloud & SSRF', 1, 28, '2026-10-15T00:00:00Z', '2026-11-01T00:00:00Z'),

                ('rule_jwt_none_01', 'JWT alg:none Signature Bypass Pattern', 'HIGH', 'SWA_HEURISTIC', 'pattern: "eyJhbGciOiAibm9uZSI" in auth_header', 'Identity & Access', 1, 6, '2026-10-20T00:00:00Z', '2026-11-01T00:00:00Z');

                """)



            cursor.execute("SELECT COUNT(*) FROM threat_indicators;")

            if cursor.fetchone()[0] == 0:

                cursor.execute("""

                INSERT INTO threat_indicators (id, indicator_value, indicator_type, reputation_score, source_feed, confidence, description, first_seen, last_seen)

                VALUES

                ('ioc_001', '198.51.100.45', 'IP', 92, 'AbuseIPDB', 0.95, 'High-volume SSH brute force attacker', '2026-10-25T12:00:00Z', '2026-11-04T05:00:00Z'),

                ('ioc_002', 'malicious-c2-update.top', 'DOMAIN', 88, 'AlienVault OTX', 0.90, 'Cobalt Strike C2 beacon domain', '2026-10-28T08:30:00Z', '2026-11-03T19:00:00Z'),

                ('ioc_003', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'HASH_SHA256', 99, 'VirusTotal', 0.99, 'Known LockBit 3.0 ransomware builder payload', '2026-10-12T00:00:00Z', '2026-11-02T14:00:00Z');

                """)



            cursor.execute("SELECT COUNT(*) FROM cloud_assets;")

            if cursor.fetchone()[0] == 0:

                cursor.execute("""

                INSERT INTO cloud_assets (id, provider, account_id, region, service_type, resource_id, resource_name, exposure_level, misconfiguration_findings_count, last_synced)

                VALUES

                ('cld_001', 'AWS', '123456789012', 'us-east-1', 'S3', 'arn:aws:s3:::prod-swa-telemetry-exports', 'prod-swa-telemetry-exports', 'RESTRICTED', 0, '2026-11-04T06:00:00Z'),

                ('cld_002', 'AWS', '123456789012', 'us-east-1', 'EC2', 'i-0ab12cd34ef567890', 'swa-core-api-primary', 'INTERNAL', 1, '2026-11-04T06:00:00Z'),

                ('cld_003', 'GCP', 'swa-enterprise-prod', 'us-central1', 'CloudSQL', 'projects/swa-enterprise-prod/instances/swa-db-pg', 'swa-db-pg', 'INTERNAL', 0, '2026-11-04T06:00:00Z');

                """)



            

            # 
            # Additive migration for report_records table
            cursor.execute("PRAGMA table_info(report_records);")
            existing_rr_cols = {col[1] for col in cursor.fetchall()}
            additive_rr_cols = [
                ("file_path", "TEXT"),
                ("file_size", "INTEGER DEFAULT 0"),
                ("grouping_mode", "TEXT DEFAULT 'host'"),
                ("config_json", "TEXT"),
                ("status", "TEXT DEFAULT 'COMPLETED'"),
                ("report_type", "TEXT DEFAULT 'detailed_technical'")
            ]
            for col_name, col_def in additive_rr_cols:
                if col_name not in existing_rr_cols:
                    cursor.execute(f"ALTER TABLE report_records ADD COLUMN {col_name} {col_def};")

            # ditive migration for findings table (Vulnerabilities & Findings Module)

            cursor.execute("PRAGMA table_info(findings);")

            existing_f_cols = {col[1] for col in cursor.fetchall()}

            additive_f_cols = [

                ("verification_status", "TEXT DEFAULT 'NEEDS_VALIDATION'"),

                ("remediation_status", "TEXT DEFAULT 'OPEN'"),

                ("cvss_version", "TEXT DEFAULT '3.1'"),

                ("cve_id", "TEXT DEFAULT ''"),

                ("cisco_sir", "TEXT DEFAULT ''"),

                ("poc_verification_state", "TEXT DEFAULT 'SCANNER DETECTED'"),

                ("poc_verification_evidence", "TEXT DEFAULT ''"),

                ("reviewer", "TEXT DEFAULT ''"),

                ("false_positive_reason", "TEXT DEFAULT ''"),

                ("last_status_change", "TEXT DEFAULT ''"),

            ]

            for col_name, col_def in additive_f_cols:

                if col_name not in existing_f_cols:

                    cursor.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_def};")



            # Table for full status audit trail (§5 Status Transition Rules)

            cursor.execute("""

            CREATE TABLE IF NOT EXISTS finding_status_history (

                id TEXT PRIMARY KEY,

                finding_id TEXT NOT NULL,

                previous_status TEXT,

                new_status TEXT NOT NULL,

                status_type TEXT DEFAULT 'LIFECYCLE',

                change_reason TEXT,

                supporting_evidence TEXT,

                responsible_actor TEXT,

                approval_reference TEXT,

                timestamp TEXT NOT NULL,

                FOREIGN KEY(finding_id) REFERENCES findings(id)

            );

            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_fsh_finding ON finding_status_history(finding_id);")

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_fsh_timestamp ON finding_status_history(timestamp);")



            # Safe initial data population for existing findings

            cursor.execute("""

                UPDATE findings 

                SET verification_status = CASE WHEN verified = 1 THEN 'CONFIRMED' ELSE 'NEEDS_VALIDATION' END

                WHERE verification_status IS NULL OR verification_status = '' OR verification_status = 'NEEDS_VALIDATION';

            """)

            cursor.execute("""

                UPDATE findings 

                SET remediation_status = 'OPEN'

                WHERE remediation_status IS NULL OR remediation_status = '';

            """)

            cursor.execute("""

                UPDATE findings 

                SET poc_verification_state = CASE 

                    WHEN poc_curl IS NOT NULL AND length(trim(poc_curl)) > 5 AND verified = 1 THEN 'PoC VERIFIED'

                    WHEN (request_evidence IS NOT NULL AND length(trim(request_evidence)) > 5) THEN 'EVIDENCE VERIFIED'

                    ELSE 'SCANNER DETECTED' 

                END

                WHERE poc_verification_state IS NULL OR poc_verification_state = '' OR poc_verification_state = 'SCANNER DETECTED';

            """)

            cursor.execute("""

                UPDATE findings 

                SET cvss_version = '3.1'

                WHERE cvss_version IS NULL OR cvss_version = '';

            """)



            # Ensure baseline audit history exists

            cursor.execute("SELECT COUNT(*) FROM finding_status_history;")

            if cursor.fetchone()[0] == 0:

                cursor.execute("""

                INSERT INTO finding_status_history (id, finding_id, previous_status, new_status, status_type, change_reason, supporting_evidence, responsible_actor, timestamp)

                SELECT 

                    'fsh_' || substr(id, 1, 8) || '_' || substr(hex(randomblob(4)), 1, 8),

                    id,

                    'DISCOVERED',

                    CASE WHEN verified = 1 THEN 'CONFIRMED' ELSE 'NEEDS_VALIDATION' END,

                    'LIFECYCLE',

                    'Baseline platform discovery and automated verification',

                    coalesce(poc_curl, detection_method, 'Automated scanner probe'),

                    'Autonomous Recon Engine',

                    coalesce(created_at, datetime('now'))

                FROM findings;

                """)



            cursor.execute("SELECT COUNT(*) FROM container_assets;")

            if cursor.fetchone()[0] == 0:

                cursor.execute("""

                INSERT INTO container_assets (id, image_name, tag, digest, registry, critical_vulns, high_vulns, medium_vulns, sbom_generated, scan_status, last_scanned)

                VALUES

                ('cnt_001', 'swa-ai/core-engine', 'v2.3.0', 'sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069', 'ghcr.io', 0, 0, 2, 1, 'SCANNED', '2026-11-04T06:00:00Z'),

                ('cnt_002', 'swa-ai/frontend-soc', 'v2.3.0', 'sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b', 'ghcr.io', 0, 0, 1, 1, 'SCANNED', '2026-11-04T06:00:00Z');

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







    def list_scans(self, limit: Optional[int] = None) -> List[ScanJob]:



        with self.get_connection() as conn:



            cursor = conn.cursor()



            query = "SELECT * FROM scans ORDER BY created_at DESC"



            if limit:



                query += f" LIMIT {int(limit)}"



            cursor.execute(query)



            rows = cursor.fetchall()



            return [self._row_to_scan(r) for r in rows]







    def get_scans(self, limit: Optional[int] = None) -> List[ScanJob]:



        return self.list_scans(limit=limit)







    def get_findings_by_scan(self, scan_id: str) -> List[VulnerabilityFinding]:



        return self.list_findings(scan_id=scan_id)







    def delete_scan(self, scan_id: str) -> bool:



        with self.get_connection() as conn:



            cursor = conn.cursor()



            cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))



            cursor.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))



            cursor.execute("DELETE FROM logs WHERE scan_id = ?", (scan_id,))



            conn.commit()



            return cursor.rowcount > 0







    def add_finding(self, finding: VulnerabilityFinding):



        from core.app_security import redact_sensitive_evidence



        # Evidence protection: redact sensitive credentials before persistence



        clean_poc = redact_sensitive_evidence(finding.poc_curl)



        clean_req = redact_sensitive_evidence(finding.request_evidence)



        clean_resp = redact_sensitive_evidence(finding.response_evidence)







        with self.get_connection() as conn:



            cursor = conn.cursor()



            if finding.scan_id:



                cursor.execute("SELECT 1 FROM scans WHERE id = ?", (finding.scan_id,))



                if not cursor.fetchone():



                    cursor.execute("""



                    INSERT OR IGNORE INTO scans (id, target_url, status, profile, created_at)



                    VALUES (?, 'standalone-test-target', 'COMPLETED', 'standard', datetime('now'))



                    """, (finding.scan_id,))



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



                clean_poc, finding.poc_explanation, clean_req,



                clean_resp, finding.remediation_advice, finding.remediation_patch,



                1 if finding.verified else 0,



                finding.confidence,



                finding.detection_method,



                finding.affected_asset,



                finding.reproduction_steps,



                finding.impact,



                finding.created_at



            ))



            conn.commit()



            l_status = getattr(finding, "lifecycle_status", None) or "NEW"
            r_status = getattr(finding, "remediation_status", None) or "OPEN"
            p_state = getattr(finding, "poc_verification_state", None) or ("POC VERIFIED" if clean_poc else "SCANNER DETECTED")
            cursor.execute("""
                UPDATE findings 
                SET lifecycle_status = ?, verification_status = ?, remediation_status = ?, poc_verification_state = ?
                WHERE id = ?;
            """, (l_status, l_status, r_status, p_state, finding.id))
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



            if event.scan_id:



                cursor.execute("SELECT 1 FROM scans WHERE id = ?", (event.scan_id,))



                if not cursor.fetchone():



                    cursor.execute("""



                    INSERT OR IGNORE INTO scans (id, target_url, status, profile, created_at)



                    VALUES (?, 'standalone-test-target', 'COMPLETED', 'standard', datetime('now'))



                    """, (event.scan_id,))



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

        l_status = row["lifecycle_status"] if "lifecycle_status" in keys and row["lifecycle_status"] else "NEW"

        v_status = row["verification_status"] if "verification_status" in keys and row["verification_status"] else ("CONFIRMED" if bool(row["verified"]) else "NEEDS_VALIDATION")

        r_status = row["remediation_status"] if "remediation_status" in keys and row["remediation_status"] else "OPEN"

        c_ver = row["cvss_version"] if "cvss_version" in keys and row["cvss_version"] else "3.1"

        cve = row["cve_id"] if "cve_id" in keys and row["cve_id"] else None

        sir = row["cisco_sir"] if "cisco_sir" in keys and row["cisco_sir"] else None

        epss = row["epss_score"] if "epss_score" in keys and row["epss_score"] is not None else None

        poc_state = row["poc_verification_state"] if "poc_verification_state" in keys and row["poc_verification_state"] else (

            "PoC VERIFIED" if (row["poc_curl"] and bool(row["verified"])) else "SCANNER DETECTED"

        )

        poc_ev = row["poc_verification_evidence"] if "poc_verification_evidence" in keys and row["poc_verification_evidence"] else None

        rev = row["reviewer"] if "reviewer" in keys and row["reviewer"] else None

        fp_reason = row["false_positive_reason"] if "false_positive_reason" in keys and row["false_positive_reason"] else None

        lsc = row["last_status_change"] if "last_status_change" in keys and row["last_status_change"] else None



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



            created_at=row["created_at"],



            lifecycle_status=l_status,



            verification_status=v_status,



            remediation_status=r_status,



            cvss_version=c_ver,



            cve_id=cve,



            cisco_sir=sir,



            epss_score=epss,



            poc_verification_state=poc_state,



            poc_verification_evidence=poc_ev,



            reviewer=rev,



            false_positive_reason=fp_reason,



            last_status_change=lsc



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



                status, status_reason, test_sample_count, accuracy, precision, recall, f1_score,



                confusion_matrix_json, latency_ms_per_request, throughput_tokens_per_sec,



                prompt_tokens, completion_tokens, total_tokens, estimated_cost_usd,



                regression_detected, improvement_percent, comparison_summary, created_at



            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)



            """, (



                res.id, res.model_name, res.baseline_model_name, res.dataset_id, res.task_type,



                getattr(res, "status", "COMPLETED"), getattr(res, "status_reason", None),



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











    # -------------------------------------------------------------



    # Enterprise Workspace & Project Methods



    # -------------------------------------------------------------



    def get_workspaces(self) -> List[Dict[str, Any]]:



        with self.get_connection() as conn:



            cursor = conn.cursor()



            cursor.execute("SELECT * FROM workspaces ORDER BY created_at ASC")



            return [dict(r) for r in cursor.fetchall()]







    def get_workspace(self, workspace_id: str) -> Optional[Dict[str, Any]]:



        with self.get_connection() as conn:



            cursor = conn.cursor()



            cursor.execute("SELECT * FROM workspaces WHERE id = ?", (workspace_id,))



            row = cursor.fetchone()



            return dict(row) if row else None







    def save_workspace(self, workspace: Dict[str, Any]):



        with self.get_connection() as conn:



            cursor = conn.cursor()



            cursor.execute('''



            INSERT OR REPLACE INTO workspaces (id, name, description, organization, created_at)



            VALUES (?, ?, ?, ?, ?)



            ''', (workspace.get("id"), workspace.get("name"), workspace.get("description", ""),



                  workspace.get("organization", "Enterprise Security"),



                  workspace.get("created_at", datetime.datetime.now(datetime.timezone.utc).isoformat())))



            conn.commit()







    def get_projects(self, workspace_id: Optional[str] = None) -> List[Dict[str, Any]]:



        with self.get_connection() as conn:



            cursor = conn.cursor()



            if workspace_id:



                cursor.execute("SELECT * FROM projects WHERE workspace_id = ? ORDER BY created_at ASC", (workspace_id,))



            else:



                cursor.execute("SELECT * FROM projects ORDER BY created_at ASC")



            return [dict(r) for r in cursor.fetchall()]







    def get_project(self, project_id: str) -> Optional[Dict[str, Any]]:



        with self.get_connection() as conn:



            cursor = conn.cursor()



            cursor.execute("SELECT * FROM projects WHERE id = ?", (project_id,))



            row = cursor.fetchone()



            return dict(row) if row else None







    def save_project(self, project: Dict[str, Any]):



        with self.get_connection() as conn:



            cursor = conn.cursor()



            cursor.execute('''



            INSERT OR REPLACE INTO projects (id, workspace_id, name, description, authorized_domains, business_criticality, owner, created_at)



            VALUES (?, ?, ?, ?, ?, ?, ?, ?)



            ''', (project.get("id"), project.get("workspace_id", "ws_default"), project.get("name"),



                  project.get("description", ""), json.dumps(project.get("authorized_domains", [])),



                  project.get("business_criticality", "HIGH"), project.get("owner", "Security Team"),



                  project.get("created_at", datetime.datetime.now(datetime.timezone.utc).isoformat())))



            conn.commit()







    # -------------------------------------------------------------



    # Global Security Context Methods



    # -------------------------------------------------------------



    def get_global_context(self, user_id: str = "default_user") -> Dict[str, Any]:



        with self.get_connection() as conn:



            cursor = conn.cursor()



            cursor.execute("SELECT * FROM global_contexts WHERE user_id = ?", (user_id,))



            row = cursor.fetchone()



            if row:



                res = dict(row)



                res["target_authorized"] = bool(res.get("target_authorized", 1))



                return res



            return {



                "user_id": user_id,



                "workspace_id": "ws_default",



                "workspace_name": "Default Enterprise",



                "project_id": "proj_default",



                "project_name": "Core Infrastructure",



                "target": "127.0.0.1:8000",



                "target_authorized": True,



                "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()



            }







    def save_global_context(self, context: Dict[str, Any], user_id: str = "default_user"):



        with self.get_connection() as conn:



            cursor = conn.cursor()



            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()



            cursor.execute('''



            INSERT OR REPLACE INTO global_contexts (user_id, workspace_id, workspace_name, project_id, project_name, target, target_authorized, updated_at)



            VALUES (?, ?, ?, ?, ?, ?, ?, ?)



            ''', (



                user_id,



                context.get("workspace_id", "ws_default"),



                context.get("workspace_name", "Default Enterprise"),



                context.get("project_id", "proj_default"),



                context.get("project_name", "Core Infrastructure"),



                context.get("target", "127.0.0.1:8000"),



                1 if context.get("target_authorized", True) else 0,



                now_iso



            ))



            conn.commit()







    # -------------------------------------------------------------



    # Human-in-the-Loop Approval Gates



    # -------------------------------------------------------------



    def create_approval_request(self, req: Dict[str, Any]) -> str:



        with self.get_connection() as conn:



            cursor = conn.cursor()



            cursor.execute('''



            INSERT INTO approval_requests (id, action_type, target, requested_by, agent_role, rationale, impact_assessment, scope_details_json, status, created_at)



            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)



            ''', (



                req.get("id"),



                req.get("action_type"),



                req.get("target"),



                req.get("requested_by", "SWA AI Orchestrator"),



                req.get("agent_role"),



                req.get("rationale", ""),



                req.get("impact_assessment", ""),



                json.dumps(req.get("scope_details", {})),



                req.get("status", "PENDING"),



                req.get("created_at", datetime.datetime.now(datetime.timezone.utc).isoformat())



            ))



            conn.commit()



            return req.get("id")







    def get_approval_requests(self, status: Optional[str] = None) -> List[Dict[str, Any]]:



        with self.get_connection() as conn:



            cursor = conn.cursor()



            if status:



                cursor.execute("SELECT * FROM approval_requests WHERE status = ? ORDER BY created_at DESC", (status,))



            else:



                cursor.execute("SELECT * FROM approval_requests ORDER BY created_at DESC")



            rows = cursor.fetchall()



            results = []



            for r in rows:



                d = dict(r)



                try:



                    d["scope_details"] = json.loads(d.get("scope_details_json") or "{}")



                except Exception:



                    d["scope_details"] = {}



                results.append(d)



            return results







    def get_approval_request(self, req_id: str) -> Optional[Dict[str, Any]]:



        with self.get_connection() as conn:



            cursor = conn.cursor()



            cursor.execute("SELECT * FROM approval_requests WHERE id = ?", (req_id,))



            row = cursor.fetchone()



            if not row:



                return None



            d = dict(row)



            try:



                d["scope_details"] = json.loads(d.get("scope_details_json") or "{}")



            except Exception:



                d["scope_details"] = {}



            return d







    def update_approval_status(self, req_id: str, status: str, decided_by: str, reason: str = "") -> bool:



        with self.get_connection() as conn:



            cursor = conn.cursor()



            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()



            cursor.execute('''



            UPDATE approval_requests



            SET status = ?, decided_by = ?, decision_reason = ?, decided_at = ?



            WHERE id = ?



            ''', (status, decided_by, reason, now_iso, req_id))



            conn.commit()



            return cursor.rowcount > 0







    # -------------------------------------------------------------



    # Security Knowledge Graph Nodes & Edges



    # -------------------------------------------------------------



    def upsert_knowledge_node(self, node: Dict[str, Any]):



        with self.get_connection() as conn:



            cursor = conn.cursor()



            cursor.execute('''



            INSERT OR REPLACE INTO knowledge_nodes (id, type, label, properties_json, criticality, created_at)



            VALUES (?, ?, ?, ?, ?, ?)



            ''', (



                node.get("id"),



                node.get("type"),



                node.get("label"),



                json.dumps(node.get("properties", {})),



                node.get("criticality"),



                node.get("created_at", datetime.datetime.now(datetime.timezone.utc).isoformat())



            ))



            conn.commit()







    def upsert_knowledge_edge(self, edge: Dict[str, Any]):



        with self.get_connection() as conn:



            cursor = conn.cursor()



            cursor.execute('''



            INSERT OR REPLACE INTO knowledge_edges (id, source_id, target_id, relationship, properties_json, created_at)



            VALUES (?, ?, ?, ?, ?, ?)



            ''', (



                edge.get("id"),



                edge.get("source_id"),



                edge.get("target_id"),



                edge.get("relationship"),



                json.dumps(edge.get("properties", {})),



                edge.get("created_at", datetime.datetime.now(datetime.timezone.utc).isoformat())



            ))



            conn.commit()







    def get_knowledge_graph(self) -> Dict[str, Any]:



        with self.get_connection() as conn:



            cursor = conn.cursor()



            cursor.execute("SELECT * FROM knowledge_nodes")



            node_rows = cursor.fetchall()



            nodes = []



            for r in node_rows:



                d = dict(r)



                try:



                    d["properties"] = json.loads(d.get("properties_json") or "{}")



                except Exception:



                    d["properties"] = {}



                nodes.append(d)







            cursor.execute("SELECT * FROM knowledge_edges")



            edge_rows = cursor.fetchall()



            edges = []



            for r in edge_rows:



                d = dict(r)



                try:



                    d["properties"] = json.loads(d.get("properties_json") or "{}")



                except Exception:



                    d["properties"] = {}



                edges.append(d)







            summary = {}



            for n in nodes:



                t = n.get("type", "Unknown")



                summary[t] = summary.get(t, 0) + 1







            return {"nodes": nodes, "edges": edges, "summary": summary}







    # -------------------------------------------------------------



    # Continuous Attack Surface Intelligence (EASM Drift)



    # -------------------------------------------------------------



    def save_drift_event(self, event: Dict[str, Any]):



        with self.get_connection() as conn:



            cursor = conn.cursor()



            cursor.execute('''



            INSERT OR REPLACE INTO asset_drift_events (



                id, project_id, target, asset_name, drift_type, title, description,



                previous_state_json, current_state_json, confidence, is_genuine_change, detected_at



            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)



            ''', (



                event.get("id"),



                event.get("project_id", "proj_default"),



                event.get("target"),



                event.get("asset_name"),



                event.get("drift_type"),



                event.get("title"),



                event.get("description", ""),



                json.dumps(event.get("previous_state", {})),



                json.dumps(event.get("current_state", {})),



                event.get("confidence", "CONFIRMED"),



                1 if event.get("is_genuine_change", True) else 0,



                event.get("detected_at", datetime.datetime.now(datetime.timezone.utc).isoformat())



            ))



            conn.commit()







    def get_drift_events(self, limit: int = 100, project_id: Optional[str] = None) -> List[Dict[str, Any]]:



        with self.get_connection() as conn:



            cursor = conn.cursor()



            if project_id:



                cursor.execute("SELECT * FROM asset_drift_events WHERE project_id = ? ORDER BY detected_at DESC LIMIT ?", (project_id, limit))



            else:



                cursor.execute("SELECT * FROM asset_drift_events ORDER BY detected_at DESC LIMIT ?", (limit,))



            rows = cursor.fetchall()



            results = []



            for r in rows:



                d = dict(r)



                try:



                    d["previous_state"] = json.loads(d.get("previous_state_json") or "{}")



                except Exception:



                    d["previous_state"] = {}



                try:



                    d["current_state"] = json.loads(d.get("current_state_json") or "{}")



                except Exception:



                    d["current_state"] = {}



                d["is_genuine_change"] = bool(d.get("is_genuine_change", 1))



                results.append(d)



            return results







    # -------------------------------------------------------------



    # Remediation Lifecycle Tickets



    # -------------------------------------------------------------



    def save_remediation_ticket(self, ticket: Dict[str, Any]):



        with self.get_connection() as conn:



            cursor = conn.cursor()



            cursor.execute('''



            INSERT OR REPLACE INTO remediation_tickets (



                id, finding_id, scan_id, target, title, severity, lifecycle_status,



                owner, due_date, patch_code, mitigation_guidance, retest_status,



                retest_evidence, suppression_reason, history_json, created_at, updated_at



            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)



            ''', (



                ticket.get("id"),



                ticket.get("finding_id"),



                ticket.get("scan_id"),



                ticket.get("target"),



                ticket.get("title"),



                ticket.get("severity"),



                ticket.get("lifecycle_status", "DISCOVERED"),



                ticket.get("owner", "Unassigned"),



                ticket.get("due_date"),



                ticket.get("patch_code"),



                ticket.get("mitigation_guidance"),



                ticket.get("retest_status"),



                ticket.get("retest_evidence"),



                ticket.get("suppression_reason"),



                json.dumps(ticket.get("history", [])),



                ticket.get("created_at", datetime.datetime.now(datetime.timezone.utc).isoformat()),



                ticket.get("updated_at", datetime.datetime.now(datetime.timezone.utc).isoformat())



            ))



            conn.commit()







    def get_remediation_tickets(self, status: Optional[str] = None, scan_id: Optional[str] = None) -> List[Dict[str, Any]]:



        with self.get_connection() as conn:



            cursor = conn.cursor()



            query = "SELECT * FROM remediation_tickets WHERE 1=1"



            params = []



            if status:



                query += " AND lifecycle_status = ?"



                params.append(status)



            if scan_id:



                query += " AND scan_id = ?"



                params.append(scan_id)



            query += " ORDER BY updated_at DESC"



            cursor.execute(query, params)



            rows = cursor.fetchall()



            results = []



            for r in rows:



                d = dict(r)



                try:



                    d["history"] = json.loads(d.get("history_json") or "[]")



                except Exception:



                    d["history"] = []



                results.append(d)



            return results







    def get_remediation_ticket(self, ticket_id: str) -> Optional[Dict[str, Any]]:



        with self.get_connection() as conn:



            cursor = conn.cursor()



            cursor.execute("SELECT * FROM remediation_tickets WHERE id = ? OR finding_id = ?", (ticket_id, ticket_id))



            row = cursor.fetchone()



            if not row:



                return None



            d = dict(row)



            try:



                d["history"] = json.loads(d.get("history_json") or "[]")



            except Exception:



                d["history"] = []



            return d







    def update_ticket_status(self, ticket_id: str, new_status: str, actor: str = "Analyst", reason: str = "") -> bool:



        ticket = self.get_remediation_ticket(ticket_id)



        if not ticket:



            return False



        history = ticket.get("history", [])



        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()



        history.append({



            "from_status": ticket.get("lifecycle_status"),



            "to_status": new_status,



            "actor": actor,



            "reason": reason,



            "timestamp": now_iso



        })



        with self.get_connection() as conn:



            cursor = conn.cursor()



            cursor.execute('''



            UPDATE remediation_tickets



            SET lifecycle_status = ?, history_json = ?, updated_at = ?



            WHERE id = ?



            ''', (new_status, json.dumps(history), now_iso, ticket.get("id")))



            



            # Also update findings table lifecycle_status



            cursor.execute('''



            UPDATE findings



            SET lifecycle_status = ?



            WHERE id = ?



            ''', (new_status, ticket.get("finding_id")))



            conn.commit()



            return True







    # -------------------------------------------------------------



    # 12-Template Enterprise Report Records



    # -------------------------------------------------------------



    def save_report_record(self, report: Dict[str, Any]):



        with self.get_connection() as conn:



            cursor = conn.cursor()



            cursor.execute('''



            INSERT OR REPLACE INTO report_records (



                id, template_type, title, target, scan_id, format,



                summary, findings_count, risk_score, generated_by, content, created_at



            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)



            ''', (



                report.get("id"),



                report.get("template_type"),



                report.get("title"),



                report.get("target"),



                report.get("scan_id"),



                report.get("format", "html"),



                report.get("summary", ""),



                report.get("findings_count", 0),



                report.get("risk_score", 0.0),



                report.get("generated_by", "Report Generation Agent"),



                report.get("content", ""),



                report.get("created_at", datetime.datetime.now(datetime.timezone.utc).isoformat())



            ))



            conn.commit()







    def get_report_records(self, limit: int = 50, template_type: Optional[str] = None) -> List[Dict[str, Any]]:



        with self.get_connection() as conn:



            cursor = conn.cursor()



            if template_type:



                cursor.execute("SELECT id, template_type, title, target, scan_id, format, summary, findings_count, risk_score, generated_by, created_at FROM report_records WHERE template_type = ? ORDER BY created_at DESC LIMIT ?", (template_type, limit))



            else:



                cursor.execute("SELECT id, template_type, title, target, scan_id, format, summary, findings_count, risk_score, generated_by, created_at FROM report_records ORDER BY created_at DESC LIMIT ?", (limit,))



            return [dict(r) for r in cursor.fetchall()]







    def get_report_record(self, report_id: str) -> Optional[Dict[str, Any]]:



        with self.get_connection() as conn:



            cursor = conn.cursor()



            cursor.execute("SELECT * FROM report_records WHERE id = ?", (report_id,))



            row = cursor.fetchone()



            return dict(row) if row else None

    # -------------------------------------------------------------
    # Professional Vulnerability Assessment Reports (Nessus-Style)
    # -------------------------------------------------------------
    def save_vuln_assessment_report(self, report: Dict[str, Any]):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
            INSERT OR REPLACE INTO vulnerability_assessment_reports (
                id, name, report_type, template_type, scan_id, target_scope,
                grouping_mode, format, status, findings_count, file_path,
                file_size, config_json, created_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                report.get("id"),
                report.get("name") or report.get("title") or "Vulnerability Assessment Report",
                report.get("report_type", "detailed_technical"),
                report.get("template_type", "template_b"),
                report.get("scan_id"),
                report.get("target_scope") or report.get("target", "127.0.0.1:8000"),
                report.get("grouping_mode", "host"),
                report.get("format", "html"),
                report.get("status", "COMPLETED"),
                report.get("findings_count", 0),
                report.get("file_path", ""),
                report.get("file_size", 0),
                report.get("config_json", ""),
                report.get("created_by", "SWA Vulnerability Assessment Engine"),
                report.get("created_at", datetime.datetime.now(datetime.timezone.utc).isoformat())
            ))
            conn.commit()

    def list_vuln_assessment_reports(self, limit: int = 50, scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if scan_id:
                cursor.execute('''
                SELECT * FROM vulnerability_assessment_reports
                WHERE scan_id = ?
                ORDER BY created_at DESC LIMIT ?
                ''', (scan_id, limit))
            else:
                cursor.execute('''
                SELECT * FROM vulnerability_assessment_reports
                ORDER BY created_at DESC LIMIT ?
                ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_vuln_assessment_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM vulnerability_assessment_reports WHERE id = ?", (report_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def delete_vuln_assessment_report(self, report_id: str) -> bool:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM vulnerability_assessment_reports WHERE id = ?", (report_id,))
            cursor.execute("DELETE FROM report_records WHERE id = ?", (report_id,))
            conn.commit()
            return cursor.rowcount > 0







    # -------------------------------------------------------------



    # Multi-Agent Workforce Task Execution History



    # -------------------------------------------------------------



    def save_agent_task(self, task: Dict[str, Any]):



        with self.get_connection() as conn:



            cursor = conn.cursor()



            cursor.execute('''



            INSERT OR REPLACE INTO agent_tasks (



                id, agent_role, scan_id, title, status, inputs_json,



                outputs_json, evidence_json, error_message, started_at, completed_at, duration_seconds



            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)



            ''', (



                task.get("id"),



                task.get("agent_role"),



                task.get("scan_id"),



                task.get("title"),



                task.get("status"),



                json.dumps(task.get("inputs", {})),



                json.dumps(task.get("outputs", {})),



                json.dumps(task.get("evidence", [])),



                task.get("error_message"),



                task.get("started_at"),



                task.get("completed_at"),



                task.get("duration_seconds", 0.0)



            ))



            conn.commit()







    def get_agent_tasks(self, scan_id: Optional[str] = None, agent_role: Optional[str] = None) -> List[Dict[str, Any]]:



        with self.get_connection() as conn:



            cursor = conn.cursor()



            query = "SELECT * FROM agent_tasks WHERE 1=1"



            params = []



            if scan_id:



                query += " AND scan_id = ?"



                params.append(scan_id)



            if agent_role:



                query += " AND agent_role = ?"



                params.append(agent_role)



            query += " ORDER BY started_at DESC LIMIT 100"



            cursor.execute(query, params)



            rows = cursor.fetchall()



            results = []



            for r in rows:



                d = dict(r)



                try:



                    d["inputs"] = json.loads(d.get("inputs_json") or "{}")



                except Exception:



                    d["inputs"] = {}



                try:



                    d["outputs"] = json.loads(d.get("outputs_json") or "{}")



                except Exception:



                    d["outputs"] = {}



                try:



                    d["evidence"] = json.loads(d.get("evidence_json") or "[]")



                except Exception:



                    d["evidence"] = []



                results.append(d)



            return results







    def get_agents_inventory(



        self,



        tier: Optional[str] = None,



        category: Optional[str] = None,



        status: Optional[str] = None,



        search: Optional[str] = None



    ) -> List[Dict[str, Any]]:



        with self.get_connection() as conn:



            cursor = conn.cursor()



            query = "SELECT * FROM agents_inventory WHERE 1=1"



            params = []



            if tier:



                query += " AND tier = ?"



                params.append(tier)



            if category:



                query += " AND category = ?"



                params.append(category)



            if status:



                query += " AND status = ?"



                params.append(status)



            if search:



                query += " AND (name LIKE ? OR id LIKE ? OR description LIKE ?)"



                q = f"%{search}%"



                params.extend([q, q, q])



            query += " ORDER BY tier ASC, name ASC"



            cursor.execute(query, params)



            rows = cursor.fetchall()



            results = []



            for r in rows:



                d = dict(r)



                try:



                    d["capabilities"] = json.loads(d.get("capabilities_json") or "[]")



                except Exception:



                    d["capabilities"] = []



                try:



                    d["responsibilities"] = json.loads(d.get("responsibilities_json") or "[]")



                except Exception:



                    d["responsibilities"] = []



                try:



                    d["permission_boundary"] = json.loads(d.get("permission_boundary_json") or "{}")



                except Exception:



                    d["permission_boundary"] = {}



                results.append(d)



            return results







    def count_agents_inventory(self) -> int:



        with self.get_connection() as conn:



            cursor = conn.cursor()



            cursor.execute("SELECT COUNT(*) FROM agents_inventory")



            return cursor.fetchone()[0]







    def backup_database(self, backup_path: Optional[str] = None) -> str:



        """



        Executes a zero-downtime, live SQLite database backup using sqlite3.backup.



        Returns the absolute path to the backup file.



        """



        if not backup_path:



            backup_dir = os.path.join(os.path.dirname(self.db_path), "backups")



            os.makedirs(backup_dir, exist_ok=True)



            timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")



            backup_path = os.path.join(backup_dir, f"swa_backup_{timestamp}.db")



        else:



            os.makedirs(os.path.dirname(os.path.abspath(backup_path)), exist_ok=True)







        with self.get_connection() as src_conn:



            dst_conn = sqlite3.connect(backup_path)



            try:



                src_conn.backup(dst_conn)



            finally:



                dst_conn.close()



        return os.path.abspath(backup_path)







    def create_ai_agent(self, data: Dict[str, Any]) -> str:

        with self.get_connection() as conn:

            cursor = conn.cursor()

            agent_id = data.get("id") or f"agent_{uuid.uuid4().hex[:10]}"

            now = datetime.datetime.now(datetime.timezone.utc).isoformat()

            

            if data.get("is_default"):

                cursor.execute("UPDATE ai_agents SET is_default = 0")

                

            cursor.execute("""

                INSERT INTO ai_agents (

                    id, name, provider, model, base_url, api_key_encrypted, api_key_masked,

                    description, role, enabled, is_default, connection_status, last_tested_at,

                    last_error, created_at, updated_at

                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

            """, (

                agent_id,

                data.get("name", "Custom AI Agent"),

                data.get("provider", "openai"),

                data.get("model", "gpt-4o-mini"),

                data.get("base_url"),

                data.get("api_key_encrypted", ""),

                data.get("api_key_masked", ""),

                data.get("description", ""),

                data.get("role", "Cybersecurity Specialist"),

                1 if data.get("enabled", True) else 0,

                1 if data.get("is_default", False) else 0,

                data.get("connection_status", "DISCONNECTED"),

                data.get("last_tested_at"),

                data.get("last_error"),

                now,

                now

            ))

            conn.commit()

            return agent_id



    def get_ai_agent(self, agent_id: str, include_encrypted_key: bool = False) -> Optional[Dict[str, Any]]:

        with self.get_connection() as conn:

            cursor = conn.cursor()

            cursor.execute("SELECT * FROM ai_agents WHERE id = ?", (agent_id,))

            row = cursor.fetchone()

            if not row:

                return None

            res = dict(row)

            if not include_encrypted_key:

                res.pop("api_key_encrypted", None)

            res["has_api_key"] = bool(row["api_key_encrypted"])

            return res



    def list_ai_agents(self, enabled_only: bool = False) -> List[Dict[str, Any]]:

        with self.get_connection() as conn:

            cursor = conn.cursor()

            query = "SELECT * FROM ai_agents"

            if enabled_only:

                query += " WHERE enabled = 1"

            query += " ORDER BY is_default DESC, created_at ASC"

            cursor.execute(query)

            rows = cursor.fetchall()

            agents = []

            for r in rows:

                d = dict(r)

                d.pop("api_key_encrypted", None)

                d["has_api_key"] = bool(r["api_key_encrypted"])

                agents.append(d)

            return agents



    def update_ai_agent(self, agent_id: str, updates: Dict[str, Any]) -> bool:

        with self.get_connection() as conn:

            cursor = conn.cursor()

            if updates.get("is_default"):

                cursor.execute("UPDATE ai_agents SET is_default = 0")

            

            allowed_cols = [

                "name", "provider", "model", "base_url", "api_key_encrypted",

                "api_key_masked", "description", "role", "enabled", "is_default",

                "connection_status", "last_tested_at", "last_error"

            ]

            set_clauses = []

            params = []

            for col in allowed_cols:

                if col in updates:

                    set_clauses.append(f"{col} = ?")

                    params.append(updates[col])

            

            if not set_clauses:

                return False

            

            set_clauses.append("updated_at = ?")

            now = datetime.datetime.now(datetime.timezone.utc).isoformat()

            params.append(now)

            params.append(agent_id)

            

            cursor.execute(f"UPDATE ai_agents SET {', '.join(set_clauses)} WHERE id = ?", tuple(params))

            conn.commit()

            return cursor.rowcount > 0



    def delete_ai_agent(self, agent_id: str) -> bool:

        with self.get_connection() as conn:

            cursor = conn.cursor()

            cursor.execute("DELETE FROM ai_agents WHERE id = ?", (agent_id,))

            conn.commit()

            cursor.execute("SELECT id FROM ai_agents WHERE is_default = 1")

            if not cursor.fetchone():

                cursor.execute("UPDATE ai_agents SET is_default = 1 WHERE id IN (SELECT id FROM ai_agents LIMIT 1)")

                conn.commit()

            return cursor.rowcount > 0



    def set_default_ai_agent(self, agent_id: str) -> bool:

        with self.get_connection() as conn:

            cursor = conn.cursor()

            cursor.execute("UPDATE ai_agents SET is_default = 0")

            cursor.execute("UPDATE ai_agents SET is_default = 1 WHERE id = ?", (agent_id,))

            conn.commit()

            return cursor.rowcount > 0



    def get_default_ai_agent(self, include_encrypted_key: bool = False) -> Optional[Dict[str, Any]]:

        with self.get_connection() as conn:

            cursor = conn.cursor()

            cursor.execute("SELECT * FROM ai_agents WHERE is_default = 1 LIMIT 1")

            row = cursor.fetchone()

            if not row:

                cursor.execute("SELECT * FROM ai_agents WHERE enabled = 1 LIMIT 1")

                row = cursor.fetchone()

            if not row:

                return None

            res = dict(row)

            if not include_encrypted_key:

                res.pop("api_key_encrypted", None)

            res["has_api_key"] = bool(row["api_key_encrypted"])

            return res





# -------------------------------------------------------------

    # Enterprise Blue Team, Incidents & Detection Rules Methods

    # -------------------------------------------------------------

    def save_incident(self, incident: Dict[str, Any]) -> str:

        with self.get_connection() as conn:

            cursor = conn.cursor()

            now = datetime.datetime.now(datetime.timezone.utc).isoformat()

            inc_id = incident.get("id") or f"inc_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')}_{os.urandom(2).hex()}"

            cursor.execute("""

            INSERT OR REPLACE INTO incidents (

                id, title, severity, status, assigned_analyst, affected_assets,

                description, timeline_json, containment_actions_json, lessons_learned,

                created_at, updated_at

            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

            """, (

                inc_id,

                incident.get("title", "Unnamed Security Incident"),

                incident.get("severity", "MEDIUM"),

                incident.get("status", "NEW"),

                incident.get("assigned_analyst", "Unassigned"),

                incident.get("affected_assets", ""),

                incident.get("description", ""),

                json.dumps(incident.get("timeline", [])) if isinstance(incident.get("timeline"), (list, dict)) else incident.get("timeline_json", "[]"),

                json.dumps(incident.get("containment_actions", [])) if isinstance(incident.get("containment_actions"), (list, dict)) else incident.get("containment_actions_json", "[]"),

                incident.get("lessons_learned", ""),

                incident.get("created_at") or now,

                incident.get("updated_at") or now

            ))

            conn.commit()

            return inc_id



    def get_incidents(self, status: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:

        with self.get_connection() as conn:

            cursor = conn.cursor()

            if status:

                cursor.execute("SELECT * FROM incidents WHERE status = ? ORDER BY created_at DESC LIMIT ?", (status, limit))

            else:

                cursor.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,))

            return [dict(row) for row in cursor.fetchall()]



    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:

        with self.get_connection() as conn:

            cursor = conn.cursor()

            cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))

            row = cursor.fetchone()

            return dict(row) if row else None



    def update_incident_status(self, incident_id: str, new_status: str, analyst: Optional[str] = None) -> bool:

        with self.get_connection() as conn:

            cursor = conn.cursor()

            now = datetime.datetime.now(datetime.timezone.utc).isoformat()

            if analyst:

                cursor.execute("UPDATE incidents SET status = ?, assigned_analyst = ?, updated_at = ? WHERE id = ?", (new_status, analyst, now, incident_id))

            else:

                cursor.execute("UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?", (new_status, now, incident_id))

            conn.commit()

            return cursor.rowcount > 0



    def get_detection_rules(self, category: Optional[str] = None, enabled_only: bool = False) -> List[Dict[str, Any]]:

        with self.get_connection() as conn:

            cursor = conn.cursor()

            query = "SELECT * FROM detection_rules WHERE 1=1"

            params = []

            if category:

                query += " AND category = ?"

                params.append(category)

            if enabled_only:

                query += " AND enabled = 1"

            query += " ORDER BY name ASC"

            cursor.execute(query, params)

            return [dict(row) for row in cursor.fetchall()]



    def toggle_detection_rule(self, rule_id: str) -> bool:

        with self.get_connection() as conn:

            cursor = conn.cursor()

            now = datetime.datetime.now(datetime.timezone.utc).isoformat()

            cursor.execute("UPDATE detection_rules SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END, updated_at = ? WHERE id = ?", (now, rule_id))

            conn.commit()

            return cursor.rowcount > 0



    def get_security_events(self, limit: int = 100) -> List[Dict[str, Any]]:

        with self.get_connection() as conn:

            cursor = conn.cursor()

            cursor.execute("SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ?", (limit,))

            return [dict(row) for row in cursor.fetchall()]



    def get_threat_indicators(self, indicator_type: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:

        with self.get_connection() as conn:

            cursor = conn.cursor()

            if indicator_type:

                cursor.execute("SELECT * FROM threat_indicators WHERE indicator_type = ? ORDER BY reputation_score DESC LIMIT ?", (indicator_type, limit))

            else:

                cursor.execute("SELECT * FROM threat_indicators ORDER BY reputation_score DESC LIMIT ?", (limit,))

            return [dict(row) for row in cursor.fetchall()]



    def get_cloud_assets(self, provider: Optional[str] = None) -> List[Dict[str, Any]]:

        with self.get_connection() as conn:

            cursor = conn.cursor()

            if provider:

                cursor.execute("SELECT * FROM cloud_assets WHERE provider = ? ORDER BY exposure_level DESC", (provider.upper(),))

            else:

                cursor.execute("SELECT * FROM cloud_assets ORDER BY exposure_level DESC")

            return [dict(row) for row in cursor.fetchall()]



    def get_container_assets(self) -> List[Dict[str, Any]]:

        with self.get_connection() as conn:

            cursor = conn.cursor()

            cursor.execute("SELECT * FROM container_assets ORDER BY critical_vulns DESC, high_vulns DESC")

            return [dict(row) for row in cursor.fetchall()]







    # -------------------------------------------------------------

    # SWA AI Enterprise Vulnerabilities & Findings Methods (§3, §5, §6, §8)

    # -------------------------------------------------------------



    def get_finding_metrics(self) -> Dict[str, Any]:

        """Calculates exact counts for the 10 summary cards, severity distribution, and lifecycle status distribution."""

        with self.get_connection() as conn:

            cursor = conn.cursor()

            cursor.execute("""

                SELECT 

                    id, title, severity, cvss_score, verified, 

                    coalesce(lifecycle_status, 'NEW') as l_status,

                    coalesce(verification_status, 'NEEDS_VALIDATION') as v_status,

                    coalesce(remediation_status, 'OPEN') as r_status,

                    coalesce(poc_verification_state, 'SCANNER DETECTED') as poc_state

                FROM findings;

            """)

            rows = cursor.fetchall()



            total_detections = len(rows)

            unique_titles = {r[1] for r in rows}

            unique_findings = len(unique_titles)



            confirmed_vulns = 0

            needs_validation = 0

            suspected_fps = 0

            confirmed_fps = 0

            critical_count = 0

            open_remediation = 0

            fixed_pending_retest = 0

            verified_resolved = 0



            sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0, "UNCLASSIFIED": 0}

            status_counts = {

                "NEW": 0, "NEEDS_VALIDATION": 0, "IN_PROGRESS": 0, "CONFIRMED": 0,

                "LIKELY_FALSE_POSITIVE": 0, "FALSE_POSITIVE": 0, "DUPLICATE": 0,

                "ACCEPTED_RISK": 0, "FIX_IN_PROGRESS": 0, "FIXED_PENDING_RETEST": 0,

                "RESOLVED_VERIFIED": 0, "REOPENED": 0, "INCONCLUSIVE": 0

            }



            for r in rows:

                f_id, title, sev, cvss, verified, l_status, v_status, r_status, poc_state = r

                s_upper = (sev or "LOW").upper()

                if s_upper in sev_counts:

                    sev_counts[s_upper] += 1

                else:

                    sev_counts["UNCLASSIFIED"] += 1



                # Normalize lifecycle status for 13 standardized codes

                norm_status = l_status

                if norm_status == "DISCOVERED":

                    norm_status = "CONFIRMED" if verified == 1 else "NEEDS_VALIDATION"

                elif norm_status == "VERIFIED":

                    norm_status = "CONFIRMED"



                if norm_status in status_counts:

                    status_counts[norm_status] += 1

                else:

                    status_counts["NEW"] += 1



                # 10 KPI summary counts

                if v_status == "CONFIRMED" or norm_status == "CONFIRMED" or poc_state == "PoC VERIFIED":

                    confirmed_vulns += 1

                if v_status == "NEEDS_VALIDATION" or norm_status == "NEEDS_VALIDATION":

                    needs_validation += 1

                if v_status == "LIKELY_FALSE_POSITIVE" or norm_status == "LIKELY_FALSE_POSITIVE":

                    suspected_fps += 1

                if v_status == "FALSE_POSITIVE" or norm_status == "FALSE_POSITIVE" or verified == 0:

                    confirmed_fps += 1

                if s_upper == "CRITICAL":

                    critical_count += 1

                if r_status == "OPEN":

                    open_remediation += 1

                if r_status in ("PENDING_RETEST", "FIX_SUBMITTED") or norm_status == "FIXED_PENDING_RETEST":

                    fixed_pending_retest += 1

                if r_status == "RESOLVED" or norm_status == "RESOLVED_VERIFIED":

                    verified_resolved += 1



            # Compute percentages for severity distribution

            sev_dist = []

            for s_name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNCLASSIFIED"]:

                c = sev_counts[s_name]

                pct = round((c / total_detections * 100), 1) if total_detections > 0 else 0.0

                sev_dist.append({"severity": s_name, "count": c, "percentage": pct})



            # Format status distribution

            status_dist = []

            from core.intelligence_models import FINDING_STATUS_METADATA

            for s_code, count in status_counts.items():

                meta = FINDING_STATUS_METADATA.get(s_code, {"label": s_code, "color": "#64748B"})

                pct = round((count / total_detections * 100), 1) if total_detections > 0 else 0.0

                status_dist.append({

                    "code": s_code,

                    "label": meta["label"],

                    "color": meta["color"],

                    "count": count,

                    "percentage": pct

                })



            poc_verified_count = cursor.execute("SELECT COUNT(*) FROM findings WHERE upper(coalesce(poc_verification_state, '')) = 'POC VERIFIED';").fetchone()[0]



            return {

                "total_findings": total_detections,

                "open_vulnerabilities": open_remediation,

                "poc_verified": poc_verified_count,

                "false_positives": confirmed_fps,

                "needs_validation": needs_validation,

                "fix_in_progress": status_counts.get('FIX_IN_PROGRESS', 0),

                "pending_retest": fixed_pending_retest,

                "resolved_verified": verified_resolved,

                "critical_findings": critical_count,

                "high_findings": sev_counts.get('HIGH', 0),

                "summary": {

                    "total_detections": total_detections,

                    "unique_findings": unique_findings,

                    "confirmed_vulnerabilities": confirmed_vulns,

                    "needs_validation": needs_validation,

                    "suspected_false_positives": suspected_fps,

                    "confirmed_false_positives": confirmed_fps,

                    "critical_findings": critical_count,

                    "open_remediation": open_remediation,

                    "fixed_pending_retest": fixed_pending_retest,

                    "verified_resolved": verified_resolved,

                    "poc_verified": poc_verified_count

                },

                "severity_distribution": sev_dist,

                "status_distribution": status_dist

            }



    def list_findings_advanced(

        self,

        search: Optional[str] = None,

        severity: Optional[str] = None,

        lifecycle_status: Optional[str] = None,

        remediation_status: Optional[str] = None,

        poc_state: Optional[str] = None,

        scan_id: Optional[str] = None,

        limit: int = 50,

        offset: int = 0,

        sort_by: str = "cvss_score",

        sort_order: str = "desc"

    ) -> Tuple[List[VulnerabilityFinding], int]:

        """Advanced multi-dimensional querying for findings data table with pagination and sorting."""

        with self.get_connection() as conn:

            cursor = conn.cursor()

            conditions = []

            params = []



            if scan_id:

                conditions.append("scan_id = ?")

                params.append(scan_id)



            if severity and severity.upper() != "ALL":

                sevs = [s.strip().upper() for s in severity.split(",")]

                placeholders = ",".join(["?"] * len(sevs))

                conditions.append(f"upper(severity) IN ({placeholders})")

                params.extend(sevs)



            if lifecycle_status and lifecycle_status.upper() != "ALL":

                statuses = [s.strip().upper() for s in lifecycle_status.split(",")]

                placeholders = ",".join(["?"] * len(statuses))

                conditions.append(f"upper(coalesce(lifecycle_status, 'NEW')) IN ({placeholders})")

                params.extend(statuses)



            if remediation_status and remediation_status.upper() != "ALL":

                r_statuses = [s.strip().upper() for s in remediation_status.split(",")]

                placeholders = ",".join(["?"] * len(r_statuses))

                conditions.append(f"upper(coalesce(remediation_status, 'OPEN')) IN ({placeholders})")

                params.extend(r_statuses)



            if poc_state and poc_state.upper() != "ALL":

                poc_states = [s.strip().upper() for s in poc_state.split(",")]

                placeholders = ",".join(["?"] * len(poc_states))

                conditions.append(f"upper(coalesce(poc_verification_state, 'SCANNER DETECTED')) IN ({placeholders})")

                params.extend(poc_states)



            if search and search.strip():

                term = f"%{search.strip().lower()}%"

                conditions.append("""(

                    lower(title) LIKE ? OR 

                    lower(id) LIKE ? OR 

                    lower(coalesce(cwe_id, '')) LIKE ? OR 

                    lower(coalesce(cve_id, '')) LIKE ? OR 

                    lower(endpoint) LIKE ? OR 

                    lower(coalesce(affected_asset, '')) LIKE ? OR 

                    lower(description) LIKE ?

                )""")

                params.extend([term] * 7)



            where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""



            # Count total matching

            cursor.execute(f"SELECT COUNT(*) FROM findings {where_clause};", params)

            total_count = cursor.fetchone()[0]



            # Allowed sort columns to prevent SQL injection

            allowed_sorts = {

                "cvss_score": "cvss_score",

                "created_at": "created_at",

                "severity": "CASE upper(severity) WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END",

                "title": "title",

                "lifecycle_status": "lifecycle_status",

                "remediation_status": "remediation_status"

            }

            sort_col = allowed_sorts.get(sort_by, "cvss_score")

            sort_dir = "ASC" if sort_order.lower() == "asc" else "DESC"



            query = f"""

                SELECT * FROM findings 

                {where_clause} 

                ORDER BY {sort_col} {sort_dir}, id DESC 

                LIMIT ? OFFSET ?;

            """

            cursor.execute(query, params + [limit, offset])

            rows = cursor.fetchall()

            findings = [self._row_to_finding(r) for r in rows]



            return findings, total_count



    def transition_finding_status(
        self,
        finding_id: str,
        new_status: Optional[str] = None,
        target_status: Optional[str] = None,
        status_type: str = "LIFECYCLE",
        reason: str = "",
        evidence: str = "",
        actor: str = "Analyst",
        changed_by: Optional[str] = None,
        approval_reference: str = ""
    ):
        """Controlled, auditable status transition (§5 Status Transition Rules)."""
        from core.intelligence_models import PERMITTED_LIFECYCLE_TRANSITIONS, PERMITTED_REMEDIATION_TRANSITIONS

        actual_status = (target_status or new_status or "").upper()
        actual_actor = changed_by or actor or "Analyst"

        finding = self.get_finding(finding_id)
        if not finding:
            class FailureResult(tuple):
                def __new__(cls): return super().__new__(cls, (False, f"Finding {finding_id} not found"))
                def __getitem__(self, item): return None
                def get(self, k, d=None): return d
            return FailureResult()

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        status_type = status_type.upper()

        with self.get_connection() as conn:
            cursor = conn.cursor()

            if status_type == "LIFECYCLE":
                cur_status = (finding.lifecycle_status or "NEW").upper()
                allowed = PERMITTED_LIFECYCLE_TRANSITIONS.get(cur_status, set())
                if actual_status != cur_status and actual_status not in allowed:
                    msg = f"Transition not allowed from {cur_status} to {actual_status}. Allowed: {sorted(list(allowed))}"
                    class FailureResult(tuple):
                        def __new__(cls): return super().__new__(cls, (False, msg))
                        def __getitem__(self, item): return None
                        def get(self, k, d=None): return d
                    return FailureResult()

                verified_flag = 0 if actual_status in ("FALSE_POSITIVE", "LIKELY_FALSE_POSITIVE") else 1
                cursor.execute("""
                    UPDATE findings 
                    SET lifecycle_status = ?, verification_status = ?, verified = ?, last_status_change = ?
                    WHERE id = ?;
                """, (actual_status, actual_status, verified_flag, now_iso, finding_id))

            elif status_type == "REMEDIATION":
                cur_status = (finding.remediation_status or "OPEN").upper()
                allowed = PERMITTED_REMEDIATION_TRANSITIONS.get(cur_status, set())
                if actual_status != cur_status and actual_status not in allowed:
                    msg = f"Transition not allowed from {cur_status} to {actual_status}. Allowed: {sorted(list(allowed))}"
                    class FailureResult(tuple):
                        def __new__(cls): return super().__new__(cls, (False, msg))
                        def __getitem__(self, item): return None
                        def get(self, k, d=None): return d
                    return FailureResult()

                cursor.execute("""
                    UPDATE findings 
                    SET remediation_status = ?, last_status_change = ?
                    WHERE id = ?;
                """, (actual_status, now_iso, finding_id))
            else:
                msg = f"Invalid status_type '{status_type}'. Must be 'LIFECYCLE' or 'REMEDIATION'."
                class FailureResult(tuple):
                    def __new__(cls): return super().__new__(cls, (False, msg))
                    def __getitem__(self, item): return None
                    def get(self, k, d=None): return d
                return FailureResult()

            # Record audit trail entry
            history_id = f"fsh_{uuid.uuid4().hex[:10]}"
            cursor.execute("""
                INSERT INTO finding_status_history (
                    id, finding_id, previous_status, new_status, status_type,
                    change_reason, supporting_evidence, responsible_actor, approval_reference, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (history_id, finding_id, cur_status, actual_status, status_type, reason, evidence, actual_actor, approval_reference, now_iso))

            conn.commit()

        data_dict = {
            "finding_id": finding_id,
            "status_type": status_type,
            "previous_status": cur_status,
            "new_status": actual_status,
            "actor": actual_actor,
            "timestamp": now_iso
        }
        class SuccessResult(tuple):
            def __new__(cls): return super().__new__(cls, (True, f"Transitioned to {actual_status}"))
            def __getitem__(self, item):
                if isinstance(item, str): return data_dict.get(item)
                return super().__getitem__(item)
            def get(self, k, d=None): return data_dict.get(k, d)
        return SuccessResult()

    def review_false_positive(
        self,
        finding_id: str,
        reason: str,
        reviewer: str = "Senior SecOps Analyst",
        reviewed_by: Optional[str] = None,
        notes: str = "",
        contradictory_evidence: str = "",
        is_false_positive: bool = True
    ):
        """Dedicated False-Positive review workflow (§6.2)."""
        actual_reviewer = reviewed_by or reviewer or "Senior SecOps Analyst"
        new_status = "FALSE_POSITIVE" if is_false_positive else "CONFIRMED"

        res = self.transition_finding_status(
            finding_id=finding_id,
            new_status=new_status,
            status_type="LIFECYCLE",
            reason=f"False Positive Review: {reason}. Notes: {notes}",
            evidence=contradictory_evidence or "Analyst manual evaluation",
            actor=actual_reviewer
        )

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE findings 
                SET reviewer = ?, false_positive_reason = ? 
                WHERE id = ?;
            """, (actual_reviewer, reason, finding_id))
            conn.commit()

        return res

    def get_finding_status_history(self, finding_id: str) -> List[Dict[str, Any]]:
        """Retrieves the chronological audit history of all status transitions for a finding."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, finding_id, previous_status, new_status, status_type,
                       change_reason, supporting_evidence, responsible_actor, approval_reference, timestamp
                FROM finding_status_history
                WHERE finding_id = ?
                ORDER BY timestamp DESC, rowid DESC;
            """, (finding_id,))
            rows = cursor.fetchall()
            return [
                {
                    "id": r[0],
                    "finding_id": r[1],
                    "previous_status": r[2],
                    "old_status": r[2],
                    "new_status": r[3],
                    "status_type": r[4],
                    "change_reason": r[5],
                    "reason": r[5],
                    "supporting_evidence": r[6],
                    "evidence": r[6],
                    "responsible_actor": r[7],
                    "changed_by": r[7],
                    "approval_reference": r[8],
                    "timestamp": r[9]
                }
                for r in rows
            ]

db = Database()

