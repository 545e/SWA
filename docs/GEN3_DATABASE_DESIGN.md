# SWA AI — Generation 3 Database Design

## 1. Engine & Configuration

SWA AI utilizes an optimized embedded SQLite relational database engine with enterprise concurrency settings:
- **Write-Ahead Logging (WAL):** `PRAGMA journal_mode = WAL;` (permits concurrent non-blocking reads during background write transactions).
- **Foreign Key Constraints:** `PRAGMA foreign_keys = ON;` (enforces relational referential integrity).
- **Synchronous Mode:** `PRAGMA synchronous = NORMAL;` (optimal balance of ACID persistence and write throughput).

---

## 2. Relational Schema & Tables

The schema comprises 18 core tables:

1. `scans`: Security assessment records (ID, target_url, profile, status, created_at, finished_at, options).
2. `findings`: Normalized vulnerability findings (ID, scan_id, title, severity, cvss_score, cwe_id, owasp_category, endpoint, method, evidence, status).
3. `scan_logs`: Timestamped execution log entries associated with scans.
4. `subdomain_assets`: Discovered domains, subdomains, IPs, CNAMEs, and takeover risk indicators.
5. `security_knowledge_nodes`: Nodes for the contextual cybersecurity knowledge graph (assets, vulns, agents, tools).
6. `security_knowledge_edges`: Relationships connecting knowledge nodes.
7. `remediation_tickets`: Tracking lifecycle of remediation efforts (open, in_progress, resolved, retested, closed).
8. `easm_drift_history`: Records of attack surface changes over time.
9. `human_approval_gates`: Audit records of sensitive actions awaiting human sign-off.
10. `audit_log_entries`: Immutable log of platform operations and administrative actions.
11. `datasets`: AI dataset version registry with quality scores and provenance.
12. `training_jobs`: Training/fine-tuning execution history and hyperparameter tracking.
13. `model_evaluations`: Model benchmark metrics (precision, recall, F1, latency, false positives).
14. `cyber_test_runs`: Continuous verification and regression test runs.
15. `cyber_deployments`: Deployment lifecycle events, health checks, and rollback history.
16. `cyber_exports`: Generated compliance packages and report downloads.
17. `tool_registry`: Catalog of integrated security tools and health states.
18. `users_sessions`: Active sessions and RBAC identity tracking.

---

## 3. B-Tree Performance Indexes

15 dedicated indexes maintain constant-time Lookups and efficient joins:

```sql
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_endpoint ON findings(endpoint);
CREATE INDEX IF NOT EXISTS idx_logs_scan_id ON scan_logs(scan_id);
CREATE INDEX IF NOT EXISTS idx_assets_subdomain ON subdomain_assets(subdomain);
CREATE INDEX IF NOT EXISTS idx_assets_parent ON subdomain_assets(parent_domain);
CREATE INDEX IF NOT EXISTS idx_knowledge_nodes_type ON security_knowledge_nodes(type);
CREATE INDEX IF NOT EXISTS idx_knowledge_edges_source ON security_knowledge_edges(source_id);
CREATE INDEX IF NOT EXISTS idx_knowledge_edges_target ON security_knowledge_edges(target_id);
CREATE INDEX IF NOT EXISTS idx_remediation_lifecycle ON remediation_tickets(lifecycle_status);
CREATE INDEX IF NOT EXISTS idx_remediation_finding ON remediation_tickets(finding_id);
CREATE INDEX IF NOT EXISTS idx_drift_project ON easm_drift_history(project_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log_entries(timestamp);
```

---

## 4. Backup & Disaster Recovery

- **Live Zero-Downtime Backup:** Implemented in `core.database.db.backup_database(backup_path)` using SQLite's native `sqlite3_backup` API.
- Safe to execute while the application is processing scans and writes.
