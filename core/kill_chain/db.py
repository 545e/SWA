"""
SWA AI — Cyber Kill Chain Database & Persistence Layer
Handles storage, retrieval, transactions, and indexing for all seven stages,
findings, evidence, threat indicators, security controls, and incidents.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import sqlite3
from typing import Any, Dict, List, Optional

from core.database import db
from core.kill_chain.models import (
    KillChainStageEnum,
    KillChainFinding,
    EvidenceItem,
    ThreatIndicator,
    IncidentRecord,
    SecurityControl,
    SeverityEnum,
    ConfidenceLevelEnum,
    IncidentStatusEnum,
    ControlCapabilityEnum,
    ControlStatusEnum,
)


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def init_kill_chain_schema() -> None:
    """Creates all required Kill Chain tables and indexes if not already present."""
    with db.get_connection() as conn:
        cursor = conn.cursor()

        # Evidence Repository Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS kill_chain_evidence (
            id TEXT PRIMARY KEY,
            stage TEXT NOT NULL,
            artifact_type TEXT NOT NULL,
            raw_data TEXT NOT NULL,
            normalized_json TEXT,
            source_tool TEXT NOT NULL,
            affected_asset TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            evidence_hash TEXT NOT NULL,
            confidence_level TEXT NOT NULL,
            confidence_score REAL NOT NULL,
            created_at TEXT NOT NULL
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_kc_ev_stage ON kill_chain_evidence(stage);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_kc_ev_asset ON kill_chain_evidence(affected_asset);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_kc_ev_hash ON kill_chain_evidence(evidence_hash);")

        # Stage Findings Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS kill_chain_findings (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            stage TEXT NOT NULL,
            severity TEXT NOT NULL,
            cve TEXT,
            cwe TEXT,
            mitre_technique_id TEXT,
            mitre_tactic TEXT,
            affected_host TEXT NOT NULL,
            affected_endpoint TEXT,
            http_status_code INTEGER,
            description TEXT,
            evidence TEXT,
            evidence_ids_json TEXT,
            detection_source TEXT NOT NULL,
            first_observed TEXT NOT NULL,
            last_observed TEXT NOT NULL,
            confidence_level TEXT NOT NULL,
            confidence_score REAL NOT NULL,
            risk_score REAL NOT NULL,
            remediation TEXT,
            references_json TEXT,
            status TEXT NOT NULL DEFAULT 'OPEN',
            created_at TEXT NOT NULL
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_kc_find_stage ON kill_chain_findings(stage);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_kc_find_sev ON kill_chain_findings(severity);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_kc_find_host ON kill_chain_findings(affected_host);")

        # Threat Indicators Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS kill_chain_indicators (
            id TEXT PRIMARY KEY,
            indicator_type TEXT NOT NULL,
            value TEXT NOT NULL UNIQUE,
            stage TEXT NOT NULL,
            threat_actor TEXT,
            malware_family TEXT,
            reputation_score REAL NOT NULL,
            provider TEXT NOT NULL,
            source_attribution TEXT NOT NULL,
            verified INTEGER NOT NULL DEFAULT 0,
            details_json TEXT,
            first_seen TEXT NOT NULL,
            last_checked TEXT NOT NULL
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_kc_ind_val ON kill_chain_indicators(value);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_kc_ind_stage ON kill_chain_indicators(stage);")

        # Security Control Coverage Matrix Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS kill_chain_controls (
            id TEXT PRIMARY KEY,
            stage TEXT NOT NULL,
            name TEXT NOT NULL,
            capability TEXT NOT NULL,
            status TEXT NOT NULL,
            tool_mapping TEXT,
            description TEXT,
            last_verified_at TEXT,
            coverage_score REAL NOT NULL DEFAULT 0.0
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_kc_ctrl_stage ON kill_chain_controls(stage);")

        # Incidents Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS kill_chain_incidents (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            assigned_analyst TEXT NOT NULL,
            affected_assets_json TEXT,
            description TEXT,
            stages_involved_json TEXT,
            linked_findings_json TEXT,
            linked_evidence_json TEXT,
            attack_path_id TEXT,
            containment_recommendations_json TEXT,
            containment_actions_taken_json TEXT,
            remediation_notes TEXT,
            audit_trail_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_kc_inc_status ON kill_chain_incidents(status);")

        # Reports Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS kill_chain_reports (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            format TEXT NOT NULL,
            file_path TEXT,
            summary_json TEXT,
            total_findings INTEGER NOT NULL,
            critical_count INTEGER NOT NULL,
            high_count INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        """)

        # Audit Logs Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS kill_chain_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            analyst TEXT NOT NULL,
            details TEXT,
            timestamp TEXT NOT NULL
        );
        """)

        conn.commit()


# Call schema initialization on import
init_kill_chain_schema()


# Evidence Operations
def save_evidence(item: EvidenceItem) -> str:
    with db.get_connection() as conn:
        cursor = conn.cursor()
        raw_hash = item.evidence_hash or hashlib.sha256(item.raw_data.encode("utf-8", errors="ignore")).hexdigest()
        cursor.execute(
            """
            INSERT OR REPLACE INTO kill_chain_evidence (
                id, stage, artifact_type, raw_data, normalized_json,
                source_tool, affected_asset, observed_at, evidence_hash,
                confidence_level, confidence_score, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item.id,
                item.stage.value if hasattr(item.stage, "value") else str(item.stage),
                item.artifact_type,
                item.raw_data,
                json.dumps(item.normalized_data),
                item.source_tool,
                item.affected_asset,
                item.observed_at,
                raw_hash,
                item.confidence_level.value if hasattr(item.confidence_level, "value") else str(item.confidence_level),
                float(item.confidence_score),
                item.created_at,
            )
        )
        conn.commit()
    return item.id


def get_evidence(evidence_id: str) -> Optional[EvidenceItem]:
    with db.get_connection() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        row = cursor.execute("SELECT * FROM kill_chain_evidence WHERE id = ?", (evidence_id,)).fetchone()
        if not row:
            return None
        return _row_to_evidence(row)


def list_evidence(stage: Optional[str] = None, asset: Optional[str] = None, limit: int = 100) -> List[EvidenceItem]:
    with db.get_connection() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        query = "SELECT * FROM kill_chain_evidence"
        clauses = []
        params: List[Any] = []
        if stage:
            clauses.append("stage = ?")
            params.append(stage)
        if asset:
            clauses.append("affected_asset = ?")
            params.append(asset)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY observed_at DESC LIMIT ?"
        params.append(limit)

        rows = cursor.execute(query, params).fetchall()
        return [_row_to_evidence(r) for r in rows]


def _row_to_evidence(row: sqlite3.Row) -> EvidenceItem:
    return EvidenceItem(
        id=row["id"],
        stage=KillChainStageEnum(row["stage"]),
        artifact_type=row["artifact_type"],
        raw_data=row["raw_data"],
        normalized_data=json.loads(row["normalized_json"] or "{}"),
        source_tool=row["source_tool"],
        affected_asset=row["affected_asset"],
        observed_at=row["observed_at"],
        evidence_hash=row["evidence_hash"],
        confidence_level=ConfidenceLevelEnum(row["confidence_level"]),
        confidence_score=float(row["confidence_score"]),
        created_at=row["created_at"],
    )


# Finding Operations
def save_finding(finding: KillChainFinding) -> str:
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO kill_chain_findings (
                id, title, stage, severity, cve, cwe,
                mitre_technique_id, mitre_tactic, affected_host, affected_endpoint,
                http_status_code, description, evidence, evidence_ids_json,
                detection_source, first_observed, last_observed,
                confidence_level, confidence_score, risk_score,
                remediation, references_json, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.id,
                finding.title,
                finding.stage.value if hasattr(finding.stage, "value") else str(finding.stage),
                finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                finding.cve,
                finding.cwe,
                finding.mitre_technique_id,
                finding.mitre_tactic,
                finding.affected_host,
                finding.affected_endpoint,
                finding.http_status_code,
                finding.description,
                finding.evidence,
                json.dumps(finding.evidence_ids),
                finding.detection_source,
                finding.first_observed,
                finding.last_observed,
                finding.confidence_level.value if hasattr(finding.confidence_level, "value") else str(finding.confidence_level),
                float(finding.confidence_score),
                float(finding.risk_score),
                finding.remediation,
                json.dumps(finding.references),
                finding.status,
                finding.created_at,
            )
        )
        conn.commit()
    return finding.id


def get_finding(finding_id: str) -> Optional[KillChainFinding]:
    with db.get_connection() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        row = cursor.execute("SELECT * FROM kill_chain_findings WHERE id = ?", (finding_id,)).fetchone()
        if not row:
            return None
        return _row_to_finding(row)


def list_findings(stage: Optional[str] = None, severity: Optional[str] = None, limit: int = 200) -> List[KillChainFinding]:
    with db.get_connection() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        query = "SELECT * FROM kill_chain_findings"
        clauses = []
        params: List[Any] = []
        if stage and stage != "ALL":
            clauses.append("stage = ?")
            params.append(stage)
        if severity and severity != "ALL":
            clauses.append("severity = ?")
            params.append(severity.upper())
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY risk_score DESC, created_at DESC LIMIT ?"
        params.append(limit)

        rows = cursor.execute(query, params).fetchall()
        return [_row_to_finding(r) for r in rows]


def _row_to_finding(row: sqlite3.Row) -> KillChainFinding:
    return KillChainFinding(
        id=row["id"],
        title=row["title"],
        stage=KillChainStageEnum(row["stage"]),
        severity=SeverityEnum(row["severity"]),
        cve=row["cve"],
        cwe=row["cwe"],
        mitre_technique_id=row["mitre_technique_id"],
        mitre_tactic=row["mitre_tactic"],
        affected_host=row["affected_host"],
        affected_endpoint=row["affected_endpoint"],
        http_status_code=row["http_status_code"],
        description=row["description"] or "",
        evidence=row["evidence"] or "",
        evidence_ids=json.loads(row["evidence_ids_json"] or "[]"),
        detection_source=row["detection_source"],
        first_observed=row["first_observed"],
        last_observed=row["last_observed"],
        confidence_level=ConfidenceLevelEnum(row["confidence_level"]),
        confidence_score=float(row["confidence_score"]),
        risk_score=float(row["risk_score"]),
        remediation=row["remediation"] or "",
        references=json.loads(row["references_json"] or "[]"),
        status=row["status"],
        created_at=row["created_at"],
    )


# Threat Indicator Operations
def save_indicator(ind: ThreatIndicator) -> str:
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO kill_chain_indicators (
                id, indicator_type, value, stage, threat_actor, malware_family,
                reputation_score, provider, source_attribution, verified, details_json,
                first_seen, last_checked
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ind.id,
                ind.indicator_type,
                ind.value,
                ind.stage.value if hasattr(ind.stage, "value") else str(ind.stage),
                ind.threat_actor,
                ind.malware_family,
                float(ind.reputation_score),
                ind.provider,
                ind.source_attribution,
                1 if ind.verified else 0,
                json.dumps(ind.details),
                ind.first_seen,
                ind.last_checked,
            )
        )
        conn.commit()
    return ind.id


def list_indicators(stage: Optional[str] = None, indicator_type: Optional[str] = None) -> List[ThreatIndicator]:
    with db.get_connection() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        query = "SELECT * FROM kill_chain_indicators"
        clauses = []
        params: List[Any] = []
        if stage:
            clauses.append("stage = ?")
            params.append(stage)
        if indicator_type:
            clauses.append("indicator_type = ?")
            params.append(indicator_type.upper())
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY reputation_score DESC LIMIT 100"

        rows = cursor.execute(query, params).fetchall()
        res = []
        for r in rows:
            res.append(
                ThreatIndicator(
                    id=r["id"],
                    indicator_type=r["indicator_type"],
                    value=r["value"],
                    stage=KillChainStageEnum(r["stage"]),
                    threat_actor=r["threat_actor"],
                    malware_family=r["malware_family"],
                    reputation_score=float(r["reputation_score"]),
                    provider=r["provider"],
                    source_attribution=r["source_attribution"],
                    verified=bool(r["verified"]),
                    details=json.loads(r["details_json"] or "{}"),
                    first_seen=r["first_seen"],
                    last_checked=r["last_checked"],
                )
            )
        return res


# Security Controls Operations
def save_control(ctrl: SecurityControl) -> str:
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO kill_chain_controls (
                id, stage, name, capability, status, tool_mapping, description, last_verified_at, coverage_score
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ctrl.id,
                ctrl.stage.value if hasattr(ctrl.stage, "value") else str(ctrl.stage),
                ctrl.name,
                ctrl.capability.value if hasattr(ctrl.capability, "value") else str(ctrl.capability),
                ctrl.status.value if hasattr(ctrl.status, "value") else str(ctrl.status),
                ctrl.tool_mapping,
                ctrl.description,
                ctrl.last_verified_at,
                float(ctrl.coverage_score),
            )
        )
        conn.commit()
    return ctrl.id


def list_controls(stage: Optional[str] = None) -> List[SecurityControl]:
    with db.get_connection() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        query = "SELECT * FROM kill_chain_controls"
        params = []
        if stage:
            query += " WHERE stage = ?"
            params.append(stage)
        query += " ORDER BY stage, capability"
        rows = cursor.execute(query, params).fetchall()
        res = []
        for r in rows:
            res.append(
                SecurityControl(
                    id=r["id"],
                    stage=KillChainStageEnum(r["stage"]),
                    name=r["name"],
                    capability=ControlCapabilityEnum(r["capability"]),
                    status=ControlStatusEnum(r["status"]),
                    tool_mapping=r["tool_mapping"] or "",
                    description=r["description"] or "",
                    last_verified_at=r["last_verified_at"],
                    coverage_score=float(r["coverage_score"]),
                )
            )
        return res


# Incident Operations
def save_incident(inc: IncidentRecord) -> str:
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO kill_chain_incidents (
                id, title, severity, status, assigned_analyst, affected_assets_json,
                description, stages_involved_json, linked_findings_json, linked_evidence_json,
                attack_path_id, containment_recommendations_json, containment_actions_taken_json,
                remediation_notes, audit_trail_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                inc.id,
                inc.title,
                inc.severity.value if hasattr(inc.severity, "value") else str(inc.severity),
                inc.status.value if hasattr(inc.status, "value") else str(inc.status),
                inc.assigned_analyst,
                json.dumps(inc.affected_assets),
                inc.description,
                json.dumps([s.value if hasattr(s, "value") else str(s) for s in inc.stages_involved]),
                json.dumps(inc.linked_findings),
                json.dumps(inc.linked_evidence),
                inc.attack_path_id,
                json.dumps(inc.containment_recommendations),
                json.dumps(inc.containment_actions_taken),
                inc.remediation_notes,
                json.dumps(inc.audit_trail),
                inc.created_at,
                inc.updated_at,
            )
        )
        conn.commit()
    return inc.id


def get_incident(incident_id: str) -> Optional[IncidentRecord]:
    with db.get_connection() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        row = cursor.execute("SELECT * FROM kill_chain_incidents WHERE id = ?", (incident_id,)).fetchone()
        if not row:
            return None
        return _row_to_incident(row)


def list_incidents(status: Optional[str] = None) -> List[IncidentRecord]:
    with db.get_connection() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        query = "SELECT * FROM kill_chain_incidents"
        params = []
        if status and status != "ALL":
            query += " WHERE status = ?"
            params.append(status.upper())
        query += " ORDER BY updated_at DESC"
        rows = cursor.execute(query, params).fetchall()
        return [_row_to_incident(r) for r in rows]


def _row_to_incident(row: sqlite3.Row) -> IncidentRecord:
    stages_raw = json.loads(row["stages_involved_json"] or "[]")
    stages = []
    for s in stages_raw:
        try:
            stages.append(KillChainStageEnum(s))
        except Exception:
            pass

    return IncidentRecord(
        id=row["id"],
        title=row["title"],
        severity=SeverityEnum(row["severity"]),
        status=IncidentStatusEnum(row["status"]),
        assigned_analyst=row["assigned_analyst"],
        affected_assets=json.loads(row["affected_assets_json"] or "[]"),
        description=row["description"] or "",
        stages_involved=stages,
        linked_findings=json.loads(row["linked_findings_json"] or "[]"),
        linked_evidence=json.loads(row["linked_evidence_json"] or "[]"),
        attack_path_id=row["attack_path_id"],
        containment_recommendations=json.loads(row["containment_recommendations_json"] or "[]"),
        containment_actions_taken=json.loads(row["containment_actions_taken_json"] or "[]"),
        remediation_notes=row["remediation_notes"] or "",
        audit_trail=json.loads(row["audit_trail_json"] or "[]"),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def record_audit(action: str, entity_type: str, entity_id: str, analyst: str = "SOC Lead", details: str = "") -> None:
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO kill_chain_audit (action, entity_type, entity_id, analyst, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (action, entity_type, entity_id, analyst, details, _utc_now())
        )
        conn.commit()


def save_report_record(report_id: str, title: str, format_type: str, file_path: str, summary: Dict[str, Any], total_findings: int, critical_count: int, high_count: int) -> None:
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO kill_chain_reports (
                id, title, format, file_path, summary_json, total_findings, critical_count, high_count, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (report_id, title, format_type, file_path, json.dumps(summary), total_findings, critical_count, high_count, _utc_now())
        )
        conn.commit()


def list_report_records() -> List[Dict[str, Any]]:
    with db.get_connection() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        rows = cursor.execute("SELECT * FROM kill_chain_reports ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]
