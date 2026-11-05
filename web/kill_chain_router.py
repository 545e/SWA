"""
SWA AI — Cyber Kill Chain API Router
Implements all required RESTful endpoints for the seven-stage attack lifecycle analyzer,
evidence repository, threat correlation, intelligence lookups, controls matrix,
incident management, playbooks, and report exports.
"""

from __future__ import annotations

import datetime
import os
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Body, Path
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from core.kill_chain.engine import kill_chain_engine
from core.kill_chain.models import (
    KillChainStageEnum,
    KillChainFinding,
    EvidenceItem,
    IncidentRecord,
    ThreatIndicator,
    KillChainOverview,
)
from core.kill_chain.db import (
    list_findings,
    get_finding,
    list_evidence,
    get_evidence,
    save_evidence,
    list_indicators,
    list_incidents,
    get_incident,
    list_report_records,
)

kill_chain_router = APIRouter(prefix="/api/kill-chain", tags=["Cyber Kill Chain"])


class TelemetryIngestRequest(BaseModel):
    target: Optional[str] = "127.0.0.1"
    telemetry: Optional[Dict[str, Any]] = None
    subdomains: Optional[List[str]] = None
    open_ports: Optional[List[Any]] = None
    files: Optional[List[Dict[str, Any]]] = None
    emails: Optional[List[Dict[str, Any]]] = None
    urls: Optional[List[Any]] = None
    findings: Optional[List[Dict[str, Any]]] = None
    processes: Optional[List[Dict[str, Any]]] = None
    network_flows: Optional[List[Dict[str, Any]]] = None
    exfiltration: Optional[List[Dict[str, Any]]] = None


class IncidentCreateRequest(BaseModel):
    title: str
    severity: str = "HIGH"
    assigned_analyst: str = "SOC Lead"
    affected_assets: List[str] = ["127.0.0.1"]
    description: str = ""
    stages_involved: List[str] = ["reconnaissance"]
    linked_findings: List[str] = []
    linked_evidence: Optional[List[str]] = None


class IncidentUpdateRequest(BaseModel):
    status: str
    analyst: Optional[str] = "SOC Lead"
    notes: Optional[str] = ""


class IndicatorLookupRequest(BaseModel):
    indicator_type: str  # IP, DOMAIN, URL, CVE, SHA256, MD5
    value: str


class ReportGenerateRequest(BaseModel):
    title: Optional[str] = "Enterprise Cyber Kill Chain Threat & Vulnerability Assessment"
    formats: Optional[List[str]] = ["html", "json", "csv", "markdown", "pdf"]
    scope: Optional[str] = "All Monitored Assets"
    analyst: Optional[str] = "Principal Security Architect"


# 1. Overview & Health
@kill_chain_router.get("/overview", response_model=KillChainOverview)
def get_kill_chain_overview():
    """Returns high-level SOC dashboard metrics across all 7 stages."""
    return kill_chain_engine.get_overview()


@kill_chain_router.get("/health")
def get_kill_chain_health():
    """Health check endpoint for the Cyber Kill Chain engine."""
    return {
        "status": "HEALTHY",
        "service": "Cyber Kill Chain Intelligence & Attack Lifecycle Analyzer",
        "version": "2.0.0",
        "stages_active": 7,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


# 2. Seven Stages
@kill_chain_router.get("/stages")
def list_kill_chain_stages():
    """Lists definitions, objectives, and metadata for all seven stages."""
    overview = kill_chain_engine.get_overview()
    return overview.stage_summaries


@kill_chain_router.get("/stages/{stage_id}")
def get_stage_details(stage_id: str = Path(..., description="Stage identifier (e.g. reconnaissance, c2)")):
    """Returns detailed investigation telemetry, findings, evidence, controls, and playbooks for a stage."""
    detail = kill_chain_engine.get_stage_detail(stage_id)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Stage '{stage_id}' not found.")
    return detail


# 3. Telemetry Ingestion & Live Analysis
@kill_chain_router.post("/analyze")
def analyze_telemetry_payload(request: TelemetryIngestRequest):
    """Executes analysis across all seven stages against ingested telemetry or scans."""
    telemetry = request.telemetry or {}
    if request.target:
        telemetry["target"] = request.target
    if request.subdomains:
        telemetry["subdomains"] = request.subdomains
    if request.open_ports:
        telemetry["open_ports"] = request.open_ports
    if request.files:
        telemetry["files"] = request.files
    if request.emails:
        telemetry["emails"] = request.emails
    if request.urls:
        telemetry["urls"] = request.urls
    if request.findings:
        telemetry["findings"] = request.findings
    if request.processes:
        telemetry["processes"] = request.processes
    if request.network_flows:
        telemetry["network_flows"] = request.network_flows
    if request.exfiltration:
        telemetry["exfiltration"] = request.exfiltration

    return kill_chain_engine.analyze_telemetry(telemetry, target=request.target)


# 4. Findings
@kill_chain_router.get("/findings")
def get_kill_chain_findings(
    stage: Optional[str] = Query(None, description="Filter by stage"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(200, ge=1, le=500),
):
    """Returns persistent findings across the 7 stages with risk and confidence scores."""
    findings = list_findings(stage=stage, severity=severity, limit=limit)
    return [f.dict() for f in findings]


@kill_chain_router.get("/findings/{finding_id}")
def get_kill_chain_finding_by_id(finding_id: str):
    f = get_finding(finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    return f.dict()


# 5. Correlation & Attack Paths
@kill_chain_router.post("/correlate")
def run_correlation(target_asset: Optional[str] = Query(None)):
    """Runs central correlation engine across all persistent findings and returns multi-stage attack paths."""
    findings = list_findings()
    evidence = list_evidence()
    indicators = list_indicators()
    paths = kill_chain_engine.correlation_engine.correlate(
        findings=findings,
        evidence=evidence,
        indicators=indicators,
        target_asset=target_asset,
    )
    return [p.dict() for p in paths]


# 6. Evidence Repository
@kill_chain_router.get("/evidence")
def get_kill_chain_evidence(
    stage: Optional[str] = Query(None),
    asset: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
):
    """Returns forensic evidence items from the repository."""
    items = list_evidence(stage=stage, asset=asset, limit=limit)
    return [e.dict() for e in items]


@kill_chain_router.post("/evidence")
def ingest_evidence_item(evidence_data: Dict[str, Any] = Body(...)):
    """Ingests a new raw evidence artifact with automatic cryptographic hashing and confidence rating."""
    try:
        stage_enum = KillChainStageEnum(evidence_data.get("stage", "reconnaissance").lower())
    except Exception:
        stage_enum = KillChainStageEnum.RECONNAISSANCE

    analyzer = kill_chain_engine.analyzers[stage_enum]
    ev = analyzer.create_evidence(
        artifact_type=evidence_data.get("artifact_type", "GENERIC_TELEMETRY"),
        raw_data=evidence_data.get("raw_data", ""),
        normalized_data=evidence_data.get("normalized_data", {}),
        affected_asset=evidence_data.get("affected_asset", "127.0.0.1"),
        source_tool=evidence_data.get("source_tool", "Analyst Manual Ingestion"),
    )
    save_evidence(ev)
    return ev.dict()


# 7. Threat Intelligence
@kill_chain_router.get("/intelligence")
def get_threat_intelligence_status():
    """Returns provider status, health metrics, and active threat indicators."""
    providers = kill_chain_engine.threat_intel.get_provider_health()
    indicators = list_indicators()
    return {
        "providers": providers,
        "indicators_count": len(indicators),
        "indicators": [i.dict() for i in indicators],
    }


@kill_chain_router.post("/intelligence/lookup")
def lookup_threat_indicator(req: IndicatorLookupRequest):
    """Performs real-time reputation and threat intelligence lookup for an indicator."""
    return kill_chain_engine.threat_intel.lookup_indicator(req.indicator_type, req.value)


# 8. Security Control Coverage Matrix
@kill_chain_router.get("/controls")
def get_security_controls_matrix():
    """Returns 7x5 matrix of defensive capabilities (Detect, Deny, Disrupt, Degrade, Deceive)."""
    return kill_chain_engine.controls_matrix.get_matrix()


# 9. Attack Progression Timeline
@kill_chain_router.get("/timeline")
def get_attack_progression_timeline():
    """Returns chronological timeline of security events and findings normalized to UTC."""
    findings = list_findings(limit=150)
    evidence = list_evidence(limit=150)

    timeline_events = []
    for f in findings:
        timeline_events.append({
            "id": f.id,
            "type": "FINDING",
            "title": f.title,
            "stage": f.stage.value,
            "severity": f.severity.value,
            "asset": f.affected_host,
            "timestamp": f.first_observed,
            "risk_score": f.risk_score,
            "description": f.description,
        })

    for e in evidence:
        timeline_events.append({
            "id": e.id,
            "type": "EVIDENCE",
            "title": f"{e.artifact_type} ({e.source_tool})",
            "stage": e.stage.value,
            "severity": "INFO",
            "asset": e.affected_asset,
            "timestamp": e.observed_at,
            "risk_score": 0.0,
            "description": e.raw_data[:120],
        })

    # Sort descending by timestamp
    timeline_events.sort(key=lambda x: x["timestamp"], reverse=True)
    return timeline_events


# 10. AI Threat Analysis & Playbook Recommendations
@kill_chain_router.post("/ai/analyze")
def run_ai_threat_analysis(finding_id: str = Query(...)):
    """Runs AI analysis answering the 7 SOC questions with deterministic fallback."""
    f = get_finding(finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found.")
    ev = get_evidence(f.evidence_ids[0]) if f.evidence_ids else None
    return kill_chain_engine.ai_analyzer.analyze_event(f, ev)


@kill_chain_router.post("/response/recommend")
def recommend_response_actions(stage: str = Query(...)):
    """Returns defensive response playbook for a given stage."""
    return kill_chain_engine.incident_manager.get_playbook_for_stage(stage)


# 11. Incident Response Center
@kill_chain_router.get("/incidents")
def list_soc_incidents(status: Optional[str] = Query(None)):
    """Returns all tracked SOC incidents."""
    incidents = list_incidents(status=status)
    return [i.dict() for i in incidents]


@kill_chain_router.post("/incidents")
def create_soc_incident(req: IncidentCreateRequest):
    """Creates a new incident record and links related findings and stages."""
    inc = kill_chain_engine.incident_manager.create_incident(
        title=req.title,
        severity=req.severity,
        assigned_analyst=req.assigned_analyst,
        affected_assets=req.affected_assets,
        description=req.description,
        stages_involved=req.stages_involved,
        linked_findings=req.linked_findings,
        linked_evidence=req.linked_evidence,
    )
    return inc.dict()


@kill_chain_router.get("/incidents/{incident_id}")
def get_soc_incident_by_id(incident_id: str):
    inc = get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return inc.dict()


@kill_chain_router.patch("/incidents/{incident_id}")
def update_soc_incident_status(incident_id: str, req: IncidentUpdateRequest):
    """Updates status of an incident and appends to audit trail."""
    inc = kill_chain_engine.incident_manager.update_status(
        incident_id=incident_id,
        new_status=req.status,
        analyst=req.analyst or "SOC Analyst",
        notes=req.notes or "",
    )
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return inc.dict()


# 12. Professional Reports & Deliverables
@kill_chain_router.get("/reports")
def list_kill_chain_reports():
    """Lists previously generated reports."""
    return list_report_records()


@kill_chain_router.post("/reports/generate")
def generate_kill_chain_report(req: ReportGenerateRequest):
    """Generates complete Nessus-style report across PDF, HTML, JSON, CSV, and Markdown."""
    findings = list_findings()
    evidence = list_evidence()
    indicators = list_indicators()
    paths = kill_chain_engine.correlation_engine.correlate(findings, evidence, indicators)
    coverage = kill_chain_engine.controls_matrix.get_matrix()

    report_pack = kill_chain_engine.reporter.generate_report(
        title=req.title or "Enterprise Cyber Kill Chain Assessment",
        findings=findings,
        evidence=evidence,
        attack_paths=paths,
        coverage_data=coverage,
        metadata={"analyst": req.analyst, "scope": req.scope},
        export_formats=req.formats,
    )
    return report_pack


@kill_chain_router.get("/reports/{report_id}/download")
def download_kill_chain_report(
    report_id: str,
    format: str = Query("html", pattern="^(html|pdf|json|csv|markdown|md)$"),
):
    """Downloads report deliverable in specified format."""
    ext = "md" if format == "markdown" else format
    output_dir = kill_chain_engine.reporter.output_dir
    file_path = os.path.join(output_dir, f"{report_id}.{ext}")

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"Report file {report_id}.{ext} not found on server.")

    media_types = {
        "html": "text/html",
        "pdf": "application/pdf",
        "json": "application/json",
        "csv": "text/csv",
        "md": "text/markdown",
        "markdown": "text/markdown",
    }
    return FileResponse(
        path=file_path,
        media_type=media_types.get(ext, "application/octet-stream"),
        filename=f"{report_id}.{ext}",
    )


# 13. Pre-load Verified Demo Scenario
@kill_chain_router.post("/seed-demo")
def seed_demo_scenario(target: str = Query("127.0.0.1")):
    """Seeds a complete realistic multi-stage intrusion investigation for instant verification."""
    return kill_chain_engine.seed_demonstration_scenario(target=target)
