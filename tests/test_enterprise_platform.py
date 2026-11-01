"""
SWA AI — Automated Enterprise Platform Quality Gate Test Suite
Verifies:
1. Multi-Agent Specialist Workforce (all 17 agent roles and manifests)
2. Human-in-the-Loop Approval Engine
3. Security Knowledge Graph & Relationship Queries
4. Continuous Attack Surface Intelligence & EASM Drift
5. Defensible & Explainable Risk Prioritization
6. Remediation Lifecycle & Retest Verification
7. 12-Template Enterprise Report Intelligence Engine
8. REST API Integration Endpoints
"""

import pytest
import asyncio
import datetime
from fastapi.testclient import TestClient
from web.server import app
from core.database import db
from core.intelligence_models import (
    AgentRole,
    ApprovalActionType,
    ApprovalStatus,
    FindingLifecycleStatus,
    ReportTemplateType
)
from core.approval_engine import approval_engine
from core.knowledge_graph import knowledge_graph_engine
from core.attack_surface_intel import attack_surface_intel
from core.risk_engine import risk_engine
from core.remediation_engine import remediation_engine
from agents.agent_workforce import agent_workforce
from reports.enterprise_reports import enterprise_report_engine
from core.models import ScanJob, ScanConfig, ScanProfile, VulnerabilityFinding, Severity, ReconResult

client = TestClient(app)


# ---------------------------------------------------------------------------
# Test 1: Multi-Agent Specialist Workforce
# ---------------------------------------------------------------------------
def test_specialist_agent_workforce_manifests():
    manifests = agent_workforce.list_manifests()
    assert len(manifests) == 17, f"Expected 17 specialist agents, got {len(manifests)}"
    roles = {m.role for m in manifests}
    for expected in AgentRole:
        assert expected in roles, f"Missing agent role in manifests: {expected}"


def test_specialist_agent_task_dispatch():
    async def _run():
        from core.intelligence_models import AgentTask
        task = AgentTask(
            agent_role=AgentRole.SUPERVISOR,
            scan_id="test_scan_super",
            title="Formulate Autonomous Security Objective",
            inputs={"target": "127.0.0.1:8000", "profile": "standard"}
        )
        res = await agent_workforce.dispatch_task(AgentRole.SUPERVISOR, task)
        assert res.status == "COMPLETED"
        assert res.outputs is not None
        assert "plan" in res.outputs
        assert len(res.outputs["plan"]) >= 10
    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Test 2: Human-in-the-Loop Approval Gates
# ---------------------------------------------------------------------------
def test_approval_gate_lifecycle():
    async def _run():
        # 1. Request approval for aggressive scanning
        req = await approval_engine.request_approval(
            action_type=ApprovalActionType.AGGRESSIVE_SCANNING,
            target="127.0.0.1:8000",
            rationale="Operator requested intensive fuzzing.",
            impact_assessment="Target server resource load increase."
        )
        assert req.status == ApprovalStatus.PENDING

        # 2. Check pending list
        pending = approval_engine.list_requests(ApprovalStatus.PENDING)
        assert any(r.id == req.id for r in pending)

        # 3. Approve request
        decided = await approval_engine.decide_approval(
            request_id=req.id,
            approved=True,
            decided_by="Lead Security Architect",
            reason="Target is validated test lab."
        )
        assert decided is not None
        assert decided.status == ApprovalStatus.APPROVED
    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Test 3: Security Knowledge Graph Engine
# ---------------------------------------------------------------------------
def test_knowledge_graph_ingestion_and_queries():
    scan_id = "test_kg_scan_01"
    target = "http://127.0.0.1:8000"
    job = ScanJob(
        id=scan_id,
        target_url=target,
        config=ScanConfig(target_url=target)
    )
    recon = ReconResult(
        target=target,
        ip_addresses=["127.0.0.1"],
        open_ports=[{"port": 8000, "service": "http", "state": "open"}],
        technologies=[{"name": "Python", "version": "3.12"}]
    )
    findings = [
        VulnerabilityFinding(
            id="f_test_01",
            scan_id=scan_id,
            title="Missing Anti-Clickjacking Header",
            severity=Severity.MEDIUM,
            cvss_score=4.3,
            cwe_id="CWE-1021",
            endpoint="http://127.0.0.1:8000/dashboard",
            description="X-Frame-Options is missing.",
            poc_curl="curl -i http://127.0.0.1:8000/dashboard",
            poc_explanation="HTTP 200 without X-Frame-Options.",
            remediation_advice="Add X-Frame-Options: SAMEORIGIN"
        )
    ]

    knowledge_graph_engine.ingest_scan(job, findings, recon)
    graph = knowledge_graph_engine.get_full_graph()
    assert len(graph.nodes) > 0
    assert len(graph.edges) > 0

    exposed = knowledge_graph_engine.query_exposed_assets()
    assert isinstance(exposed, list)


# ---------------------------------------------------------------------------
# Test 4: Continuous Attack Surface Intelligence (EASM Drift)
# ---------------------------------------------------------------------------
def test_attack_surface_drift_evaluation():
    scan_id = "test_drift_scan_01"
    target = "http://127.0.0.1:8000"
    job = ScanJob(
        id=scan_id,
        target_url=target,
        config=ScanConfig(target_url=target)
    )
    recon = ReconResult(
        target=target,
        ip_addresses=["127.0.0.1"],
        open_ports=[{"port": 8000, "service": "http", "state": "open"}],
        technologies=[{"name": "FastAPI", "version": "0.110"}]
    )

    drift_events = attack_surface_intel.evaluate_drift(job, recon)
    assert isinstance(drift_events, list)


# ---------------------------------------------------------------------------
# Test 5: Defensible & Explainable Risk Prioritization
# ---------------------------------------------------------------------------
def test_defensible_risk_scoring():
    finding = VulnerabilityFinding(
        id="f_risk_01",
        scan_id="scan_risk",
        title="Remote Command Execution",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        cwe_id="CWE-78",
        endpoint="http://127.0.0.1:8000/api/exec",
        description="Arbitrary command execution flaw.",
        poc_curl="curl http://127.0.0.1:8000/api/exec?cmd=whoami",
        confidence="CONFIRMED"
    )

    breakdown = risk_engine.calculate_risk(
        finding=finding,
        asset_criticality="CRITICAL",
        is_internet_exposed=True,
        has_active_waf_or_mitigation=False
    )

    assert breakdown.final_score >= 80.0
    assert "Base severity rating: CRITICAL" in breakdown.rationale
    assert "Active PoC" in breakdown.rationale


# ---------------------------------------------------------------------------
# Test 6: Remediation Lifecycle & Retest Verification
# ---------------------------------------------------------------------------
def test_remediation_lifecycle_and_retest():
    async def _run():
        finding = VulnerabilityFinding(
            id="f_rem_test_01",
            scan_id="scan_rem",
            title="Unprotected Header Exposure",
            severity=Severity.LOW,
            cvss_score=2.5,
            endpoint="http://127.0.0.1:8000/health",
            description="Minor header flaw.",
            remediation_advice="Configure server headers."
        )
        db.save_finding(finding)
        ticket = remediation_engine.create_ticket_from_finding(finding, "127.0.0.1:8000")
        assert ticket.lifecycle_status == FindingLifecycleStatus.DISCOVERED

        # Transition to IN_PROGRESS
        updated = await remediation_engine.transition_ticket(
            ticket_id=ticket.id,
            new_status=FindingLifecycleStatus.IN_PROGRESS,
            actor="SecOps Analyst",
            reason="Assigned to web team."
        )
        assert updated.lifecycle_status == FindingLifecycleStatus.IN_PROGRESS

        # Execute automated retest probe against healthy /health endpoint
        retest_result = await remediation_engine.run_retest(ticket.id)
        assert retest_result["status"] in ("VERIFIED_RESOLVED", "FAILED_PERSISTS")
    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Test 7: 12-Template Enterprise Report Engine
# ---------------------------------------------------------------------------
def test_all_12_enterprise_reports():
    target = "127.0.0.1:8000"
    for template_type in ReportTemplateType:
        record = enterprise_report_engine.generate_report(
            template_type=template_type,
            target=target,
            format_type="html"
        )
        assert record.id.startswith("rep_")
        assert len(record.content) > 50
        assert record.template_type == template_type


# ---------------------------------------------------------------------------
# Test 8: REST API Endpoints
# ---------------------------------------------------------------------------
def test_api_enterprise_endpoints():
    # 1. Global Context
    res = client.get("/api/context")
    assert res.status_code == 200
    data = res.json()
    assert "workspace_id" in data
    assert "posture_score" in data

    # 2. Specialist Agents
    res = client.get("/api/agents")
    assert res.status_code == 200
    assert len(res.json()) == 17

    # 3. Report Templates
    res = client.get("/api/reports/templates")
    assert res.status_code == 200
    assert len(res.json()) == 12

    # 4. Approvals
    res = client.get("/api/approvals")
    assert res.status_code == 200

    # 5. Security Knowledge Graph
    res = client.get("/api/graph")
    assert res.status_code == 200
    assert "summary" in res.json()

    # 6. Diagnostics
    res = client.get("/api/health/diagnostics")
    assert res.status_code == 200
    diag = res.json()
    assert diag["status"] == "HEALTHY"
    assert diag["subsystems"]["agents"]["active_count"] == 17
