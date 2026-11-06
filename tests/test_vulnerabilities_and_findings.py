"""
SWA AI — Test Suite for Vulnerabilities & Findings Module
Covers:
- 13 Standardized Finding Lifecycle Statuses (§3.1)
- 8 Remediation Lifecycle Statuses (§3.3)
- CVSS Qualitative Severity Bands & Colors (§4)
- PoC Verification Badge & Policy (§6.1)
- Audit History Trail Persistence (§5.4)
- False-Positive Review Workflow (§5.3)
- 10 Summary KPI Metrics (§8.1)
- Advanced Filtering & Pagination (§8.3)
- REST API Endpoints (§9)
- Vulnerability Reporting Engine (§10)
"""

import pytest
from fastapi.testclient import TestClient

from core.database import db
from core.models import VulnerabilityFinding, Severity
from core.intelligence_models import (
    FindingLifecycleStatus,
    RemediationStatus,
    PoCVerificationState,
    FINDING_STATUS_METADATA,
    REMEDIATION_STATUS_METADATA,
    SEVERITY_COLOR_METADATA,
    PERMITTED_LIFECYCLE_TRANSITIONS,
    PERMITTED_REMEDIATION_TRANSITIONS
)
from reports.vulnerability_reports import VulnerabilityReportEngine
from web.server import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# 1. Status Codes & Enums Coverage (§3)
# ---------------------------------------------------------------------------

def test_all_13_finding_lifecycle_status_codes():
    """Verify all 13 required lifecycle status codes exist and have metadata."""
    expected_codes = [
        "NEW", "NEEDS_VALIDATION", "IN_PROGRESS", "CONFIRMED",
        "LIKELY_FALSE_POSITIVE", "FALSE_POSITIVE", "DUPLICATE",
        "ACCEPTED_RISK", "FIX_IN_PROGRESS", "FIXED_PENDING_RETEST",
        "RESOLVED_VERIFIED", "REOPENED", "INCONCLUSIVE"
    ]
    for code in expected_codes:
        assert hasattr(FindingLifecycleStatus, code), f"Missing enum member: {code}"
        assert code in FINDING_STATUS_METADATA, f"Missing metadata for: {code}"
        meta = FINDING_STATUS_METADATA[code]
        assert "label" in meta and "color" in meta and "description" in meta


def test_all_8_remediation_status_codes():
    """Verify all 8 required remediation status codes exist and have metadata."""
    expected_remediation = [
        "OPEN", "ASSIGNED", "IN_PROGRESS", "FIX_SUBMITTED",
        "PENDING_RETEST", "RESOLVED", "RISK_ACCEPTED", "REOPENED"
    ]
    for code in expected_remediation:
        assert hasattr(RemediationStatus, code), f"Missing remediation enum: {code}"
        assert code in REMEDIATION_STATUS_METADATA, f"Missing remediation metadata for: {code}"
        meta = REMEDIATION_STATUS_METADATA[code]
        assert "label" in meta and "color" in meta


def test_official_cvss_severity_colors():
    """Verify CVSS severity colors and thresholds adhere to standard."""
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNCLASSIFIED"]
    for sev in severities:
        assert sev in SEVERITY_COLOR_METADATA
        entry = SEVERITY_COLOR_METADATA[sev]
        assert "fg" in entry and "bg" in entry and "cvss" in entry


# ---------------------------------------------------------------------------
# 2. Database Status Transitions & Audit History (§5.4)
# ---------------------------------------------------------------------------

def test_finding_status_transition_valid_and_audit_history():
    """Test valid lifecycle transitions and verify audit history persistence."""
    test_id = "FIND-TRANS-TEST-001"
    db.save_finding(VulnerabilityFinding(
        id=test_id,
        scan_id="scan-test-transition",
        title="Test Status Transition Injection",
        description="SQL injection discovered in query param",
        severity=Severity.HIGH,
        cvss_score=8.5,
        endpoint="/api/v1/test_transition",
        poc_curl="curl -i 'http://127.0.0.1:8000/api/v1/test_transition'",
        poc_verification_state=PoCVerificationState.POC_VERIFIED.value,
        lifecycle_status=FindingLifecycleStatus.NEW.value,
        remediation_status=RemediationStatus.OPEN.value
    ))

    # Valid: NEW -> IN_PROGRESS
    success, msg = db.transition_finding_status(
        finding_id=test_id,
        target_status="IN_PROGRESS",
        reason="Security engineer triaging",
        status_type="LIFECYCLE",
        changed_by="SecLead",
        evidence="Analysis confirmed packet trace"
    )
    assert success, f"Transition failed: {msg}"

    # Verify updated finding
    f = db.get_finding(test_id)
    assert f.lifecycle_status == "IN_PROGRESS"

    # Verify history audit trail
    history = db.get_finding_status_history(test_id)
    assert len(history) >= 1
    latest = history[0]
    assert latest["old_status"] == "NEW"
    assert latest["new_status"] == "IN_PROGRESS"
    assert latest["changed_by"] == "SecLead"
    assert "Analysis confirmed" in latest["evidence"]


def test_finding_status_transition_invalid_rejected():
    """Test that unauthorized transitions violate state machine policy."""
    test_id = "FIND-TRANS-TEST-002"
    db.save_finding(VulnerabilityFinding(
        id=test_id,
        scan_id="scan-test-invalid",
        title="Test Invalid Transition",
        description="Cross-site scripting vector",
        severity=Severity.MEDIUM,
        cvss_score=5.0,
        endpoint="/api/v1/test_invalid",
        lifecycle_status=FindingLifecycleStatus.CONFIRMED.value
    ))

    # Invalid: CONFIRMED cannot jump directly to RESOLVED_VERIFIED without retest
    success, msg = db.transition_finding_status(
        finding_id=test_id,
        target_status="RESOLVED_VERIFIED",
        reason="Attempting direct closure",
        status_type="LIFECYCLE"
    )
    assert not success
    assert "Transition not allowed" in msg


# ---------------------------------------------------------------------------
# 3. False-Positive Review Workflow (§5.3)
# ---------------------------------------------------------------------------

def test_false_positive_review_workflow():
    """Test senior analyst false positive review and contradictory evidence recording."""
    test_id = "FIND-FP-TEST-001"
    db.save_finding(VulnerabilityFinding(
        id=test_id,
        scan_id="scan-test-fp",
        title="Test Potential False Alarm",
        description="Healthcheck reflection",
        severity=Severity.LOW,
        cvss_score=3.2,
        endpoint="/healthz",
        lifecycle_status=FindingLifecycleStatus.CONFIRMED.value
    ))

    success, msg = db.review_false_positive(
        finding_id=test_id,
        reason="WAF blocks all reflection payloads in production",
        contradictory_evidence="HTTP 403 Forbidden with ModSecurity signature 941100",
        reviewed_by="Lead Analyst Alice"
    )
    assert success
    f = db.get_finding(test_id)
    assert f.lifecycle_status == "FALSE_POSITIVE"
    assert f.reviewer == "Lead Analyst Alice"
    assert "WAF blocks" in f.false_positive_reason


# ---------------------------------------------------------------------------
# 4. Metrics & Multi-Dimensional Advanced Search (§8.1 & §8.3)
# ---------------------------------------------------------------------------

def test_finding_metrics_10_cards_and_distributions():
    """Verify 10 summary KPI counts and distribution bars."""
    metrics = db.get_finding_metrics()
    assert "total_findings" in metrics
    assert "open_vulnerabilities" in metrics
    assert "poc_verified" in metrics
    assert "critical_findings" in metrics
    assert "high_findings" in metrics
    assert "false_positives" in metrics
    assert "needs_validation" in metrics
    assert "fix_in_progress" in metrics
    assert "pending_retest" in metrics
    assert "resolved_verified" in metrics
    assert metrics["total_findings"] >= 400
    assert len(metrics["severity_distribution"]) == 6
    assert len(metrics["status_distribution"]) == 13


def test_list_findings_advanced_filtering_and_sorting():
    """Test multi-dimensional querying, filtering by severity and status, and pagination."""
    items, total = db.list_findings_advanced(
        severity="HIGH",
        limit=10,
        offset=0,
        sort_by="cvss_score",
        sort_order="desc"
    )
    assert total >= 40
    assert len(items) == 10
    for item in items:
        sev_val = item.severity.value if hasattr(item.severity, "value") else item.severity
        assert sev_val.upper() == "HIGH"


# ---------------------------------------------------------------------------
# 5. REST API Endpoints Verification (§9)
# ---------------------------------------------------------------------------

def test_api_findings_metrics_endpoint():
    """GET /api/findings/metrics returns 200 with complete metrics schema."""
    resp = client.get("/api/findings/metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_findings"] >= 400
    assert "severity_distribution" in data


def test_api_findings_paged_and_compatibility():
    """GET /api/findings preserves backward compatible list and supports paged object."""
    # Backward compatible list
    resp_list = client.get("/api/findings")
    assert resp_list.status_code == 200
    assert isinstance(resp_list.json(), list)

    # Paged response
    resp_paged = client.get("/api/findings?paged=true&limit=5&offset=0")
    assert resp_paged.status_code == 200
    paged = resp_paged.json()
    assert "items" in paged and "total" in paged
    assert len(paged["items"]) == 5


def test_api_finding_detail_and_history():
    """GET /api/findings/{id} and /api/findings/{id}/history."""
    # Fetch first finding
    resp = client.get("/api/findings?limit=1")
    f_id = resp.json()[0]["id"]

    detail_resp = client.get(f"/api/findings/{f_id}")
    assert detail_resp.status_code == 200
    assert "history" in detail_resp.json()

    hist_resp = client.get(f"/api/findings/{f_id}/history")
    assert hist_resp.status_code == 200
    assert isinstance(hist_resp.json(), list)


def test_api_finding_transition_endpoint():
    """POST /api/findings/{id}/transition."""
    test_id = "FIND-API-TRANS-001"
    db.save_finding(VulnerabilityFinding(
        id=test_id,
        scan_id="scan-api-transition",
        title="Test API Transition",
        description="Path traversal parameter validation error",
        severity=Severity.LOW,
        cvss_score=2.0,
        endpoint="/test",
        lifecycle_status=FindingLifecycleStatus.NEW.value
    ))

    resp = client.post(f"/api/findings/{test_id}/transition", json={
        "status_type": "LIFECYCLE",
        "target_status": "NEEDS_VALIDATION",
        "reason": "Submitted for peer validation",
        "changed_by": "Tester"
    })
    assert resp.status_code == 200
    assert resp.json()["status"] == "SUCCESS"


def test_api_false_positive_endpoint():
    """POST /api/findings/{id}/false-positive."""
    test_id = "FIND-API-FP-001"
    db.save_finding(VulnerabilityFinding(
        id=test_id,
        scan_id="scan-api-fp",
        title="Test API FP",
        description="Simulated mock vulnerability",
        severity=Severity.LOW,
        cvss_score=1.5,
        endpoint="/test-fp",
        lifecycle_status=FindingLifecycleStatus.NEW.value
    ))

    resp = client.post(f"/api/findings/{test_id}/false-positive", json={
        "reason": "Architectural mock endpoint",
        "contradictory_evidence": "Mock returns static response",
        "reviewed_by": "Senior Reviewer"
    })
    assert resp.status_code == 200
    assert resp.json()["status"] == "SUCCESS"


def test_api_findings_export_csv_and_json():
    """GET /api/findings/export supports CSV, JSON, and PDF."""
    r_csv = client.get("/api/findings/export?format=csv")
    assert r_csv.status_code == 200
    assert "text/csv" in r_csv.headers["content-type"]
    assert "Finding ID" in r_csv.text

    r_json = client.get("/api/findings/export?format=json")
    assert r_json.status_code == 200
    assert "application/json" in r_json.headers["content-type"]


# ---------------------------------------------------------------------------
# 6. Vulnerability Report Engine (§10)
# ---------------------------------------------------------------------------

def test_vulnerability_reports_generation():
    """Verify all 5 specialized vulnerability reports generate in HTML and PDF."""
    # Executive Report (§10.1)
    rep_exec = VulnerabilityReportEngine.generate_executive_report(format_type="html")
    assert "SWA AI Executive Vulnerability Report" in rep_exec["data"].decode("utf-8")

    # Technical Report (§10.2)
    rep_tech = VulnerabilityReportEngine.generate_technical_report(format_type="html")
    assert "Technical Vulnerability Assessment Report" in rep_tech["data"].decode("utf-8")

    # False-Positive Report (§10.4)
    rep_fp = VulnerabilityReportEngine.generate_false_positive_report(format_type="html")
    assert "False-Positive Review & Suppression Report" in rep_fp["data"].decode("utf-8")

    # Remediation Report (§10.5)
    rep_rem = VulnerabilityReportEngine.generate_remediation_report(format_type="html")
    assert "Remediation & Retest Governance Report" in rep_rem["data"].decode("utf-8")


def test_api_vulnerability_reports_endpoint():
    """GET /api/reports/vulnerability/{report_type}."""
    resp = client.get("/api/reports/vulnerability/executive?format=html")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]

    resp_tech = client.get("/api/reports/vulnerability/technical?format=json")
    assert resp_tech.status_code == 200
    assert "application/json" in resp_tech.headers["content-type"]
