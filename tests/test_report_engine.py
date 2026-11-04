"""
Unit and Integration Test Suite for Professional Nessus-Style Vulnerability Assessment Report Engine
"""

import os
import io
import json
import pytest
from fastapi.testclient import TestClient

from core.database import db
from core.models import VulnerabilityFinding, Severity, ScanJob, ScanProfile, ScanStatus, ScanConfig
from reports.nessus_report_engine import NessusVulnerabilityReportEngine, redact_secrets
from web.server import app

client = TestClient(app)


@pytest.fixture(scope="module")
def setup_test_assessment_data():
    """Seeds test scan and findings to verify report reconciliation."""
    scan_id = "scan_test_nessus_report_001"
    target = "http://127.0.0.1:8000"
    scan = ScanJob(
        id=scan_id,
        target_url=target,
        profile=ScanProfile.FULL_RED_TEAM,
        status=ScanStatus.COMPLETED,
        duration_seconds=22.4,
        config=ScanConfig(target_url=target)
    )
    db.save_scan(scan)

    findings = [
        VulnerabilityFinding(
            id="find_test_crit_01",
            scan_id=scan_id,
            title="Remote Code Execution via Insecure Deserialization",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_id="CWE-502",
            cve_id="CVE-2023-9999",
            endpoint="http://127.0.0.1:8000/api/v1/load",
            description="Arbitrary code execution flaw in serialization parser.",
            remediation_advice="Upgrade serializer and enforce strict HMAC verification.",
            lifecycle_status="CONFIRMED",
            verification_status="CONFIRMED",
            remediation_status="OPEN",
            poc_curl="curl -X POST http://127.0.0.1:8000/api/v1/load -H 'Authorization: Bearer secret_token_1234567890abcdef' -d 'payload'",
            request_evidence="POST /api/v1/load HTTP/1.1\nHost: 127.0.0.1:8000\nAuthorization: Bearer secret_token_1234567890abcdef\n\npayload",
            epss_score=0.884,
            cisa_kev=1
        ),
        VulnerabilityFinding(
            id="find_test_high_01",
            scan_id=scan_id,
            title="SQL Injection in User Search Parameter",
            severity=Severity.HIGH,
            cvss_score=8.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cwe_id="CWE-89",
            cve_id="CVE-2023-8888",
            endpoint="http://127.0.0.1:8000/api/v1/users?q=test",
            description="Unescaped dynamic SQL query allows unauthorized database access.",
            remediation_advice="Use parameterized prepared statements.",
            lifecycle_status="NEEDS_VALIDATION",
            verification_status="NEEDS_VALIDATION",
            remediation_status="OPEN",
            poc_curl="curl 'http://127.0.0.1:8000/api/v1/users?q=%27+OR+1%3D1--'",
            epss_score=0.452
        ),
        VulnerabilityFinding(
            id="find_test_med_01",
            scan_id=scan_id,
            title="Missing Content-Security-Policy Header",
            severity=Severity.MEDIUM,
            cvss_score=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
            cwe_id="CWE-1021",
            endpoint="http://127.0.0.1:8000/",
            description="Absence of CSP header allows potential cross-site scripting impact.",
            remediation_advice="Define strict Content-Security-Policy response header.",
            lifecycle_status="IN_PROGRESS",
            verification_status="IN_PROGRESS",
            remediation_status="FIX_IN_PROGRESS"
        ),
        VulnerabilityFinding(
            id="find_test_low_01",
            scan_id=scan_id,
            title="Server Banner Information Disclosure",
            severity=Severity.LOW,
            cvss_score=3.1,
            cwe_id="CWE-200",
            endpoint="http://127.0.0.1:8000/info",
            description="Server header reveals backend framework and version.",
            remediation_advice="Suppress server version headers in reverse proxy.",
            lifecycle_status="RESOLVED_VERIFIED",
            verification_status="RESOLVED_VERIFIED",
            remediation_status="RESOLVED_VERIFIED"
        ),
        VulnerabilityFinding(
            id="find_test_info_01",
            scan_id=scan_id,
            title="HTTP Strict Transport Security Not Enforced on Local Port",
            severity=Severity.INFO,
            cvss_score=0.0,
            cwe_id="CWE-319",
            endpoint="http://127.0.0.1:8000/health",
            description="HSTS header is absent for plaintext HTTP loopback port.",
            remediation_advice="Enforce TLS termination and HSTS on production domains.",
            lifecycle_status="NEW",
            verification_status="NEEDS_VALIDATION",
            remediation_status="OPEN"
        )
    ]

    for f in findings:
        db.save_finding(f)

    return {"scan_id": scan_id, "findings": findings}


class TestNessusReportEngine:
    """Validates the core NessusVulnerabilityReportEngine logic."""

    def test_01_templates_and_types_metadata(self):
        """Engine provides 10 report types and 6 templates."""
        templates = NessusVulnerabilityReportEngine.get_templates_metadata()
        types = NessusVulnerabilityReportEngine.get_report_types_metadata()
        
        assert len(templates) == 6
        assert len(types) == 10

        template_ids = [t["id"] for t in templates]
        assert "template_a" in template_ids
        assert "template_b" in template_ids
        assert "template_c" in template_ids
        assert "template_d" in template_ids
        assert "template_e" in template_ids
        assert "template_f" in template_ids

        type_ids = [t["id"] for t in types]
        assert "executive_summary" in type_ids
        assert "detailed_technical" in type_ids
        assert "vulnerabilities_by_host" in type_ids
        assert "vulnerabilities_by_plugin" in type_ids
        assert "remediation" in type_ids
        assert "false_positive_review" in type_ids

    def test_02_data_aggregation_metrics(self, setup_test_assessment_data):
        """Severity counts and unique metrics reconcile exactly with DB findings."""
        scan_id = setup_test_assessment_data["scan_id"]
        data = NessusVulnerabilityReportEngine.aggregate_data(
            scan_id=scan_id,
            grouping_mode="host",
            template_type="template_b"
        )

        assert data["total_detections"] == 5
        assert data["unique_findings_count"] == 5
        assert data["severity_counts"]["CRITICAL"] == 1
        assert data["severity_counts"]["HIGH"] == 1
        assert data["severity_counts"]["MEDIUM"] == 1
        assert data["severity_counts"]["LOW"] == 1
        assert data["severity_counts"]["INFORMATIONAL"] == 1

        # Host grouping
        assert len(data["hosts"]) >= 1
        host_key = list(data["hosts"].keys())[0]
        host = data["hosts"][host_key]
        assert host["critical"] == 1
        assert host["high"] == 1
        assert len(host["findings"]) == 5

        # Plugin grouping
        assert len(data["plugins"]) >= 4

    def test_03_secret_redaction(self):
        """Sensitive credentials and private tokens are masked from exports."""
        raw_output = "Authorization: Bearer secret_token_1234567890abcdef and api_key='sk_live_99999999999999999999'"
        redacted = redact_secrets(raw_output)
        assert "secret_token_1234567890abcdef" not in redacted
        assert "sk_live_99999999999999999999" not in redacted
        assert "[REDACTED_BY_SWA_REPORT_ENGINE]" in redacted

    def test_04_pdf_report_generation(self, setup_test_assessment_data):
        """PDF generator creates valid binary PDF bytes with cover page & headers."""
        scan_id = setup_test_assessment_data["scan_id"]
        data = NessusVulnerabilityReportEngine.aggregate_data(scan_id=scan_id, grouping_mode="host")
        pdf_bytes = NessusVulnerabilityReportEngine.generate_pdf(data)

        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 2000
        # Standard PDF magic header
        assert pdf_bytes.startswith(b"%PDF-")

    def test_05_html_report_generation(self, setup_test_assessment_data):
        """HTML generator renders standalone responsive dossier with search & print styles."""
        scan_id = setup_test_assessment_data["scan_id"]
        data = NessusVulnerabilityReportEngine.aggregate_data(scan_id=scan_id, grouping_mode="host")
        html_content = NessusVulnerabilityReportEngine.generate_html(data)

        assert "<!DOCTYPE html>" in html_content
        assert "VULNERABILITY ASSESSMENT REPORT" in html_content
        assert "Remote Code Execution via Insecure Deserialization" in html_content
        assert "SQL Injection in User Search Parameter" in html_content
        assert "findingSearch" in html_content
        assert "@media print" in html_content

    def test_06_csv_export_structure(self, setup_test_assessment_data):
        """CSV export contains all 23 standard columns with quoted headers."""
        scan_id = setup_test_assessment_data["scan_id"]
        data = NessusVulnerabilityReportEngine.aggregate_data(scan_id=scan_id)
        csv_text = NessusVulnerabilityReportEngine.generate_csv(data)

        lines = csv_text.strip().splitlines()
        header = lines[0]
        assert "Finding ID" in header
        assert "Plugin/Rule ID" in header
        assert "CVSS Score" in header
        assert "EPSS Score" in header
        assert "Severity" in header
        assert "Lifecycle Status" in header
        assert "Host" in header
        assert "Plugin Output" in header
        assert len(lines) == 6  # Header + 5 test findings

    def test_07_json_export_structure(self, setup_test_assessment_data):
        """JSON export contains machine-readable structured schema."""
        scan_id = setup_test_assessment_data["scan_id"]
        data = NessusVulnerabilityReportEngine.aggregate_data(scan_id=scan_id)
        json_text = NessusVulnerabilityReportEngine.generate_json(data)

        parsed = json.loads(json_text)
        assert "report_metadata" in parsed
        assert "scan_information" in parsed
        assert "executive_summary" in parsed
        assert "findings" in parsed
        assert len(parsed["findings"]) == 5
        assert parsed["findings"][0]["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "INFORMATIONAL")

    def test_08_nessus_xml_export_and_import(self, setup_test_assessment_data):
        """Nessus XML format (.nessus v2) export and import round-trip preserves findings."""
        scan_id = setup_test_assessment_data["scan_id"]
        data = NessusVulnerabilityReportEngine.aggregate_data(scan_id=scan_id)
        xml_text = NessusVulnerabilityReportEngine.generate_nessus_xml(data)

        assert "<NessusClientData_v2>" in xml_text
        assert "<ReportHost" in xml_text
        assert "<ReportItem" in xml_text
        assert "CWE-502" in xml_text or "Remote Code Execution" in xml_text

        # Test import of generated Nessus XML
        imported = NessusVulnerabilityReportEngine.import_nessus_xml(
            xml_text,
            scan_id="scan_imported_nessus_test"
        )
        assert len(imported) == 5
        assert any("Remote Code Execution" in f.title for f in imported)
        assert any(f.severity == Severity.CRITICAL for f in imported)

    def test_09_sarif_export_structure(self, setup_test_assessment_data):
        """SARIF export adheres to SARIF 2.1.0 schema."""
        scan_id = setup_test_assessment_data["scan_id"]
        data = NessusVulnerabilityReportEngine.aggregate_data(scan_id=scan_id)
        sarif_text = NessusVulnerabilityReportEngine.generate_sarif(data)

        parsed = json.loads(sarif_text)
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"]) == 1
        assert "tool" in parsed["runs"][0]
        assert len(parsed["runs"][0]["results"]) == 5

    def test_10_empty_assessment_handling(self):
        """Engine safely handles assessments with 0 findings without errors."""
        empty_scan_id = "scan_empty_test_000"
        target = "http://clean-target.local"
        scan = ScanJob(
            id=empty_scan_id,
            target_url=target,
            profile=ScanProfile.QUICK,
            status=ScanStatus.COMPLETED,
            config=ScanConfig(target_url=target)
        )
        db.save_scan(scan)

        data = NessusVulnerabilityReportEngine.aggregate_data(scan_id=empty_scan_id)
        assert data["total_detections"] == 0
        assert data["unique_findings_count"] == 0
        assert data["severity_counts"]["CRITICAL"] == 0

        # PDF and HTML should still generate cleanly
        pdf = NessusVulnerabilityReportEngine.generate_pdf(data)
        assert len(pdf) > 1000
        html = NessusVulnerabilityReportEngine.generate_html(data)
        assert "VULNERABILITY ASSESSMENT REPORT" in html


class TestReportEngineAPIEndpoints:
    """Validates FastAPI REST endpoints for report preview, generation, and downloads."""

    def test_api_01_get_templates(self):
        """GET /api/reports/vulnerability-assessment/templates returns 6 templates."""
        res = client.get("/api/reports/vulnerability-assessment/templates")
        assert res.status_code == 200
        items = res.json()
        assert len(items) == 6
        assert any(i["code"] == "Template A" for i in items)

    def test_api_02_get_types(self):
        """GET /api/reports/vulnerability-assessment/types returns 10 report types."""
        res = client.get("/api/reports/vulnerability-assessment/types")
        assert res.status_code == 200
        items = res.json()
        assert len(items) == 10

    def test_api_03_preview_report(self, setup_test_assessment_data):
        """POST /api/reports/vulnerability-assessment/preview provides live telemetry."""
        scan_id = setup_test_assessment_data["scan_id"]
        res = client.post(
            "/api/reports/vulnerability-assessment/preview",
            json={
                "scan_id": scan_id,
                "report_type": "detailed_technical",
                "template_type": "template_b",
                "grouping_mode": "host"
            }
        )
        assert res.status_code == 200
        preview = res.json()
        assert preview["total_detections"] == 5
        assert "severity_counts" in preview
        assert preview["severity_counts"]["CRITICAL"] == 1
        assert len(preview["sample_findings"]) > 0

    def test_api_04_generate_and_download_pdf(self, setup_test_assessment_data):
        """POST /generate produces PDF deliverable, and GET /download returns binary PDF."""
        scan_id = setup_test_assessment_data["scan_id"]
        res = client.post(
            "/api/reports/vulnerability-assessment/generate",
            json={
                "scan_id": scan_id,
                "report_type": "detailed_technical",
                "template_type": "template_b",
                "format_type": "pdf"
            }
        )
        assert res.status_code == 200
        body = res.json()
        assert body["status"] == "SUCCESS"
        report_id = body["report"]["id"]
        download_url = body["download_url"]

        # Download PDF
        dl_res = client.get(download_url)
        assert dl_res.status_code == 200
        assert dl_res.headers["content-type"] == "application/pdf"
        assert dl_res.content.startswith(b"%PDF-")

    def test_api_05_generate_and_download_html(self, setup_test_assessment_data):
        """POST /generate produces HTML deliverable, and GET /download returns HTML."""
        scan_id = setup_test_assessment_data["scan_id"]
        res = client.post(
            "/api/reports/vulnerability-assessment/generate",
            json={
                "scan_id": scan_id,
                "report_type": "executive_summary",
                "template_type": "template_a",
                "format_type": "html"
            }
        )
        assert res.status_code == 200
        body = res.json()
        report_id = body["report"]["id"]

        dl_res = client.get(f"/api/reports/vulnerability-assessment/{report_id}/download")
        assert dl_res.status_code == 200
        assert "text/html" in dl_res.headers["content-type"]
        assert "<!DOCTYPE html>" in dl_res.text

    def test_api_06_report_history_and_deletion(self, setup_test_assessment_data):
        """Generated reports appear in history and can be soft/hard deleted."""
        scan_id = setup_test_assessment_data["scan_id"]
        # Generate one report
        gen_res = client.post(
            "/api/reports/vulnerability-assessment/generate",
            json={
                "scan_id": scan_id,
                "format_type": "csv"
            }
        )
        report_id = gen_res.json()["report"]["id"]

        # Check history
        hist_res = client.get("/api/reports/vulnerability-assessment/history")
        assert hist_res.status_code == 200
        reports = hist_res.json()
        assert any(r["id"] == report_id for r in reports)

        # Delete report
        del_res = client.delete(f"/api/reports/vulnerability-assessment/{report_id}")
        assert del_res.status_code == 200
        assert del_res.json()["status"] == "SUCCESS"
