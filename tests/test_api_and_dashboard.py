"""
Automated Integration and Schema Tests for SWA AI Web API, SOC Dashboard, and Persistence
"""

import unittest
from fastapi.testclient import TestClient
from web.server import app
from core.database import db
from core.models import ScanConfig, ScanProfile, VulnerabilityFinding, Severity, ScanStatus, ScanJob
from reports.generator import ReportGenerator


class TestApiAndDashboard(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_dashboard_html_and_soc_navigation(self):
        """Dashboard HTML delivers complete SOC structure with 11 navigation views."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        html = response.text
        self.assertIn("SWA AI", html)
        self.assertIn("soc-nav-bar", html)
        self.assertIn("themeToggleBtn", html)
        self.assertIn("posture-formula-box", html)
        
        # Verify 11 navigation view dispatches
        views = [
            "dashboard", "recon", "pentest", "fuzzer",
            "tools", "waf", "forensics",
            "siem", "reports", "settings", "docs"
        ]
        for v in views:
            self.assertIn(f"navToView('{v}')", html)

    def test_02_settings_api_schema(self):
        """Settings endpoint returns valid configuration schema."""
        response = self.client.get("/api/settings")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("ai_provider", data)
        self.assertIn("ai_model", data)
        self.assertIn("has_api_key", data)

    def test_03_subdomain_tool_api_schema(self):
        """Standalone Subdomain API returns structured metrics and asset list."""
        payload = {
            "domain": "example.com",
            "passive_only": True
        }
        response = self.client.post("/api/tools/subdomains", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        required_keys = [
            "domain", "apex_domain", "count", "discovered_count",
            "resolved_count", "wildcard_filtered_count", "failed_resolution_count",
            "live_count", "wildcard_detected", "takeover_count", "subdomains"
        ]
        for key in required_keys:
            self.assertIn(key, data)
        self.assertIsInstance(data["subdomains"], list)

    def test_04_target_scope_enforcement_and_ssrf(self):
        """Scope policy rejects malicious SSRF and unpermitted cloud metadata endpoints."""
        # AWS IMDS IP
        resp_imds = self.client.post("/api/scans", json={"target_url": "169.254.169.254", "profile": "standard"})
        self.assertEqual(resp_imds.status_code, 403)
        self.assertIn("Target Scope Refusal", resp_imds.json()["detail"])

        # Private RFC-1918 range without lab mode
        resp_priv = self.client.post("/api/scans", json={"target_url": "10.0.0.1", "profile": "standard"})
        self.assertEqual(resp_priv.status_code, 403)

        # Loopback permitted with lab_assessment profile
        resp_lab = self.client.post("/api/scans", json={"target_url": "http://127.0.0.1:8000", "profile": "lab_assessment"})
        self.assertEqual(resp_lab.status_code, 200)
        scan_id = resp_lab.json()["id"]
        self.assertTrue(len(scan_id) > 0)

    def test_05_scan_status_and_cancellation(self):
        """Scan creation, retrieval, and clean cancellation endpoints."""
        from core.queue_manager import queue_manager
        from unittest.mock import MagicMock

        # Create scan
        resp = self.client.post("/api/scans", json={"target_url": "http://127.0.0.1:8000", "profile": "lab_assessment"})
        self.assertEqual(resp.status_code, 200)
        scan_id = resp.json()["id"]

        # Check status
        resp_get = self.client.get(f"/api/scans/{scan_id}")
        self.assertEqual(resp_get.status_code, 200)
        self.assertIn("status", resp_get.json())

        # Register mock active task for reliable cancellation
        mock_task = MagicMock()
        queue_manager.active_tasks[scan_id] = mock_task

        # Cancel scan
        resp_cancel = self.client.post(f"/api/scans/{scan_id}/cancel")
        self.assertEqual(resp_cancel.status_code, 200)
        self.assertEqual(resp_cancel.json()["status"], "cancelled")
        self.assertTrue(mock_task.cancel.called)

    def test_06_database_finding_metadata_persistence(self):
        """Database correctly stores and retrieves enriched finding fields."""
        scan_id = "test_persistence_scan_01"
        finding = VulnerabilityFinding(
            id="FIND-TEST-9999",
            scan_id=scan_id,
            endpoint="http://example.com/test",
            title="Automated Test Finding",
            severity=Severity.HIGH,
            description="Testing schema extension columns",
            remediation_advice="Apply secure configurations",
            cwe_id="CWE-200",
            cvss_score=7.5,
            confidence="Confirmed",
            detection_method="Active PoC Probe",
            affected_asset="http://example.com/test",
            reproduction_steps="Send GET request with test header",
            impact="Unauthorized metadata exposure"
        )
        
        # Add finding
        db.add_finding(finding)
        
        # Retrieve findings
        findings = db.list_findings(scan_id)
        self.assertTrue(len(findings) >= 1)
        target_f = next(f for f in findings if f.id == "FIND-TEST-9999")
        self.assertEqual(target_f.confidence, "Confirmed")
        self.assertEqual(target_f.detection_method, "Active PoC Probe")
        self.assertEqual(target_f.affected_asset, "http://example.com/test")
        self.assertEqual(target_f.reproduction_steps, "Send GET request with test header")
        self.assertEqual(target_f.impact, "Unauthorized metadata exposure")

    def test_07_report_export_generation(self):
        """Report generator exports valid HTML, JSON, Markdown, and SARIF."""
        job = ScanJob(
            id="test_export_job",
            target_url="http://127.0.0.1:8000",
            config=ScanConfig(target_url="http://127.0.0.1:8000", profile=ScanProfile.LAB_ASSESSMENT),
            status=ScanStatus.COMPLETED
        )
        
        finding = VulnerabilityFinding(
            id="F-EXP-1",
            scan_id="test_export_job",
            endpoint="http://127.0.0.1:8000/api",
            title="Sample Test Export Finding",
            severity=Severity.MEDIUM,
            description="Sample description"
        )
        
        generator = ReportGenerator(job, [finding])
        
        # JSON export
        json_report = generator.generate_json()
        self.assertIn("test_export_job", json_report)
        self.assertIn("target", json_report)
        
        # HTML export
        html_report = generator.generate_html()
        self.assertIn("SWA AI", html_report)
        self.assertIn("Cybersecurity Audit Report", html_report)
        
        # Markdown export
        md_report = generator.generate_markdown()
        self.assertIn("# SWA AI", md_report)
        
        # SARIF export
        sarif_report = generator.generate_sarif()
        self.assertIn("$schema", sarif_report)
        self.assertIn("sarif", sarif_report.lower())


if __name__ == "__main__":
    unittest.main()
