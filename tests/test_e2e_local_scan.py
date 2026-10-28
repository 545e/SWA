"""
Integration and End-to-End Test for SWA AI Vulnerability Scanner.
Validates the complete workflow against an authorized local lab target (http://127.0.0.1:8000):
- Scope verification and SSRF guard validation
- Scan job dispatch with lab_mode=True
- Status progression: PENDING -> RUNNING -> COMPLETED
- Real findings discovery with evidence and remediation
- Report generation across HTML, JSON, SARIF 2.1.0, CSV, and Markdown
"""

import json
import time
import urllib.request
import urllib.error
import unittest

BASE_URL = "http://127.0.0.1:8000"

class TestE2ELocalScan(unittest.TestCase):
    def test_01_ssrf_protection_blocks_unauthorized_local_scan(self):
        """Verifies SSRF guard blocks 127.0.0.1 when lab_mode is False."""
        payload = json.dumps({
            "target_url": "http://127.0.0.1:8000",
            "profile": "quick",
            "lab_mode": False
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{BASE_URL}/api/scans",
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 403)
        err_body = ctx.exception.read().decode("utf-8")
        self.assertIn("SSRF Protection", err_body)

    def test_02_e2e_authorized_scan_execution(self):
        """Verifies full scan execution against 127.0.0.1:8000 with lab_mode=True."""
        # 1. Submit scan
        payload = json.dumps({
            "target_url": "http://127.0.0.1:8000",
            "profile": "quick",
            "lab_mode": True,
            "max_depth": 1,
            "concurrency": 4
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{BASE_URL}/api/scans",
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        res = urllib.request.urlopen(req)
        self.assertEqual(res.code, 200)
        job = json.loads(res.read())
        scan_id = job["id"]
        self.assertTrue(scan_id.startswith("scan_"))

        # 2. Wait for completion
        completed = False
        final_data = None
        for _ in range(25):
            time.sleep(1.5)
            check_res = urllib.request.urlopen(f"{BASE_URL}/api/scans/{scan_id}")
            final_data = json.loads(check_res.read())
            status = final_data.get("status")
            if status == "COMPLETED":
                completed = True
                break
            elif status in ["FAILED", "CANCELLED"]:
                self.fail(f"Scan ended in unexpected status: {status}")

        self.assertTrue(completed, "Scan did not reach COMPLETED status within timeout")
        self.assertGreaterEqual(final_data.get("progress_percent", 0), 100)

        # 3. Verify findings
        findings_res = urllib.request.urlopen(f"{BASE_URL}/api/scans/{scan_id}/findings")
        findings = json.loads(findings_res.read())
        self.assertGreater(len(findings), 0, "Expected at least 1 vulnerability finding on test target")

        for f in findings:
            self.assertIn("title", f)
            self.assertIn("severity", f)
            self.assertIn("cwe_id", f)
            self.assertIn("remediation_advice", f)

        # 4. Verify report generation across all formats
        for fmt in ["html", "json", "sarif", "csv", "markdown"]:
            rep_res = urllib.request.urlopen(f"{BASE_URL}/api/scans/{scan_id}/report?format={fmt}")
            self.assertEqual(rep_res.code, 200)
            rep_text = rep_res.read().decode("utf-8", errors="ignore")
            self.assertGreater(len(rep_text), 50, f"Report format {fmt} returned unexpectedly short content")

if __name__ == "__main__":
    unittest.main()
