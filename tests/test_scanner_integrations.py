"""
Unit tests for SWA AI Cybersecurity Tool Integrations and Dependency Scanners.
Verifies tool inventory structure for 11 tools, graceful fallback for missing binaries,
safe argument list generation, SQLmap lab authorization guard, manifest auditing,
command reference catalog, and safe health-check execution.
"""

import asyncio
import unittest
from core.scanner_integrations import ScannerIntegrations
from core.models import Severity

class TestScannerIntegrations(unittest.TestCase):
    def test_tool_inventory_structure(self):
        inv = ScannerIntegrations.get_tool_inventory()
        required_tools = [
            "nmap", "nuclei", "owasp_zap", "sqlmap", "nikto",
            "tshark", "semgrep", "bandit", "trivy", "gitleaks", "swa_native"
        ]
        self.assertEqual(len(inv), 11)
        for tool in required_tools:
            self.assertIn(tool, inv, f"Tool '{tool}' must exist in tool inventory")
            tool_meta = inv[tool]
            self.assertIn("name", tool_meta)
            self.assertIn("installed", tool_meta)
            self.assertIn("capability", tool_meta)
            self.assertIn("install_guide", tool_meta)
            self.assertIn("supported_os", tool_meta)
            self.assertIn("output_format", tool_meta)
            self.assertIsInstance(tool_meta["installed"], bool)

        # SWA AI Native Engines must always be installed
        self.assertTrue(inv["swa_native"]["installed"])
        self.assertIn("Built-in Python 3.12 Engine", inv["swa_native"]["binary_path"])

    def test_command_reference_structure(self):
        refs = ScannerIntegrations.get_command_reference()
        self.assertGreaterEqual(len(refs), 8)
        for ref in refs:
            self.assertIn("tool", ref)
            self.assertIn("command", ref)
            self.assertIn("purpose", ref)
            self.assertIn("options", ref)
            self.assertIn("expected_input", ref)
            self.assertIn("expected_output", ref)
            self.assertIn("local_lab_example", ref)
            self.assertIn("safety_considerations", ref)
            self.assertIn("common_errors", ref)

    def test_health_check_native(self):
        res = asyncio.run(ScannerIntegrations.run_tool_health_check("swa_native"))
        self.assertEqual(res["status"], "HEALTHY")
        self.assertTrue(res["installed"])
        self.assertIn("latency_ms", res)

    def test_health_check_uninstalled(self):
        res = asyncio.run(ScannerIntegrations.run_tool_health_check("nmap"))
        self.assertEqual(res["status"], "UNAVAILABLE")
        self.assertFalse(res["installed"])
        self.assertIn("Install via", res["message"])

    def test_health_check_invalid(self):
        res = asyncio.run(ScannerIntegrations.run_tool_health_check("nonexistent_tool_xyz"))
        self.assertEqual(res["status"], "NOT_FOUND")

    def test_sqlmap_refusal_without_lab_mode(self):
        findings, meta = asyncio.run(ScannerIntegrations.run_sqlmap_safe_detection(
            target_url="http://127.0.0.1:8000",
            scan_id="test_scan",
            is_lab_mode_authorized=False
        ))
        self.assertEqual(len(findings), 0)
        self.assertFalse(meta["executed"])
        self.assertIn("Requires explicit Lab Mode confirmation", meta["reason"])

    def test_dependency_manifest_scan_python(self):
        vuln_reqs = "requests==2.28.1\nDjango==2.2.10\nurllib3==1.26.5\n"
        findings = ScannerIntegrations.scan_dependency_manifest(
            manifest_filename="requirements.txt",
            content=vuln_reqs,
            scan_id="test_dep_scan"
        )
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, Severity.HIGH)
        self.assertEqual(f.cwe_id, "CWE-1104")
        self.assertIn("Django Framework (2.2.10)", f.title)
        self.assertIn("Django>=4.2.16", f.remediation_patch)

    def test_dependency_manifest_scan_node(self):
        vuln_package_json = '{"dependencies": {"express": "4.17.1", "lodash": "4.17.20"}}'
        findings = ScannerIntegrations.scan_dependency_manifest(
            manifest_filename="package.json",
            content=vuln_package_json,
            scan_id="test_dep_node"
        )
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, Severity.HIGH)
        self.assertEqual(f.cwe_id, "CWE-1321")
        self.assertIn("lodash", f.title)
        self.assertIn("4.17.21", f.remediation_patch)

    def test_dependency_manifest_clean(self):
        clean_reqs = "requests==2.31.0\nDjango==5.0.2\nfastapi==0.110.0\n"
        findings = ScannerIntegrations.scan_dependency_manifest(
            manifest_filename="requirements.txt",
            content=clean_reqs,
            scan_id="test_dep_clean"
        )
        self.assertEqual(len(findings), 0)

if __name__ == "__main__":
    unittest.main()
