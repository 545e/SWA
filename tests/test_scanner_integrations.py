"""
Unit tests for SWA AI Cybersecurity Tool Integrations and Dependency Scanners.
Verifies tool inventory structure, graceful fallback for missing binaries,
safe argument list generation, SQLmap lab authorization guard, and manifest auditing.
"""

import asyncio
import unittest
from core.scanner_integrations import ScannerIntegrations
from core.models import Severity

class TestScannerIntegrations(unittest.TestCase):
    def test_tool_inventory_structure(self):
        inv = ScannerIntegrations.get_tool_inventory()
        required_tools = ["nmap", "nuclei", "owasp_zap", "sqlmap", "swa_native"]
        for tool in required_tools:
            self.assertIn(tool, inv, f"Tool '{tool}' must exist in tool inventory")
            tool_meta = inv[tool]
            self.assertIn("name", tool_meta)
            self.assertIn("installed", tool_meta)
            self.assertIn("capability", tool_meta)
            self.assertIn("install_guide", tool_meta)
            self.assertIsInstance(tool_meta["installed"], bool)

        # SWA AI Native Engines must always be installed
        self.assertTrue(inv["swa_native"]["installed"])
        self.assertIn("Built-in Python 3.12 Engine", inv["swa_native"]["binary_path"])

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
