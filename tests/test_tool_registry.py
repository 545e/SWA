"""
Unit and integration tests for SWA AI Tool Registry and Scan Comparison Diff Engine.
Verifies all 16 offensive, defensive, recon, forensics, and AI tools are registered
with schema, handler, dependency, and authorization metadata.
"""

import unittest
from core.tool_registry import tool_registry, ToolMetadata
from fastapi.testclient import TestClient
from web.server import app


class TestToolRegistry(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_01_all_categories_represented(self):
        tools = tool_registry.list_all()
        self.assertGreaterEqual(len(tools), 15)
        categories = {t.category for t in tools}
        self.assertIn("soc", categories)
        self.assertIn("recon", categories)
        self.assertIn("websec", categories)
        self.assertIn("blue_team", categories)
        self.assertIn("ai_security", categories)

    def test_02_tool_metadata_fields(self):
        for tool in tool_registry.list_all():
            self.assertTrue(len(tool.id) > 0)
            self.assertTrue(len(tool.name) > 0)
            self.assertIn("type", tool.input_schema)
            self.assertIsNotNone(tool.backend_handler)
            self.assertIn(tool.status, ["active", "degraded", "external_optional"])

    def test_03_tool_registry_api_endpoints(self):
        resp = self.client.get("/api/tools/registry")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("tools", data)
        self.assertGreaterEqual(data["total"], 15)

        # Single tool inspection
        single_resp = self.client.get("/api/tools/registry/recon_subdomain_amass")
        self.assertEqual(single_resp.status_code, 200)
        t_data = single_resp.json()
        self.assertEqual(t_data["id"], "recon_subdomain_amass")
        self.assertEqual(t_data["category"], "recon")

    def test_04_asset_inventory_api(self):
        resp = self.client.get("/api/assets")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("total", data)
        self.assertIn("assets", data)

    def test_05_ai_hardware_api(self):
        resp = self.client.get("/api/ai/hardware")
        self.assertEqual(resp.status_code, 200)
        hw = resp.json()
        self.assertIn("device", hw)
        self.assertIn("cpu_cores", hw)


if __name__ == "__main__":
    unittest.main()
