"""
Automated Integration and Acceptance Tests for AI Automation, Workflows,
Cyber Testing, and Deployment Operations in SWA AI.
"""

import unittest
from fastapi.testclient import TestClient
from web.server import app
from core.database import db
from core.automation_engine import automation_engine


class TestAiAutomationAndOperations(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_automation_workflows_catalog(self):
        """Workflow catalog returns pre-seeded autonomous security workflows."""
        resp = self.client.get("/api/automation/workflows")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 4)

        # Verify default full pentest workflow exists
        full_wf = next((w for w in data if w["id"] == "wf-full-pentest-01"), None)
        self.assertIsNotNone(full_wf)
        self.assertEqual(full_wf["steps_count"], 11)
        self.assertTrue(full_wf["enabled"])

    def test_02_create_and_duplicate_workflow(self):
        """Create a custom workflow and duplicate it."""
        payload = {
            "name": "Custom Integration Test Pipeline",
            "description": "Validates API and worker dispatching",
            "category": "Integration Testing",
            "steps": [
                {"step_id": "s1", "name": "Scope Probe", "action_type": "scope_check"},
                {"step_id": "s2", "name": "Agent Sync", "action_type": "agent_task", "agent_id": "supervisor"}
            ]
        }
        create_resp = self.client.post("/api/automation/workflows", json=payload)
        self.assertEqual(create_resp.status_code, 200)
        created = create_resp.json()
        self.assertEqual(created["name"], payload["name"])
        wf_id = created["id"]

        # Duplicate workflow
        dup_resp = self.client.post(f"/api/automation/workflows/{wf_id}/duplicate")
        self.assertEqual(dup_resp.status_code, 200)
        duplicated = dup_resp.json()
        self.assertIn("Copy", duplicated["name"])

        # Toggle enabled
        toggle_resp = self.client.post(f"/api/automation/workflows/{wf_id}/toggle")
        self.assertEqual(toggle_resp.status_code, 200)
        self.assertFalse(toggle_resp.json()["enabled"])

        # Clean up
        del_resp = self.client.delete(f"/api/automation/workflows/{wf_id}")
        self.assertEqual(del_resp.status_code, 200)
        self.client.delete(f"/api/automation/workflows/{duplicated['id']}")

    def test_03_execute_workflow_on_authorized_target(self):
        """Execute full 11-step autonomous pentest workflow on authorized test target."""
        run_resp = self.client.post("/api/automation/workflows/wf-full-pentest-01/run", json={
            "target": "http://127.0.0.1:8000",
            "initiated_by": "Automated_QA_Runner"
        })
        self.assertEqual(run_resp.status_code, 200)
        data = run_resp.json()
        self.assertEqual(data["status"], "COMPLETED")
        self.assertEqual(data["current_step"], 11)
        self.assertEqual(data["total_steps"], 11)
        self.assertGreaterEqual(len(data["step_logs"]), 11)

        # Check execution history
        hist_resp = self.client.get("/api/automation/executions")
        self.assertEqual(hist_resp.status_code, 200)
        execs = hist_resp.json()
        self.assertGreaterEqual(len(execs), 1)

        # Check execution details
        exec_id = data["id"]
        det_resp = self.client.get(f"/api/automation/executions/{exec_id}")
        self.assertEqual(det_resp.status_code, 200)
        det = det_resp.json()
        self.assertEqual(det["id"], exec_id)
        self.assertIn("step_logs", det)

    def test_04_cyber_testing_suite_execution(self):
        """Execute cyber test suite and retrieve results."""
        resp = self.client.post("/api/cyber/test/run", json={
            "profile": "smoke",
            "target_url": "http://127.0.0.1:8000"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("results", data)
        self.assertIn("run", data)
        self.assertGreaterEqual(data["run"]["passed_count"], 1)

        # Test runs history
        hist_resp = self.client.get("/api/cyber/test/runs")
        self.assertEqual(hist_resp.status_code, 200)
        self.assertIsInstance(hist_resp.json(), list)

    def test_05_cyber_deploy_and_acceptance_checklist(self):
        """Verify deployment initiation and latest acceptance checklist (§52)."""
        # Initiate deployment in local environment
        dep_resp = self.client.post("/api/cyber/deploy/initiate", json={
            "environment": "LOCAL",
            "method": "local_process",
            "release_id": "v2.3.0-Test",
            "approved_by": "QA_Lead"
        })
        self.assertEqual(dep_resp.status_code, 200)
        dep = dep_resp.json()
        self.assertIn("id", dep)

        # Retrieve acceptance checklist
        chk_resp = self.client.get("/api/cyber/deploy/latest/acceptance-checklist")
        self.assertEqual(chk_resp.status_code, 200)
        chk = chk_resp.json()
        self.assertIn("sections", chk)
        self.assertIn("overall_status", chk)
        self.assertEqual(chk["overall_status"], "ACCEPTED WITH DOCUMENTED LIMITATIONS")
        self.assertEqual(len(chk["sections"]), 10)

    def test_06_frontend_ui_navigation_and_views_presence(self):
        """Verify restored navigation strip, all tools section, and new views in HTML."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.text

        # Verify Master Top SOC Navigation Strip
        self.assertIn('id="socTopStrip"', html)
        self.assertIn('topNavDashboard', html)
        self.assertIn('topNavAssessments', html)
        self.assertIn('topNavAutomation', html)
        self.assertIn('topNavTools', html)
        self.assertIn('topNavAgents', html)

        # Verify Restored All Tools section
        self.assertIn('id="allToolsSection"', html)
        self.assertIn('id="allToolsTarget"', html)
        self.assertIn('id="btnRunAllTools"', html)

        # Verify viewAiAutomation and viewCyberDeploy
        self.assertIn('id="viewAiAutomation"', html)
        self.assertIn('id="viewCyberDeploy"', html)
        self.assertIn('id="viewCyberTest"', html)

        # Verify sidebar items for new views
        self.assertIn("navToView('ai_automation')", html)
        self.assertIn("navToView('security_testing')", html)
        self.assertIn("navToView('api_testing')", html)
        self.assertIn("navToView('ai_models')", html)
        self.assertIn("navToView('api_keys')", html)


if __name__ == "__main__":
    unittest.main()
