"""
Automated Unit Tests for SWA AI Deployment Readiness & Production Operations.
Verifies WAL database health, online backup integrity, healthcheck API routes,
cross-platform installation script availability, and deployment profiles.
"""

import os
import sqlite3
import tempfile
import unittest
from fastapi.testclient import TestClient

from core.database import db
from web.server import app


class TestDeploymentReadiness(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_database_health_check(self):
        """Verifies database connectivity and WAL mode reporting."""
        h = db.check_health()
        self.assertIn("status", h)
        self.assertEqual(h["status"], "healthy")
        self.assertEqual(h.get("journal_mode"), "WAL")
        self.assertEqual(h.get("integrity"), "ok")
        self.assertIsInstance(h.get("scans_count"), int)
        self.assertIsInstance(h.get("findings_count"), int)

    def test_database_online_backup(self):
        """Verifies zero-downtime online SQLite backup execution."""
        tmp_dir = tempfile.TemporaryDirectory()
        try:
            backup_path = os.path.join(tmp_dir.name, "test_backup.db")
            res_path = db.backup_database(backup_path)
            self.assertEqual(os.path.abspath(res_path), os.path.abspath(backup_path))
            self.assertTrue(os.path.exists(res_path))
            self.assertGreater(os.path.getsize(res_path), 0)

            # Verify integrity of backup database
            conn = sqlite3.connect(res_path)
            try:
                cursor = conn.cursor()
                cursor.execute("PRAGMA quick_check(1)")
                self.assertEqual(cursor.fetchone()[0], "ok")
                cursor.execute("SELECT COUNT(*) FROM scans")
                scans_in_backup = cursor.fetchone()[0]
                self.assertGreaterEqual(scans_in_backup, 0)
            finally:
                conn.close()
        finally:
            try:
                tmp_dir.cleanup()
            except Exception:
                pass

    def test_health_and_readiness_endpoints(self):
        """Verifies /health and /ready REST endpoints for monitoring and orchestrators."""
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("status", data)
        self.assertIn("database", data)
        self.assertIn("version", data)
        self.assertEqual(data["database"]["status"], "healthy")

        ready_resp = self.client.get("/ready")
        self.assertEqual(ready_resp.status_code, 200)
        self.assertEqual(ready_resp.json(), {"ready": True})

    def test_universal_install_and_run_scripts_exist(self):
        """Verifies existence and non-empty content of all 6 universal scripts."""
        required_scripts = [
            "install.bat",
            "install.ps1",
            "install.sh",
            "run.bat",
            "run.ps1",
            "run.sh"
        ]
        for script_name in required_scripts:
            script_path = os.path.join(self.repo_root, script_name)
            self.assertTrue(os.path.exists(script_path), f"Missing script: {script_name}")
            self.assertGreater(os.path.getsize(script_path), 50, f"Script too small: {script_name}")

    def test_deployment_profiles_exist(self):
        """Verifies deployment profiles for Linux, Docker, AWS, Azure, GCP, Render & Self-Hosted."""
        required_profiles = [
            os.path.join(self.repo_root, "deploy", "linux", "swa.service"),
            os.path.join(self.repo_root, "deploy", "linux", "nginx.conf"),
            os.path.join(self.repo_root, "deploy", "linux", "deploy.sh"),
            os.path.join(self.repo_root, "deploy", "docker", "docker-compose.prod.yml"),
            os.path.join(self.repo_root, "deploy", "aws", "ecs-task-definition.json"),
            os.path.join(self.repo_root, "deploy", "aws", "ec2-user-data.sh"),
            os.path.join(self.repo_root, "deploy", "azure", "container-app.json"),
            os.path.join(self.repo_root, "deploy", "gcp", "cloudrun.yaml"),
            os.path.join(self.repo_root, "deploy", "platform", "render.yaml"),
            os.path.join(self.repo_root, "deploy", "platform", "railway.json"),
            os.path.join(self.repo_root, "deploy", "self-hosted", "offline-install.sh"),
            os.path.join(self.repo_root, "deploy", "self-hosted", "backup.sh")
        ]
        for profile in required_profiles:
            self.assertTrue(os.path.exists(profile), f"Missing deployment profile: {profile}")
            self.assertGreater(os.path.getsize(profile), 20, f"Profile too small: {profile}")


if __name__ == "__main__":
    unittest.main()
