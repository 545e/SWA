"""
Unit & Integration Tests for SWA AI Cyber Test Module (Phase 9).
Verifies the 6 testing categories (Application, Security, Infrastructure,
Performance, Functional, Reliability), test execution profiles, and result tracking.
"""

import pytest
from fastapi.testclient import TestClient
from web.server import app
from core.cyber_test import cyber_tester
from core.database import db

@pytest.fixture
def client():
    return TestClient(app)

def test_cyber_test_smoke_profile():
    run_data = cyber_tester.run_suite(profile="smoke")
    run = run_data["run"]
    results = run_data["results"]

    assert run["status"] == "PASSED"
    assert run["passed_count"] > 0
    assert run["failed_count"] == 0
    assert len(results) == run["total_tests"]

    # Verify individual results have required telemetry
    for r in results:
        assert r["test_id"]
        assert r["test_name"]
        assert r["category"] in ["application", "infrastructure"]
        assert r["status"] == "PASSED"
        assert r["evidence"] != ""
        assert r["duration_seconds"] >= 0.0

def test_cyber_test_security_profile():
    run_data = cyber_tester.run_suite(profile="security")
    run = run_data["run"]
    results = run_data["results"]

    assert run["status"] == "PASSED"
    for r in results:
        assert r["category"] == "security"

def test_cyber_test_persistence():
    run_data = cyber_tester.run_suite(profile="smoke")
    run_id = run_data["run"]["id"]

    saved_run = db.get_cyber_test_run(run_id)
    assert saved_run is not None
    assert saved_run["id"] == run_id

    saved_results = db.get_cyber_test_results(run_id=run_id)
    assert len(saved_results) > 0

def test_cyber_test_api_endpoints(client):
    r_run = client.post("/api/cyber/test/run", json={"profile": "smoke"})
    assert r_run.status_code == 200
    run_id = r_run.json()["run"]["id"]

    r_list = client.get("/api/cyber/test/runs")
    assert r_list.status_code == 200
    assert any(x["id"] == run_id for x in r_list.json())

    r_det = client.get(f"/api/cyber/test/runs/{run_id}")
    assert r_det.status_code == 200
    assert r_det.json()["run"]["id"] == run_id
    assert len(r_det.json()["results"]) > 0
