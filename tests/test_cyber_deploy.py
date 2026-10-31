"""
Unit & Integration Tests for SWA AI Cyber Deploy Module (Phase 10).
Verifies the 11-step enterprise deployment lifecycle, environment configurations,
production human approval gate, health validation, and rollback mechanism.
"""

import pytest
from fastapi.testclient import TestClient
from web.server import app
from core.cyber_deploy import cyber_deployer
from core.database import db

@pytest.fixture
def client():
    return TestClient(app)

def test_local_deployment_lifecycle():
    dep = cyber_deployer.initiate_deployment(environment="local")
    assert dep["status"] == "COMPLETED"
    assert dep["current_step"] == "11/11: COMPLETED"
    assert dep["health_status"] == "HEALTHY"
    assert dep["completed_at"] is not None
    assert "PRECHECK" in dep["logs"]
    assert "BUILD" in dep["logs"]
    assert "TEST" in dep["logs"]
    assert "COMPLETE" in dep["logs"]

def test_production_deployment_approval_gate():
    # Production must be held at stage 7/11 until approved
    dep = cyber_deployer.initiate_deployment(environment="production")
    assert dep["status"] == "APPROVAL_PENDING"
    assert dep["current_step"] == "7/11: APPROVAL_PENDING"
    assert "GATE HELD" in dep["logs"]

    # Now approve
    approved = cyber_deployer.approve_deployment(dep["id"], approver="SecOps_Director")
    assert approved["status"] == "COMPLETED"
    assert approved["approved_by"] == "SecOps_Director"
    assert approved["current_step"] == "11/11: COMPLETED"

def test_deployment_rollback():
    dep = cyber_deployer.initiate_deployment(environment="local")
    dep_id = dep["id"]

    rb = cyber_deployer.rollback_deployment(dep_id, operator="Lead_SRE")
    assert rb["status"] == "ROLLED_BACK"
    assert "ROLLED_BACK to" in rb["current_step"]
    assert "ROLLBACK invoked by 'Lead_SRE'" in rb["logs"]

def test_deploy_api_endpoints(client):
    r_init = client.post("/api/cyber/deploy/initiate", json={"environment": "production"})
    assert r_init.status_code == 200
    dep_id = r_init.json()["id"]
    assert r_init.json()["status"] == "APPROVAL_PENDING"

    r_app = client.post(f"/api/cyber/deploy/{dep_id}/approve", json={"approver": "API_Admin"})
    assert r_app.status_code == 200
    assert r_app.json()["status"] == "COMPLETED"

    r_rb = client.post(f"/api/cyber/deploy/{dep_id}/rollback", json={"operator": "API_Admin"})
    assert r_rb.status_code == 200
    assert r_rb.json()["status"] == "ROLLED_BACK"

    r_hist = client.get("/api/cyber/deploy/history")
    assert r_hist.status_code == 200
    assert any(d["id"] == dep_id for d in r_hist.json())
