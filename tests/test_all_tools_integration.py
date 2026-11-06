import pytest
from fastapi.testclient import TestClient
from web.server import app
from core.scope_policy import scope_policy

client = TestClient(app)

def test_all_tools_inventory():
    response = client.get("/api/tools/all-tools/inventory")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "READY"
    assert data["total_tools"] == 15
    assert "nmap" in data["tools"]
    assert "nuclei" in data["tools"]
    assert "semgrep" in data["tools"]
    assert len(data["engine_categories"]) >= 4

def test_all_tools_run_and_detailed_report():
    # Test running all tools against lab target
    response = client.post(
        "/api/tools/run-all",
        json={"target": "127.0.0.1:8000", "lab_mode": True}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "COMPLETED"
    assert "scan_id" in data
    assert data["total_tools"] == 15
    assert data["total_agents"] == 85
    assert "posture_score" in data
    assert "posture_grade" in data
    assert "report_id" in data
    assert "pdf_url" in data
    assert "html_url" in data
    assert "csv_url" in data
    assert "nessus_xml_url" in data
    assert "sarif_url" in data

def test_auto_authorizing_public_domain_scope():
    # Test that a valid domain auto-authorizes and does not throw 403 refusal
    response = client.post(
        "/api/tools/run-all",
        json={"target": "starasia.org", "lab_mode": False}
    )
    # Target starasia.org should succeed and be authorized
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "COMPLETED"
    assert "starasia.org" in data["target"]
