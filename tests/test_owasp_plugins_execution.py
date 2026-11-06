import pytest
from fastapi.testclient import TestClient
from web.server import app

client = TestClient(app)

def test_list_plugins():
    res = client.get("/api/plugins")
    assert res.status_code == 200
    plugins = res.json()
    assert len(plugins) == 10
    ids = [p["id"] for p in plugins]
    assert "owasp_a09_logging_monitoring" in ids
    assert "owasp_a10_ssrf" in ids
    assert "owasp_a01_access_control" in ids

def test_toggle_plugin():
    res = client.post("/api/plugins/owasp_a10_ssrf/toggle?enabled=false")
    assert res.status_code == 200
    data = res.json()
    assert data["plugin_id"] == "owasp_a10_ssrf"
    assert data["enabled"] is False

    # Toggle back to true
    res2 = client.post("/api/plugins/owasp_a10_ssrf/toggle?enabled=true")
    assert res2.status_code == 200
    assert res2.json()["enabled"] is True

def test_run_single_plugin_a09():
    res = client.post("/api/plugins/owasp_a09_logging_monitoring/run", json={"target": "127.0.0.1:8000", "lab_mode": True})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "COMPLETED"
    assert data["plugin_id"] == "owasp_a09_logging_monitoring"
    assert "findings" in data
    assert "passed" in data

def test_run_single_plugin_a10():
    res = client.post("/api/plugins/owasp_a10_ssrf/run", json={"target": "127.0.0.1:8000", "lab_mode": True})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "COMPLETED"
    assert data["plugin_id"] == "owasp_a10_ssrf"
    assert "findings" in data

def test_run_all_plugins():
    res = client.post("/api/plugins/run", json={"target": "127.0.0.1:8000", "lab_mode": True})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "COMPLETED"
    assert data["total_plugins"] == 10
    assert data["enabled_plugins"] >= 9
