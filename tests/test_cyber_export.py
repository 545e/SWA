"""
Unit & Integration Tests for SWA AI Cyber Export Module (Phase 8).
Verifies multi-format report exports (JSON, CSV, HTML, PDF), filtering,
sensitive data redaction, SHA-256 integrity checks, and API endpoints.
"""

import os
import json
import pytest
from fastapi.testclient import TestClient
from web.server import app
from core.cyber_export import cyber_exporter, redact_sensitive_data
from core.database import db

@pytest.fixture
def client():
    return TestClient(app)

def test_sensitive_data_redaction():
    sample = "Authorization: Bearer secret_token_1234567890abcdef and password='SuperSecretPassword123'"
    redacted = redact_sensitive_data(sample)
    assert "secret_token_1234567890abcdef" not in redacted
    assert "SuperSecretPassword123" not in redacted
    assert "[REDACTED_BY_SWA_EXPORT]" in redacted

def test_export_engine_json():
    res = cyber_exporter.export_data(
        export_type="findings",
        format_type="json",
        title="Automated Test Export JSON"
    )
    assert res["status"] == "COMPLETED"
    assert res["format"] == "json"
    assert os.path.exists(res["file_path"])
    assert res["file_size"] > 0
    assert len(res["sha256"]) == 64

    # Validate JSON structure
    with open(res["file_path"], "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "report_id" in data
    assert "data" in data

def test_export_engine_csv():
    res = cyber_exporter.export_data(
        export_type="findings",
        format_type="csv",
        title="Automated Test Export CSV"
    )
    assert res["status"] == "COMPLETED"
    assert res["format"] == "csv"
    assert os.path.exists(res["file_path"])

def test_export_engine_html_and_pdf():
    res_html = cyber_exporter.export_data(
        export_type="findings",
        format_type="html",
        title="Automated Test Export HTML"
    )
    assert res_html["status"] == "COMPLETED"
    assert os.path.exists(res_html["file_path"])

    res_pdf = cyber_exporter.export_data(
        export_type="executive",
        format_type="pdf",
        title="Automated Test Export PDF"
    )
    assert res_pdf["status"] == "COMPLETED"
    assert os.path.exists(res_pdf["file_path"])

def test_export_compliance_matrix():
    res = cyber_exporter.export_data(
        export_type="compliance",
        format_type="json",
        title="OWASP Compliance Export"
    )
    assert res["status"] == "COMPLETED"
    with open(res["file_path"], "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "compliance_standard" in data["data"]
    assert "owasp_matrix" in data["data"]

def test_export_api_endpoints(client):
    r_gen = client.post("/api/cyber/export/generate", json={
        "export_type": "findings",
        "format_type": "json",
        "title": "API Test Export"
    })
    assert r_gen.status_code == 200
    export_id = r_gen.json()["id"]

    r_hist = client.get("/api/cyber/export/history")
    assert r_hist.status_code == 200
    assert any(e["id"] == export_id for e in r_hist.json())

    r_down = client.get(f"/api/cyber/export/download/{export_id}")
    assert r_down.status_code == 200
    assert len(r_down.content) > 0
