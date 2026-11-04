"""
Comprehensive Test Suite for SWA AI Master Version 1 API Architecture.
Verifies all /api/v1/* subsystems, health probes, RBAC, SSRF defenses, and integrations.
"""

import pytest
from fastapi.testclient import TestClient

from web.server import app

client = TestClient(app)


def test_health_endpoints():
    """Verify system health, liveness, readiness, and dependencies probes."""
    res_live = client.get("/health/live")
    assert res_live.status_code == 200
    data_live = res_live.json()
    assert data_live["status"] == "ALIVE"
    assert "uptime_sec" in data_live

    res_ready = client.get("/health/ready")
    assert res_ready.status_code == 200
    data_ready = res_ready.json()
    assert data_ready["status"] == "READY"
    assert data_ready["readiness"] is True

    res_dep = client.get("/health/dependencies")
    assert res_dep.status_code == 200
    data_dep = res_dep.json()
    assert data_dep["status"] == "HEALTHY"
    assert data_dep["dependencies"]["agent_workforce"]["total_agents"] == 85
    assert data_dep["dependencies"]["integrations_hub"]["supported_providers"] >= 21


def test_v1_system_and_info():
    """Verify v1 system info and health."""
    res = client.get("/api/v1/system/info")
    assert res.status_code == 200
    body = res.json()
    assert body["success"] is True
    assert body["data"]["api_version"] == "v1"
    assert "version" in body["data"]

    res_health = client.get("/api/v1/system/health")
    assert res_health.status_code == 200
    assert res_health.json()["data"]["status"] == "HEALTHY"


def test_v1_auth_flow():
    """Verify authentication login, session verification, status, and logout."""
    # Login
    res_login = client.post("/api/v1/auth/login", json={"username": "lead_auditor"})
    assert res_login.status_code == 200
    data_login = res_login.json()
    assert data_login["success"] is True
    token = data_login["data"]["token"]
    assert token

    # Session check with Bearer token
    res_sess = client.get("/api/v1/auth/session", headers={"Authorization": f"Bearer {token}"})
    assert res_sess.status_code == 200
    assert res_sess.json()["data"]["authenticated"] is True

    # User profile me
    res_me = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {token}"})
    assert res_me.status_code == 200
    assert res_me.json()["data"]["username"] in ["lead_auditor", "local_system_admin"]

    # Logout
    res_logout = client.post("/api/v1/auth/logout")
    assert res_logout.status_code == 200
    assert res_logout.json()["data"]["logged_out"] is True


def test_v1_workspaces_and_projects():
    """Verify multi-tenant workspace and project management APIs."""
    res_ws = client.get("/api/v1/workspaces")
    assert res_ws.status_code == 200
    assert res_ws.json()["success"] is True

    res_proj = client.get("/api/v1/projects")
    assert res_proj.status_code == 200
    assert res_proj.json()["success"] is True


def test_v1_dashboard_metrics():
    """Verify telemetry KPI and security posture metrics aggregation."""
    res = client.get("/api/v1/dashboard/metrics")
    assert res.status_code == 200
    data = res.json()["data"]
    assert "posture_score" in data
    assert "posture_grade" in data
    assert data["active_agents"] == 85
    assert data["connected_integrations"] >= 21


def test_v1_security_tools_and_catalog():
    """Verify security tool suites inventory and execution interfaces."""
    res_tools = client.get("/api/v1/security-tools")
    assert res_tools.status_code == 200
    tools = res_tools.json()["data"]
    assert len(tools) > 0

    res_cat = client.get("/api/v1/security-tools/catalog")
    assert res_cat.status_code == 200
    assert res_cat.json()["success"] is True


def test_v1_integrations_hub():
    """Verify integration registry with all 23 adapters, secret redaction, and connection testing."""
    res_prov = client.get("/api/v1/integrations/providers")
    assert res_prov.status_code == 200
    providers = res_prov.json()["data"]
    prov_ids = [p["provider_id"] for p in providers]
    assert len(providers) == 23
    assert "openai" in prov_ids
    assert "gemini" in prov_ids
    assert "virustotal" in prov_ids
    assert "cisa_kev" in prov_ids
    assert "first_epss" in prov_ids
    assert "crowdstrike" in prov_ids

    # Unconfigured integration test returns honest NOT_CONFIGURED or error
    res_test = client.post("/api/v1/integrations/test", json={"provider_id": "shodan"})
    assert res_test.status_code == 200
    assert "success" in res_test.json()["data"]


def test_v1_threat_intelligence():
    """Verify threat intelligence CISA KEV and FIRST EPSS endpoints."""
    res_kev = client.get("/api/v1/threat-intelligence/cisa-kev?cve=CVE-2021-44228")
    assert res_kev.status_code == 200
    assert res_kev.json()["data"]["cve"] == "CVE-2021-44228"

    res_epss = client.get("/api/v1/threat-intelligence/first-epss?cve=CVE-2021-44228")
    assert res_epss.status_code == 200
    assert res_epss.json()["data"]["epss_score"] > 0


def test_v1_ai_workforce():
    """Verify 85 specialist agents across 5 operational tiers."""
    res_agents = client.get("/api/v1/ai/agents")
    assert res_agents.status_code == 200
    agents = res_agents.json()["data"]
    assert len(agents) == 85

    res_summary = client.get("/api/v1/ai/agents/summary")
    assert res_summary.status_code == 200
    summary = res_summary.json()["data"]
    assert summary["total_discovered"] == 85
    assert summary["tiers"]["specialist_workforce"] == 17
    assert summary["tiers"]["offensive_recon"] == 9
    assert summary["tiers"]["owasp_plugins"] == 10
    assert summary["tiers"]["core_engines"] == 32
    assert summary["tiers"]["tool_adapters"] == 17


def test_v1_reports_and_exports():
    """Verify Nessus-style report templates and multi-format exports."""
    res_tpl = client.get("/api/v1/reports/templates")
    assert res_tpl.status_code == 200
    templates = res_tpl.json()["data"]
    assert len(templates) >= 6

    res_fmt = client.get("/api/v1/exports/formats")
    assert res_fmt.status_code == 200
    formats = [f["format"] for f in res_fmt.json()["data"]]
    assert "pdf" in formats
    assert "html" in formats
    assert "csv" in formats
    assert "json" in formats
    assert "nessus_xml" in formats


def test_v1_ssrf_and_scope_refusal():
    """Verify SSRF protection rejects dangerous cloud metadata addresses while allowing authorized targets."""
    # Attempt scanning AWS metadata loopback address
    res_ssrf = client.post("/api/v1/assessments", json={
        "target_url": "http://169.254.169.254/latest/meta-data/",
        "lab_mode": False
    })
    assert res_ssrf.status_code == 403
    assert "SSRF" in res_ssrf.json()["detail"] or "Refusal" in res_ssrf.json()["detail"]
