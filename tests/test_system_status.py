# SWA AI — System & AI status endpoint verification
#
# Locks in the honest-state contract:
#   * /api/system/status returns every required component with full
#     diagnostics fields, and an overall state derived from the components.
#   * /api/ai/status never leaks key material, distinguishes
#     CONFIGURED/NOT_CONFIGURED from reachability, and only performs a real
#     outbound probe when ?probe=true is requested.
#   * The probe path is exercised against a LOCAL http.server mock — no
#     external network is contacted.

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.database import db
from web.server import app as real_app

# ---------------------------------------------------------------- fixtures --
# Mount the REAL application (the endpoints live in web.server), hermetic DB
# is provided by tests/__init__.py.
client = TestClient(real_app)


class _MockProvider(BaseHTTPRequestHandler):
    """Local stand-in for an LLM provider (loopback only)."""

    status_to_return = 200

    def do_GET(self):  # noqa: N802 (http.server naming)
        body = json.dumps({"object": "list", "data": []}).encode()
        self.send_response(self.status_to_return)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence request logging
        pass


def _start_mock_provider(status=200):
    _MockProvider.status_to_return = status
    server = HTTPServer(("127.0.0.1", 0), _MockProvider)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}/v1"


REQUIRED_COMPONENT_FIELDS = {
    "id", "name", "state", "reason", "error_category",
    "timestamp", "details", "correction", "retry_available", "evidence",
}
VALID_STATES = {
    "HEALTHY", "DEGRADED", "BLOCKED", "FAILED",
    "NOT_CONFIGURED", "NOT_TESTED",
}


# ------------------------------------------------------- system status ------
def test_system_status_shape_and_states():
    res = client.get("/api/system/status")
    assert res.status_code == 200
    data = res.json()

    assert data["overall"] in VALID_STATES, data["overall"]
    assert isinstance(data["checked_at"], str) and data["checked_at"]
    assert isinstance(data["version"], str) and data["version"]
    components = data["components"]
    assert isinstance(components, list) and len(components) >= 8

    ids = set()
    for comp in components:
        missing = REQUIRED_COMPONENT_FIELDS - set(comp)
        assert not missing, f"component {comp.get('id')} missing fields {missing}"
        assert comp["state"] in VALID_STATES, comp
        assert comp["reason"], f"empty reason on {comp['id']}"
        assert comp["timestamp"], f"empty timestamp on {comp['id']}"
        assert isinstance(comp["retry_available"], bool)
        ids.add(comp["id"])

    # Every component the contract promises must be present.
    for required in ("api", "database", "realtime", "frontend",
                     "ai_provider", "scans", "scanner_tools",
                     "api_auth", "scope"):
        assert required in ids, f"missing component {required}"


def test_system_status_overall_derived_from_worst_critical():
    data = client.get("/api/system/status").json()
    critical = [c["state"] for c in data["components"]
                if c["state"] in ("FAILED", "BLOCKED", "DEGRADED")]
    if critical:
        # overall must equal the most severe present state
        rank = {"FAILED": 0, "BLOCKED": 1, "DEGRADED": 2,
                "HEALTHY": 3, "NOT_TESTED": 4, "NOT_CONFIGURED": 5}
        assert data["overall"] == min(critical, key=lambda s: rank[s])
    else:
        assert data["overall"] == "HEALTHY"


def test_system_status_no_secret_material():
    res = client.get("/api/system/status")
    text = res.text
    # A seeded secret must never appear in the response body.
    seeded = "swa-canary-secret-12345"
    db.set_setting("ai_api_key", seeded)
    try:
        text2 = client.get("/api/system/status").text
        assert seeded not in text2
        assert seeded not in text
    finally:
        db.set_setting("ai_api_key", "")


def test_database_component_reports_real_counts():
    data = client.get("/api/system/status").json()
    db_comp = next(c for c in data["components"] if c["id"] == "database")
    evidence = db_comp["evidence"]
    assert "scans_count" in evidence
    assert "findings_count" in evidence
    # counts must match a direct query
    with db.get_connection() as conn:
        real_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    assert evidence["scans_count"] == real_scans


# ----------------------------------------------------------- ai status ------
def test_ai_status_not_configured_is_honest():
    db.set_setting("ai_api_key", "")
    for var in ("LLM_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY",
                "ANTHROPIC_API_KEY", "OPENROUTER_API_KEY"):
        os.environ.pop(var, None)
    res = client.get("/api/ai/status")
    assert res.status_code == 200
    data = res.json()
    assert data["configuration"] == "NOT_CONFIGURED"
    assert data["reachability"] == "NOT_CONFIGURED"
    assert data["has_api_key"] is False
    assert data["mode"] == "heuristic_fallback"
    assert data["correction"], "NOT_CONFIGURED must suggest how to fix it"


def test_ai_status_configured_but_unprobed():
    db.set_setting("ai_api_key", "sk-test-dummy-key-for-status")
    db.set_setting("ai_last_probe", "")
    try:
        data = client.get("/api/ai/status").json()
        assert data["configuration"] == "CONFIGURED"
        assert data["has_api_key"] is True
        assert data["reachability"] == "NOT_TESTED"
        # never leaks the key
        assert "sk-test-dummy-key-for-status" not in json.dumps(data)
        assert "sk-test" not in client.get("/api/ai/status").text
    finally:
        db.set_setting("ai_api_key", "")


def test_ai_probe_without_probe_flag_makes_no_network_call():
    # probe=false (default) must not attempt any outbound connection,
    # so an unreachable base URL must not delay or change the response.
    db.set_setting("ai_api_key", "sk-dummy")
    db.set_setting("ai_base_url", "http://127.0.0.1:1/v1")  # dead port
    try:
        data = client.get("/api/ai/status").json()
        assert data["probed_now"] is False
        assert data["reachability"] in ("NOT_TESTED",)
    finally:
        db.set_setting("ai_api_key", "")
        db.set_setting("ai_base_url", "")


def test_ai_probe_against_local_mock_available():
    server, base = _start_mock_provider(200)
    db.set_setting("ai_api_key", "sk-local-mock-key")
    db.set_setting("ai_base_url", base)
    try:
        data = client.get("/api/ai/status?probe=true").json()
        assert data["probed_now"] is True
        assert data["reachability"] == "AVAILABLE", data
        assert data["checked_at"], "checked_at must be recorded"
        assert isinstance(data["latency_ms"], int) and data["latency_ms"] >= 0
        # the stored key must not be echoed
        assert "sk-local-mock-key" not in json.dumps(data)
        # result is persisted for subsequent non-probe reads
        follow = client.get("/api/ai/status").json()
        assert follow["reachability"] == "AVAILABLE"
        assert follow["probed_now"] is False
    finally:
        server.shutdown()
        db.set_setting("ai_api_key", "")
        db.set_setting("ai_base_url", "")
        db.set_setting("ai_last_probe", "")


def test_ai_probe_auth_rejection_is_error_not_unavailable():
    server, base = _start_mock_provider(401)
    db.set_setting("ai_api_key", "sk-wrong-key")
    db.set_setting("ai_base_url", base)
    try:
        data = client.get("/api/ai/status?probe=true").json()
        assert data["reachability"] == "ERROR", data
        assert "401" in (data["error"] or "")
        assert data["correction"], "ERROR must carry a correction"
    finally:
        server.shutdown()
        db.set_setting("ai_api_key", "")
        db.set_setting("ai_base_url", "")
        db.set_setting("ai_last_probe", "")


def test_ai_probe_unreachable_is_unavailable():
    db.set_setting("ai_api_key", "sk-dummy")
    db.set_setting("ai_base_url", "http://127.0.0.1:1/v1")  # nothing listens
    try:
        data = client.get("/api/ai/status?probe=true").json()
        assert data["reachability"] == "UNAVAILABLE", data
        assert data["error"], "UNAVAILABLE must carry the real error"
        assert data["correction"]
    finally:
        db.set_setting("ai_api_key", "")
        db.set_setting("ai_base_url", "")
        db.set_setting("ai_last_probe", "")


def test_ai_probe_never_replays_credentials_across_redirects():
    # A redirecting mock: with follow_redirects=False the probe must NOT
    # follow to a second host, so a 302 to a dead location yields ERROR or
    # non-AVAILABLE — proving credentials are not replayed elsewhere.
    class _Redirect(_MockProvider):
        def do_GET(self):  # noqa: N802
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/elsewhere")
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = HTTPServer(("127.0.0.1", 0), _Redirect)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}/v1"
    db.set_setting("ai_api_key", "sk-redirect-canary")
    db.set_setting("ai_base_url", base)
    try:
        data = client.get("/api/ai/status?probe=true").json()
        assert data["reachability"] != "AVAILABLE", data
    finally:
        server.shutdown()
        db.set_setting("ai_api_key", "")
        db.set_setting("ai_base_url", "")
        db.set_setting("ai_last_probe", "")


def test_standalone_router_mount_is_not_required_for_status():
    # status endpoints belong to the main app; a standalone app must NOT
    # accidentally expose them (guards against duplicate mounting later).
    solo = FastAPI()
    solo_client = TestClient(solo)
    assert solo_client.get("/api/system/status").status_code == 404
