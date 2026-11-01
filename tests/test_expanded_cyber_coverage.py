"""
SWA AI — Test Suite for Expanded Cybersecurity Tools and Vulnerability Coverage
Tests:
- Complete SQL Injection Testing Engine (Error, Boolean, Time, JSON, Multi-DB)
- Complete Injection Vulnerability Suite (XSS, SSTI, Command, Traversal, CRLF, Open Redirect)
- Antivirus, Endpoint & Malware Protection Manager (Telemetry & 15-Product Evaluation Matrix)
- Identity & Access Security Auditor (JWT alg none, exp claim, credentials leak, session cookies, OAuth PKCE/state)
- Extended Scanner Integrations Inventory
"""

import pytest
import os
import asyncio
import httpx
from urllib.parse import unquote
from core.sqli_engine import sqli_engine, DB_ENGINE_SIGNATURES
from core.injection_suite import injection_suite
from core.antivirus_edr_manager import antivirus_edr_manager, AV_EVALUATION_DATABASE
from core.identity_access_auditor import identity_access_auditor
from core.scanner_integrations import ScannerIntegrations
from core.tool_registry import tool_registry


# -------------------------------------------------------------
# 1. SQL Injection Engine Tests
# -------------------------------------------------------------
def test_sqli_db_engine_detection():
    # MySQL
    assert sqli_engine.detect_db_engine("Warning: mysql_fetch_array(): supplied argument...") == "MySQL / MariaDB"
    # PostgreSQL
    assert sqli_engine.detect_db_engine("ERROR: syntax error at or near 'SELECT'") == "PostgreSQL"
    # MSSQL
    assert sqli_engine.detect_db_engine("Microsoft OLE DB Provider for SQL Server: Unclosed quotation mark") == "Microsoft SQL Server"
    # Oracle
    assert sqli_engine.detect_db_engine("ORA-01756: quoted string not properly terminated") == "Oracle Database"
    # SQLite
    assert sqli_engine.detect_db_engine("sqlite3.OperationalError: near 'admin': syntax error") == "SQLite"
    # Clean text
    assert sqli_engine.detect_db_engine("Welcome to the enterprise dashboard! Status: OK") is None


def test_sqli_error_based_audit():
    def handler(request: httpx.Request):
        url_decoded = unquote(str(request.url))
        if "'" in url_decoded:
            return httpx.Response(500, text="Microsoft OLE DB Provider for SQL Server: Unclosed quotation mark after the character string")
        return httpx.Response(200, text="User profile: Alice")

    async def _run():
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            return await sqli_engine.audit_url_parameter(
                client=client,
                scan_id="test_sqli_01",
                target_url="http://mock-target.local/profile?id=101",
                param_name="id"
            )

    findings = asyncio.run(_run())
    assert len(findings) >= 1
    f = findings[0]
    assert "SQL Injection (Error-Based)" in f.title
    assert "Microsoft SQL Server" in f.title
    assert f.severity.value == "CRITICAL"
    assert f.cwe_id == "CWE-89"


def test_sqli_json_payload_audit():
    def handler(request: httpx.Request):
        content = request.read().decode("utf-8")
        if "'" in content:
            return httpx.Response(500, text="You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version")
        return httpx.Response(200, text='{"status": "authenticated"}')

    async def _run():
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            return await sqli_engine.audit_json_payload(
                client=client,
                scan_id="test_json_sqli",
                target_url="http://mock-target.local/api/login",
                json_data={"username": "admin", "role": "user"}
            )

    findings = asyncio.run(_run())
    assert len(findings) >= 1
    assert "MySQL / MariaDB" in findings[0].title


# -------------------------------------------------------------
# 2. Complete Injection Suite Tests
# -------------------------------------------------------------
def test_xss_audit():
    def handler(request: httpx.Request):
        url_decoded = unquote(str(request.url))
        if "swa_probe_swa_xss_probe_canary_8471" in url_decoded:
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text="<div>Search results for: <swa_probe_swa_xss_probe_canary_8471></div>")
        return httpx.Response(200, headers={"Content-Type": "text/html"}, text="Search page")

    async def _run():
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            return await injection_suite.audit_xss(
                client=client,
                scan_id="test_xss_01",
                url="http://mock-target.local/search?q=test",
                param="q"
            )

    findings = asyncio.run(_run())
    assert len(findings) == 1
    assert "Reflected Cross-Site Scripting" in findings[0].title
    assert findings[0].cwe_id == "CWE-79"


def test_ssti_audit():
    def handler(request: httpx.Request):
        url_decoded = unquote(str(request.url))
        if "{{47*47}}" in url_decoded:
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text="Hello user 2209!")
        return httpx.Response(200, headers={"Content-Type": "text/html"}, text="Hello user!")

    async def _run():
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            return await injection_suite.audit_ssti(
                client=client,
                scan_id="test_ssti_01",
                url="http://mock-target.local/greet?name=test",
                param="name"
            )

    findings = asyncio.run(_run())
    assert len(findings) == 1
    assert "Server-Side Template Injection" in findings[0].title
    assert findings[0].cwe_id == "CWE-1336"


def test_command_injection_audit():
    def handler(request: httpx.Request):
        url_decoded = unquote(str(request.url))
        if "swa_cmd_eval_9182" in url_decoded:
            return httpx.Response(200, text="Pinging host...\nswa_cmd_eval_9182\nPackets: Sent = 1")
        return httpx.Response(200, text="Pinging host...")

    async def _run():
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            return await injection_suite.audit_command_injection(
                client=client,
                scan_id="test_cmd_01",
                url="http://mock-target.local/ping?host=127.0.0.1",
                param="host"
            )

    findings = asyncio.run(_run())
    assert len(findings) >= 1
    assert "OS Command Injection" in findings[0].title
    assert findings[0].cwe_id == "CWE-78"


def test_path_traversal_audit():
    def handler(request: httpx.Request):
        url_decoded = unquote(str(request.url))
        if "etc/passwd" in url_decoded or "win.ini" in url_decoded:
            return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
        return httpx.Response(200, text="File content: sample document")

    async def _run():
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            return await injection_suite.audit_path_traversal(
                client=client,
                scan_id="test_lfi_01",
                url="http://mock-target.local/view?file=report.pdf",
                param="file"
            )

    findings = asyncio.run(_run())
    assert len(findings) == 1
    assert "Path Traversal" in findings[0].title
    assert findings[0].cwe_id == "CWE-22"


def test_crlf_header_injection_audit():
    def handler(request: httpx.Request):
        url_decoded = unquote(str(request.url))
        if "X-SWA-Injected" in url_decoded or "x-swa-injected" in url_decoded:
            return httpx.Response(200, headers={"X-SWA-Injected": "confirmed"}, text="Header set")
        return httpx.Response(200, text="Normal response")

    async def _run():
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            return await injection_suite.audit_crlf_header_injection(
                client=client,
                scan_id="test_crlf_01",
                url="http://mock-target.local/lang?set=en",
                param="set"
            )

    findings = asyncio.run(_run())
    assert len(findings) == 1
    assert "CRLF / HTTP Header Injection" in findings[0].title


def test_open_redirect_audit():
    def handler(request: httpx.Request):
        url_decoded = unquote(str(request.url))
        if "evil-attacker-redirect-domain.com" in url_decoded:
            return httpx.Response(302, headers={"Location": "https://evil-attacker-redirect-domain.com/login"})
        return httpx.Response(200, text="Home")

    async def _run():
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            return await injection_suite.audit_open_redirect(
                client=client,
                scan_id="test_redirect_01",
                url="http://mock-target.local/out?url=dashboard",
                param="url"
            )

    findings = asyncio.run(_run())
    assert len(findings) == 1
    assert "Open Redirect" in findings[0].title


# -------------------------------------------------------------
# 3. Antivirus, Endpoint & Malware Protection Tests
# -------------------------------------------------------------
def test_antivirus_manager_evaluation_matrix():
    matrix = antivirus_edr_manager.get_evaluation_matrix()
    assert len(matrix) == 15
    
    # Verify TotalAV has honest status and no public API
    totalav = antivirus_edr_manager.get_product("totalav")
    assert totalav is not None
    assert totalav["has_public_api"] is False
    assert totalav["status"] == "NOT_APPLICABLE"
    assert "UNSUPPORTED BY DESIGN" in totalav["integration_decision"]

    # Verify Microsoft Defender has public API/CLI
    defender = antivirus_edr_manager.get_product("microsoft_defender")
    assert defender is not None
    assert defender["has_public_api"] is True
    assert defender["has_local_cli"] is True
    assert defender["status"] == "EXISTS_AND_VERIFIED"

    # Verify CrowdStrike Falcon has API
    cs = antivirus_edr_manager.get_product("crowdstrike_falcon")
    assert cs is not None
    assert cs["has_public_api"] is True
    assert cs["status"] == "INTEGRATED_NOT_CONFIGURED"


def test_antivirus_live_host_telemetry():
    telemetry = antivirus_edr_manager.get_live_host_telemetry()
    assert "host_platform" in telemetry
    if os.name == "nt":
        # On Windows host, verify Microsoft Defender detection
        assert telemetry["host_platform"] == "Windows"
        assert telemetry["mpcmdrun_cli_available"] is True
        assert telemetry["antivirus_enabled"] is True


# -------------------------------------------------------------
# 4. Identity & Access Security Tests
# -------------------------------------------------------------
def test_jwt_alg_none_audit():
    hdr = "eyJhbGciOiAibm9uZSIgfQ" # {"alg": "none"}
    pay = "eyJzdWIiOiAiYWRtaW4iLCAicm9sZSI6ICJzdXBlcnVzZXIifQ" # {"sub": "admin", "role": "superuser"}
    token = f"{hdr}.{pay}."

    findings = identity_access_auditor.audit_jwt_token(token)
    assert len(findings) >= 1
    titles = [f.title for f in findings]
    assert any("Unsigned 'none' Algorithm Allowed" in t for t in titles)
    assert any("Missing Expiration Claim" in t for t in titles)


def test_jwt_sensitive_leakage_audit():
    import base64
    hdr = base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode("utf-8").rstrip("=")
    pay = base64.urlsafe_b64encode(b'{"user":"alice", "api_key":"secret_9182312", "exp": 1999999999}').decode("utf-8").rstrip("=")
    token = f"{hdr}.{pay}.fakesig"

    findings = identity_access_auditor.audit_jwt_token(token)
    assert len(findings) >= 1
    assert any("Sensitive Credentials Disclosed" in f.title for f in findings)


def test_session_cookie_flags_audit():
    # Missing HttpOnly and Secure
    bad_cookie = "session_token=abc123xyz; Path=/; SameSite=Lax"
    findings = identity_access_auditor.audit_session_cookie(bad_cookie)
    assert len(findings) == 2
    titles = [f.title for f in findings]
    assert "Session Cookie Missing 'HttpOnly' Flag" in titles
    assert "Session Cookie Missing 'Secure' Flag" in titles

    # Secure and HttpOnly present
    good_cookie = "session_token=abc123xyz; Path=/; HttpOnly; Secure; SameSite=Strict"
    findings_good = identity_access_auditor.audit_session_cookie(good_cookie)
    assert len(findings_good) == 0


def test_oauth_redirect_uri_audit():
    bad_auth_url = "https://auth.company.local/oauth/authorize?client_id=web_app&response_type=code&redirect_uri=https://app.company.local/cb"
    findings = identity_access_auditor.audit_oauth_redirect_uri(bad_auth_url)
    assert len(findings) == 2
    titles = [f.title for f in findings]
    assert any("Missing 'state' CSRF Protection" in t for t in titles)
    assert any("Missing PKCE ('code_challenge')" in t for t in titles)


# -------------------------------------------------------------
# 5. Tool Registry & Scanner Integrations Verification
# -------------------------------------------------------------
def test_tool_registry_expanded_tools():
    assert tool_registry.get("websec_sqli_suite") is not None
    assert tool_registry.get("websec_injection_expanded") is not None
    assert tool_registry.get("endpoint_av_edr_manager") is not None
    assert tool_registry.get("identity_access_auditor") is not None


def test_scanner_integrations_extended_inventory():
    inv = ScannerIntegrations.get_tool_inventory()
    assert "microsoft_defender" in inv
    assert "clamav" in inv
    assert "wazuh" in inv
    assert "swa_native" in inv
    assert inv["microsoft_defender"]["installed"] is True
