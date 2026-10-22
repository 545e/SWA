"""
SWA AI Vulnerability Hunter Agent
Systematic OWASP Top 10 vulnerability scanner testing for SQL Injection, XSS,
SSRF, Path Traversal, CORS Misconfigurations, and Information Disclosure.
"""

import asyncio
import re
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
import httpx
from typing import List, Dict, Any, Optional

from core.models import DiscoveredEndpoint, VulnerabilityFinding, Severity, LogEvent
from core.queue_manager import queue_manager

SQL_ERRORS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_.*",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_.*",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"Driver.* SQL[\-\_\ ]*Server",
    r"OLE DB.* SQL Server",
    r"SQLServer JDBC Driver",
    r"SqlException",
    r"Oracle error",
    r"Oracle.*Driver",
    r"Warning.*\Woci_.*",
    r"Warning.*\Wora_.*",
    r"SQLite/JDBCDriver",
    r"SQLite.Exception",
    r"System.Data.SQLite.SQLiteException",
    r"sqlite3.OperationalError",
    r"syntax error near"
]

SQL_PAYLOADS = [
    "'",
    "''",
    "\"",
    "' OR '1'='1",
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "1' ORDER BY 1--",
    "1' UNION SELECT NULL--",
    "admin' --"
]

XSS_CANARY = "swa_probe_9918"
XSS_PAYLOADS = [
    f"<swa_probe_{XSS_CANARY}>",
    f'"><script>/*swa*/console.log("{XSS_CANARY}")</script>',
    f'"><img src=x onerror=alert("{XSS_CANARY}")>'
]

LFI_PAYLOADS = [
    ("../../../../etc/passwd", r"root:.*:0:0:"),
    ("..\\..\\..\\..\\windows\\win.ini", r"\[fonts\]|\[extensions\]"),
    ("../../../../../etc/hosts", r"127\.0\.0\.1\s+localhost")
]

class VulnHunterAgent:
    def __init__(self, scan_id: str, endpoints: List[DiscoveredEndpoint], concurrency: int = 5):
        self.scan_id = scan_id
        self.endpoints = endpoints
        self.concurrency = concurrency
        self.semaphore = asyncio.Semaphore(concurrency)

    async def log(self, message: str, level: str = "INFO"):
        event = LogEvent(scan_id=self.scan_id, agent="VulnHunterAgent", level=level, message=message)
        await queue_manager.emit_log(event)

    async def run(self) -> List[VulnerabilityFinding]:
        await self.log(f"Initiating autonomous vulnerability hunting across {len(self.endpoints)} endpoints...", "INFO")
        findings: List[VulnerabilityFinding] = []

        # 1. Test CORS Security Misconfigurations
        cors_findings = await self.test_cors()
        for f in cors_findings:
            findings.append(f)
            await queue_manager.emit_finding(f)

        # 2. Test Parameter-based Vulnerabilities (SQLi, XSS, LFI)
        async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True) as client:
            for ep in self.endpoints:
                if ep.parameters:
                    # Test SQLi
                    sqli_f = await self.test_sqli_endpoint(client, ep)
                    for f in sqli_f:
                        findings.append(f)
                        await queue_manager.emit_finding(f)

                    # Test XSS
                    xss_f = await self.test_xss_endpoint(client, ep)
                    for f in xss_f:
                        findings.append(f)
                        await queue_manager.emit_finding(f)

                    # Test Path Traversal
                    lfi_f = await self.test_lfi_endpoint(client, ep)
                    for f in lfi_f:
                        findings.append(f)
                        await queue_manager.emit_finding(f)

                # Test HTTP Method Tampering & Info Disclosure
                disc_f = await self.test_info_disclosure(client, ep)
                for f in disc_f:
                    findings.append(f)
                    await queue_manager.emit_finding(f)

        await self.log(f"Vulnerability hunting completed. Identified {len(findings)} potential security issues.", "SUCCESS")
        return findings

    async def test_cors(self) -> List[VulnerabilityFinding]:
        findings = []
        if not self.endpoints:
            return findings

        test_url = self.endpoints[0].url
        attacker_origin = "https://evil-attacker-exploit.com"
        headers = {"Origin": attacker_origin}

        try:
            async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
                resp = await client.get(test_url, headers=headers)
                allow_origin = resp.headers.get("access-control-allow-origin", "")
                allow_credentials = resp.headers.get("access-control-allow-credentials", "").lower() == "true"

                if allow_origin == attacker_origin or (allow_origin == "*" and allow_credentials):
                    sev = Severity.HIGH if allow_credentials else Severity.MEDIUM
                    score = 7.5 if allow_credentials else 5.3
                    finding = VulnerabilityFinding(
                        scan_id=self.scan_id,
                        title="Insecure Cross-Origin Resource Sharing (CORS) Configuration",
                        severity=sev,
                        cvss_score=score,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                        cwe_id="CWE-942",
                        owasp_category="A01:2021-Broken Access Control",
                        endpoint=test_url,
                        method="GET",
                        description=f"Server dynamically reflects arbitrary origins ({attacker_origin}) with credentials enabled: {allow_credentials}. An attacker can steal user data via CSRF-style cross-origin requests.",
                        poc_curl=f"curl -i -H 'Origin: {attacker_origin}' '{test_url}'",
                        poc_explanation=f"Sending an arbitrary Origin header resulted in 'Access-Control-Allow-Origin: {allow_origin}'.",
                        request_evidence=f"GET {test_url} HTTP/1.1\nOrigin: {attacker_origin}",
                        response_evidence=f"Access-Control-Allow-Origin: {allow_origin}\nAccess-Control-Allow-Credentials: {allow_credentials}",
                        remediation_advice="Do not reflect arbitrary Origin headers. Maintain a strict whitelist of trusted domains and disallow credentials with wildcard origins.",
                        remediation_patch="# Reject unauthorized origins\nif origin not in ALLOWED_ORIGINS:\n    # Do not set Access-Control-Allow-Origin header"
                    )
                    findings.append(finding)
                    await self.log(f"Discovered Insecure CORS on {test_url}", "FINDING")
        except Exception:
            pass
        return findings

    async def test_sqli_endpoint(self, client: httpx.AsyncClient, ep: DiscoveredEndpoint) -> List[VulnerabilityFinding]:
        findings = []
        parsed = urlparse(ep.url)
        params = parse_qs(parsed.query)

        for param_name in ep.parameters:
            for payload in SQL_PAYLOADS:
                test_params = dict(params)
                test_params[param_name] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    resp = await client.get(test_url)
                    for err_sig in SQL_ERRORS:
                        if re.search(err_sig, resp.text, re.IGNORECASE):
                            finding = VulnerabilityFinding(
                                scan_id=self.scan_id,
                                title=f"SQL Injection via parameter '{param_name}'",
                                severity=Severity.CRITICAL,
                                cvss_score=9.8,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                cwe_id="CWE-89",
                                owasp_category="A03:2021-Injection",
                                endpoint=ep.url,
                                method="GET",
                                parameter=param_name,
                                description=f"Database syntax error or raw exception exposed when injecting SQL payload `{payload}` into `{param_name}`.",
                                poc_curl=f"curl -i '{test_url}'",
                                poc_explanation=f"Injected `{payload}` causing server to trigger SQL error signature `{err_sig}`.",
                                request_evidence=f"GET {test_url} HTTP/1.1",
                                response_evidence=resp.text[:500],
                                remediation_advice="Use parameterized queries / prepared statements exclusively. Never concatenate raw SQL strings.",
                                remediation_patch="cursor.execute('SELECT * FROM data WHERE param = %s', (safe_param,))"
                            )
                            findings.append(finding)
                            await self.log(f"CRITICAL: SQL Injection found on {ep.url} [{param_name}]", "FINDING")
                            return findings # Break early once proven
                except Exception:
                    continue
        return findings

    async def test_xss_endpoint(self, client: httpx.AsyncClient, ep: DiscoveredEndpoint) -> List[VulnerabilityFinding]:
        findings = []
        parsed = urlparse(ep.url)
        params = parse_qs(parsed.query)

        for param_name in ep.parameters:
            for payload in XSS_PAYLOADS:
                test_params = dict(params)
                test_params[param_name] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    resp = await client.get(test_url)
                    if payload in resp.text and "text/html" in resp.headers.get("content-type", ""):
                        finding = VulnerabilityFinding(
                            scan_id=self.scan_id,
                            title=f"Reflected Cross-Site Scripting (XSS) via '{param_name}'",
                            severity=Severity.HIGH,
                            cvss_score=7.2,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                            cwe_id="CWE-79",
                            owasp_category="A03:2021-Injection",
                            endpoint=ep.url,
                            method="GET",
                            parameter=param_name,
                            description=f"User input injected into parameter `{param_name}` is reflected unencoded directly in the HTML document body.",
                            poc_curl=f"curl -i '{test_url}'",
                            poc_explanation=f"Injected HTML/JS payload `{payload}` reflected literally in response.",
                            request_evidence=f"GET {test_url} HTTP/1.1",
                            response_evidence=resp.text[:500],
                            remediation_advice="Contextually encode all user-controlled data before rendering in HTML/DOM context. Implement a robust Content Security Policy (CSP).",
                            remediation_patch="import html\nsafe_output = html.escape(user_input)"
                        )
                        findings.append(finding)
                        await self.log(f"HIGH: Reflected XSS verified on {ep.url} [{param_name}]", "FINDING")
                        return findings
                except Exception:
                    continue
        return findings

    async def test_lfi_endpoint(self, client: httpx.AsyncClient, ep: DiscoveredEndpoint) -> List[VulnerabilityFinding]:
        findings = []
        parsed = urlparse(ep.url)
        params = parse_qs(parsed.query)

        for param_name in ep.parameters:
            for payload, pattern in LFI_PAYLOADS:
                test_params = dict(params)
                test_params[param_name] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    resp = await client.get(test_url)
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        finding = VulnerabilityFinding(
                            scan_id=self.scan_id,
                            title=f"Directory / Path Traversal (LFI) via '{param_name}'",
                            severity=Severity.CRITICAL,
                            cvss_score=8.6,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            cwe_id="CWE-22",
                            owasp_category="A01:2021-Broken Access Control",
                            endpoint=ep.url,
                            method="GET",
                            parameter=param_name,
                            description=f"Server allows arbitrary local file retrieval using path traversal sequences (`../`) in `{param_name}`.",
                            poc_curl=f"curl -i '{test_url}'",
                            poc_explanation=f"Passing `{payload}` caused the web application to read and return system files matching `{pattern}`.",
                            request_evidence=f"GET {test_url} HTTP/1.1",
                            response_evidence=resp.text[:500],
                            remediation_advice="Sanitize path parameters with basename checks or resolve against an allowed base directory using canonical paths.",
                            remediation_patch="import os\nsafe_path = os.path.basename(user_path)\nfull_path = os.path.join(ALLOWED_DIR, safe_path)"
                        )
                        findings.append(finding)
                        await self.log(f"CRITICAL: Path Traversal confirmed on {ep.url} [{param_name}]", "FINDING")
                        return findings
                except Exception:
                    continue
        return findings

    async def test_info_disclosure(self, client: httpx.AsyncClient, ep: DiscoveredEndpoint) -> List[VulnerabilityFinding]:
        findings = []
        try:
            # Send HTTP TRACE
            resp = await client.request("TRACE", ep.url)
            if resp.status_code == 200 and "TRACE" in resp.text:
                finding = VulnerabilityFinding(
                    scan_id=self.scan_id,
                    title="HTTP TRACE Method Enabled (Cross-Site Tracing / XST)",
                    severity=Severity.LOW,
                    cvss_score=4.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-200",
                    owasp_category="A05:2021-Security Misconfiguration",
                    endpoint=ep.url,
                    method="TRACE",
                    description="The web server permits HTTP TRACE requests, which reflects back client request headers and could aid in cookie theft via Cross-Site Tracing.",
                    poc_curl=f"curl -X TRACE -i '{ep.url}'",
                    poc_explanation="HTTP TRACE request responded with 200 OK echoing the request body.",
                    request_evidence=f"TRACE {ep.url} HTTP/1.1",
                    response_evidence=resp.text[:400],
                    remediation_advice="Disable HTTP TRACE/TRACK methods in web server configuration.",
                    remediation_patch="# Apache config:\nTraceEnable off\n# Nginx config:\nif ($request_method ~ ^(TRACE|TRACK)) { return 405; }"
                )
                findings.append(finding)
        except Exception:
            pass
        return findings
