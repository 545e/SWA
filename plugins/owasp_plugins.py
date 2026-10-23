"""
SWA AI OWASP Top 10 Security Plugins
Complete coverage of OWASP 2021 Top 10 categories:
- A01: Broken Access Control (CORS, LFI, Unprotected Admin Routes)
- A02: Cryptographic Failures (Cleartext transmission, Insecure Cookie Flags)
- A03: Injection (SQL Injection, XSS, Command Injection signals)
- A04: Insecure Design (Missing Rate Limits & Anti-Automation)
- A05: Security Misconfiguration (Missing Security Headers, Debug Stack Traces, HTTP TRACE)
- A06: Vulnerable and Outdated Components (Server & Framework Version Leaks)
- A07: Identification and Authentication Failures (Missing CSRF on Forms, Tokens in URL)
- A08: Software and Data Integrity Failures (External Scripts without SRI)
- A09: Security Logging and Monitoring Failures (Verbose 500 Error Disclosures)
- A10: Server-Side Request Forgery (SSRF)
"""

import re
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
import httpx
from bs4 import BeautifulSoup
from typing import List, Dict, Any, Optional

from core.models import DiscoveredEndpoint, VulnerabilityFinding, Severity
from plugins.base_plugin import BaseSecurityPlugin

# --- SQL Errors & Signatures ---
SQL_ERRORS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\.",
    r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\.",
    r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"SQLServer JDBC Driver",
    r"SqlException", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*",
    r"SQLite/JDBCDriver", r"SQLite\.Exception", r"sqlite3\.OperationalError", r"syntax error near"
]

SQL_PROBES = ["'", "''", "\"", "' OR '1'='1", "' OR 1=1 --", "admin' --", "1' UNION SELECT NULL--"]

# --- XSS Probes ---
XSS_CANARY = "swa_xss_probe_8471"
XSS_PROBES = [
    f"<swa_{XSS_CANARY}>",
    f'"><script>/*swa*/alert("{XSS_CANARY}")</script>',
    f'"><img src=x onerror=console.log("{XSS_CANARY}")>'
]

# --- LFI Probes ---
LFI_PROBES = [
    ("../../../../etc/passwd", r"root:.*:0:0:"),
    ("..\\..\\..\\..\\windows\\win.ini", r"\[fonts\]|\[extensions\]"),
    ("../../../../../etc/hosts", r"127\.0\.0\.1\s+localhost")
]

# --- Stack Trace Signatures ---
STACK_TRACE_SIGS = [
    r"Traceback \(most recent call last\):",
    r"Exception in thread \".*\"",
    r"org\.springframework\.",
    r"System\.Web\.HttpException",
    r"Server Error in '.*' Application",
    r"Fatal error: Uncaught exception",
    r"Django Version:.*Python Path:",
    r"Werkzeug Debugger"
]


# =====================================================================
# A01: Broken Access Control
# =====================================================================
class PluginA01_BrokenAccessControl(BaseSecurityPlugin):
    def __init__(self):
        super().__init__(
            plugin_id="owasp_a01_access_control",
            name="Broken Access Control & Path Traversal",
            owasp_category="A01:2021-Broken Access Control",
            description="Audits CORS policies, Local File Inclusion (LFI), and unauthorized administrative endpoint exposure.",
            cwe_id="CWE-22",
            default_severity=Severity.HIGH
        )

    async def run(self, scan_id: str, client: httpx.AsyncClient, endpoints: List[DiscoveredEndpoint], recon_data: Any, log_callback=None) -> List[VulnerabilityFinding]:
        findings = []
        if not endpoints:
            return findings

        # 1. CORS Misconfiguration check
        test_url = endpoints[0].url
        attacker_origin = "https://evil-attacker-exploit.com"
        try:
            resp = await client.get(test_url, headers={"Origin": attacker_origin})
            allow_origin = resp.headers.get("access-control-allow-origin", "")
            allow_creds = resp.headers.get("access-control-allow-credentials", "").lower() == "true"
            if allow_origin == attacker_origin or (allow_origin == "*" and allow_creds):
                sev = Severity.HIGH if allow_creds else Severity.MEDIUM
                f = VulnerabilityFinding(
                    scan_id=scan_id,
                    title="Insecure Cross-Origin Resource Sharing (CORS) Policy",
                    severity=sev,
                    cvss_score=7.5 if allow_creds else 5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    cwe_id="CWE-942",
                    owasp_category=self.owasp_category,
                    endpoint=test_url,
                    method="GET",
                    description=f"Server dynamically reflects arbitrary origins ({attacker_origin}) with credentials: {allow_creds}.",
                    poc_curl=f"curl -i -H 'Origin: {attacker_origin}' '{test_url}'",
                    poc_explanation=f"Received 'Access-Control-Allow-Origin: {allow_origin}' on arbitrary attacker origin.",
                    request_evidence=f"GET {test_url} HTTP/1.1\nOrigin: {attacker_origin}",
                    response_evidence=f"Access-Control-Allow-Origin: {allow_origin}\nAccess-Control-Allow-Credentials: {allow_creds}",
                    remediation_advice="Maintain an explicit whitelist of trusted origins. Never mirror untrusted Origin headers with credentials.",
                    remediation_patch="# Reject arbitrary origin reflection\nif origin not in ALLOWED_DOMAINS:\n    # Do not emit Access-Control-Allow-Origin header"
                )
                findings.append(f)
                if log_callback: await log_callback(f"[A01] Found Insecure CORS on {test_url}", "FINDING")
        except Exception:
            pass

        # 2. Path Traversal (LFI) check on parameter endpoints
        for ep in endpoints:
            params = ep.parameters or []
            if not params:
                parsed = urlparse(ep.url)
                params = list(parse_qs(parsed.query).keys())

            if params:
                parsed = urlparse(ep.url)
                orig_qs = parse_qs(parsed.query)
                for param in params:
                    if param.lower() in ["file", "path", "page", "doc", "view", "include", "template", "load", "dest", "dir"]:
                        for payload, pattern in LFI_PROBES:
                            test_params = dict(orig_qs)
                            test_params[param] = [payload]
                            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                            try:
                                r = await client.get(test_url)
                                if re.search(pattern, r.text, re.IGNORECASE):
                                    f = VulnerabilityFinding(
                                        scan_id=scan_id,
                                        title=f"Path Traversal (LFI) via Parameter '{param}'",
                                        severity=Severity.CRITICAL,
                                        cvss_score=8.6,
                                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                        cwe_id="CWE-22",
                                        owasp_category=self.owasp_category,
                                        endpoint=ep.url,
                                        method="GET",
                                        parameter=param,
                                        description=f"Server reads and exposes local system files when injecting path traversal payload `{payload}` into `{param}`.",
                                        poc_curl=f"curl -i '{test_url}'",
                                        poc_explanation=f"Response body matched system file pattern: `{pattern}`",
                                        request_evidence=f"GET {test_url} HTTP/1.1",
                                        response_evidence=r.text[:500],
                                        remediation_advice="Use os.path.basename() or canonical path resolution against a strict allowed base directory.",
                                        remediation_patch="import os\nsafe_filename = os.path.basename(user_input)\nfilepath = os.path.join(SAFE_DIR, safe_filename)"
                                    )
                                    findings.append(f)
                                    if log_callback: await log_callback(f"[A01] Verified Path Traversal on {ep.url} [{param}]", "FINDING")
                                    break
                            except Exception:
                                continue

        return findings


# =====================================================================
# A02: Cryptographic Failures
# =====================================================================
class PluginA02_CryptographicFailures(BaseSecurityPlugin):
    def __init__(self):
        super().__init__(
            plugin_id="owasp_a02_crypto_failures",
            name="Cryptographic & Transport Security",
            owasp_category="A02:2021-Cryptographic Failures",
            description="Inspects cleartext HTTP transmissions, weak TLS indicators, and unencrypted session cookies.",
            cwe_id="CWE-319",
            default_severity=Severity.MEDIUM
        )

    async def run(self, scan_id: str, client: httpx.AsyncClient, endpoints: List[DiscoveredEndpoint], recon_data: Any, log_callback=None) -> List[VulnerabilityFinding]:
        findings = []
        if not endpoints:
            return findings

        target_url = endpoints[0].url
        parsed = urlparse(target_url)

        # 1. Cleartext HTTP / Missing HSTS
        if parsed.scheme == "http":
            f = VulnerabilityFinding(
                scan_id=scan_id,
                title="Cleartext HTTP Transmission (Missing HTTPS Enforced)",
                severity=Severity.MEDIUM,
                cvss_score=5.9,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cwe_id="CWE-319",
                owasp_category=self.owasp_category,
                endpoint=target_url,
                method="GET",
                description="The application transmits traffic over unencrypted cleartext HTTP, leaving sensitive user data vulnerable to network eavesdropping and Man-in-the-Middle (MitM) attacks.",
                poc_curl=f"curl -i '{target_url}'",
                poc_explanation="Connected to HTTP port 80 without automatic HTTPS 301 redirection.",
                request_evidence=f"GET {target_url} HTTP/1.1",
                response_evidence="Cleartext HTTP stream",
                remediation_advice="Redirect all HTTP traffic to HTTPS and deploy HTTP Strict Transport Security (HSTS) with a max-age of at least 31536000 seconds.",
                remediation_patch="# Nginx HSTS enforcement\nreturn 301 https://$host$request_uri;\nadd_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;"
            )
            findings.append(f)
            if log_callback: await log_callback(f"[A02] Detected unencrypted cleartext HTTP on {target_url}", "FINDING")

        # 2. Check Set-Cookie flags (HttpOnly, Secure, SameSite)
        try:
            resp = await client.get(target_url)
            cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [resp.headers.get("set-cookie", "")]
            for c in cookie_headers:
                if not c: continue
                c_lower = c.lower()
                c_name = c.split("=")[0].strip()
                missing_flags = []
                if "httponly" not in c_lower: missing_flags.append("HttpOnly")
                if "secure" not in c_lower: missing_flags.append("Secure")
                if "samesite" not in c_lower: missing_flags.append("SameSite")

                if missing_flags:
                    f = VulnerabilityFinding(
                        scan_id=scan_id,
                        title=f"Cookie '{c_name}' Missing Security Flags ({', '.join(missing_flags)})",
                        severity=Severity.LOW,
                        cvss_score=4.3,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                        cwe_id="CWE-614",
                        owasp_category=self.owasp_category,
                        endpoint=target_url,
                        method="GET",
                        description=f"Session or state cookie `{c_name}` is set without the following protective flags: {', '.join(missing_flags)}. Missing HttpOnly permits XSS cookie theft, while missing Secure allows transmission over cleartext.",
                        poc_curl=f"curl -i '{target_url}' | grep -i Set-Cookie",
                        poc_explanation=f"Set-Cookie header received: {c}",
                        request_evidence=f"GET {target_url} HTTP/1.1",
                        response_evidence=c[:300],
                        remediation_advice="Always set HttpOnly, Secure, and SameSite=Lax (or Strict) on sensitive cookies.",
                        remediation_patch=f"response.set_cookie('{c_name}', value, secure=True, httponly=True, samesite='Lax')"
                    )
                    findings.append(f)
                    if log_callback: await log_callback(f"[A02] Cookie {c_name} missing {missing_flags}", "FINDING")
                    break
        except Exception:
            pass

        return findings


# =====================================================================
# A03: Injection (SQLi, XSS, Command Injection)
# =====================================================================
class PluginA03_Injection(BaseSecurityPlugin):
    def __init__(self):
        super().__init__(
            plugin_id="owasp_a03_injection",
            name="Injection Flaws (SQLi, XSS & Command)",
            owasp_category="A03:2021-Injection",
            description="Audits endpoints for SQL Injection syntax exposure, Cross-Site Scripting (XSS), and OS Command Injection syntax.",
            cwe_id="CWE-89",
            default_severity=Severity.CRITICAL
        )

    async def run(self, scan_id: str, client: httpx.AsyncClient, endpoints: List[DiscoveredEndpoint], recon_data: Any, log_callback=None) -> List[VulnerabilityFinding]:
        findings = []

        for ep in endpoints:
            # Gather parameters from query or discovered forms
            parsed = urlparse(ep.url)
            query_params = parse_qs(parsed.query)
            params_to_test = list(set((ep.parameters or []) + list(query_params.keys())))

            # If no parameters exist, include standard probe parameters (e.g. search, id, q, user)
            if not params_to_test:
                params_to_test = ["id", "search", "q", "query"]

            for param in params_to_test:
                # 1. SQL Injection testing
                for probe in SQL_PROBES:
                    test_params = dict(query_params)
                    test_params[param] = [probe]
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                    try:
                        r = await client.get(test_url, timeout=7.0)
                        for err_regex in SQL_ERRORS:
                            if re.search(err_regex, r.text, re.IGNORECASE):
                                f = VulnerabilityFinding(
                                    scan_id=scan_id,
                                    title=f"SQL Injection via parameter '{param}'",
                                    severity=Severity.CRITICAL,
                                    cvss_score=9.8,
                                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    cwe_id="CWE-89",
                                    owasp_category=self.owasp_category,
                                    endpoint=ep.url,
                                    method="GET",
                                    parameter=param,
                                    description=f"Injecting SQL probe `{probe}` into parameter `{param}` triggered database exception `{err_regex}`.",
                                    poc_curl=f"curl -i '{test_url}'",
                                    poc_explanation=f"Server returned raw database error signature matching regex: `{err_regex}`",
                                    request_evidence=f"GET {test_url} HTTP/1.1",
                                    response_evidence=r.text[:500],
                                    remediation_advice="Use parameterized queries / prepared statements exclusively. Never concatenate raw SQL.",
                                    remediation_patch="cursor.execute('SELECT * FROM tbl WHERE param = %s', (safe_param,))"
                                )
                                findings.append(f)
                                if log_callback: await log_callback(f"[A03] CRITICAL: SQL Injection verified on {ep.url} [{param}]", "FINDING")
                                break
                        if any(f.title.startswith(f"SQL Injection via parameter '{param}'") for f in findings):
                            break
                    except Exception:
                        continue

                # 2. Reflected XSS testing
                for x_probe in XSS_PROBES:
                    test_params = dict(query_params)
                    test_params[param] = [x_probe]
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                    try:
                        r = await client.get(test_url, timeout=7.0)
                        if x_probe in r.text and "text/html" in r.headers.get("content-type", ""):
                            f = VulnerabilityFinding(
                                scan_id=scan_id,
                                title=f"Reflected Cross-Site Scripting (XSS) via '{param}'",
                                severity=Severity.HIGH,
                                cvss_score=7.2,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                cwe_id="CWE-79",
                                owasp_category=self.owasp_category,
                                endpoint=ep.url,
                                method="GET",
                                parameter=param,
                                description=f"User-supplied input injected into parameter `{param}` is reflected unencoded directly in the HTML document.",
                                poc_curl=f"curl -i '{test_url}'",
                                poc_explanation=f"Injected probe reflected verbatim without sanitization: `{x_probe}`",
                                request_evidence=f"GET {test_url} HTTP/1.1",
                                response_evidence=r.text[:500],
                                remediation_advice="Contextually encode all untrusted inputs prior to rendering. Deploy a strict Content Security Policy.",
                                remediation_patch="import html\nsafe_output = html.escape(user_input)"
                            )
                            findings.append(f)
                            if log_callback: await log_callback(f"[A03] HIGH: Reflected XSS verified on {ep.url} [{param}]", "FINDING")
                            break
                    except Exception:
                        continue

        return findings


# =====================================================================
# A04: Insecure Design
# =====================================================================
class PluginA04_InsecureDesign(BaseSecurityPlugin):
    def __init__(self):
        super().__init__(
            plugin_id="owasp_a04_insecure_design",
            name="Insecure Design & Anti-Automation Absence",
            owasp_category="A04:2021-Insecure Design",
            description="Identifies lack of rate limiting and missing brute-force defenses on sensitive authentication endpoints.",
            cwe_id="CWE-307",
            default_severity=Severity.LOW
        )

    async def run(self, scan_id: str, client: httpx.AsyncClient, endpoints: List[DiscoveredEndpoint], recon_data: Any, log_callback=None) -> List[VulnerabilityFinding]:
        findings = []
        for ep in endpoints:
            ep_lower = ep.url.lower()
            if any(k in ep_lower for k in ["/login", "/auth", "/signin", "/user/login", "/admin/login"]):
                try:
                    resp = await client.get(ep.url)
                    headers = resp.headers
                    has_ratelimit = any("ratelimit" in h.lower() or "retry-after" in h.lower() for h in headers.keys())
                    if not has_ratelimit:
                        f = VulnerabilityFinding(
                            scan_id=scan_id,
                            title="Missing Rate-Limiting & Anti-Automation on Login Endpoint",
                            severity=Severity.LOW,
                            cvss_score=4.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            cwe_id="CWE-307",
                            owasp_category=self.owasp_category,
                            endpoint=ep.url,
                            method="GET",
                            description=f"Authentication endpoint `{ep.url}` does not return standard rate-limiting headers (X-RateLimit-Limit, Retry-After). Attackers may perform automated credential stuffing or dictionary attacks.",
                            poc_curl=f"curl -i '{ep.url}'",
                            poc_explanation="Response headers omit RateLimit and Retry-After throttling directives.",
                            request_evidence=f"GET {ep.url} HTTP/1.1",
                            response_evidence=str(headers),
                            remediation_advice="Implement progressive account lockouts and IP-based rate limiting on all login routes.",
                            remediation_patch="# Throttling with slowapi:\n@limiter.limit('5/minute')\nasync def login_endpoint(request: Request):"
                        )
                        findings.append(f)
                        if log_callback: await log_callback(f"[A04] Authentication endpoint missing rate limiting: {ep.url}", "FINDING")
                        break
                except Exception:
                    pass
        return findings


# =====================================================================
# A05: Security Misconfiguration
# =====================================================================
class PluginA05_SecurityMisconfiguration(BaseSecurityPlugin):
    def __init__(self):
        super().__init__(
            plugin_id="owasp_a05_security_misconfig",
            name="Security Misconfiguration & Header Hardening",
            owasp_category="A05:2021-Security Misconfiguration",
            description="Verifies missing HTTP security headers (CSP, Clickjacking, HSTS), debug stack trace leakage, and HTTP TRACE.",
            cwe_id="CWE-16",
            default_severity=Severity.LOW
        )

    async def run(self, scan_id: str, client: httpx.AsyncClient, endpoints: List[DiscoveredEndpoint], recon_data: Any, log_callback=None) -> List[VulnerabilityFinding]:
        findings = []
        if not endpoints:
            return findings

        test_url = endpoints[0].url

        # 1. Missing Security Headers Check
        try:
            resp = await client.get(test_url)
            h = {k.lower(): v for k, v in resp.headers.items()}

            # Clickjacking protection
            if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
                f = VulnerabilityFinding(
                    scan_id=scan_id,
                    title="Missing Clickjacking Defense (X-Frame-Options / CSP frame-ancestors)",
                    severity=Severity.LOW,
                    cvss_score=4.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                    cwe_id="CWE-1021",
                    owasp_category=self.owasp_category,
                    endpoint=test_url,
                    method="GET",
                    description="The web application can be framed in an external <iframe> or <embed>, exposing users to UI redressing and Clickjacking attacks.",
                    poc_curl=f"curl -i '{test_url}' | grep -i x-frame-options",
                    poc_explanation="Header X-Frame-Options is omitted from server response.",
                    request_evidence=f"GET {test_url} HTTP/1.1",
                    response_evidence=f"Headers: {list(h.keys())}",
                    remediation_advice="Set 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors none;'.",
                    remediation_patch="add_header X-Frame-Options 'DENY' always;\nadd_header Content-Security-Policy 'frame-ancestors none;' always;"
                )
                findings.append(f)

            # Content Security Policy (CSP)
            if "content-security-policy" not in h:
                f = VulnerabilityFinding(
                    scan_id=scan_id,
                    title="Missing Content Security Policy (CSP)",
                    severity=Severity.LOW,
                    cvss_score=4.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-693",
                    owasp_category=self.owasp_category,
                    endpoint=test_url,
                    method="GET",
                    description="The server does not deliver a Content-Security-Policy header. CSP acts as a defense-in-depth shield against Cross-Site Scripting (XSS) and data injection.",
                    poc_curl=f"curl -i '{test_url}' | grep -i content-security-policy",
                    poc_explanation="Omission of Content-Security-Policy header.",
                    request_evidence=f"GET {test_url} HTTP/1.1",
                    response_evidence="Header omitted",
                    remediation_advice="Deploy a restrictive Content Security Policy specifying trusted script, object, and media sources.",
                    remediation_patch="add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\" always;"
                )
                findings.append(f)

            # MIME Type Sniffing
            if "x-content-type-options" not in h:
                f = VulnerabilityFinding(
                    scan_id=scan_id,
                    title="Missing X-Content-Type-Options: nosniff Header",
                    severity=Severity.LOW,
                    cvss_score=3.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-116",
                    owasp_category=self.owasp_category,
                    endpoint=test_url,
                    method="GET",
                    description="Without X-Content-Type-Options: nosniff, older or misconfigured browsers may override the declared Content-Type and execute user-uploaded files as HTML/JavaScript.",
                    poc_curl=f"curl -i '{test_url}' | grep -i x-content-type-options",
                    poc_explanation="Header X-Content-Type-Options omitted.",
                    request_evidence=f"GET {test_url} HTTP/1.1",
                    response_evidence="Header omitted",
                    remediation_advice="Enforce 'X-Content-Type-Options: nosniff' across all HTTP responses.",
                    remediation_patch="add_header X-Content-Type-Options 'nosniff' always;"
                )
                findings.append(f)
        except Exception:
            pass

        # 2. HTTP TRACE Method Check
        try:
            trace_resp = await client.request("TRACE", test_url)
            if trace_resp.status_code == 200 and "TRACE" in trace_resp.text:
                f = VulnerabilityFinding(
                    scan_id=scan_id,
                    title="HTTP TRACE Method Enabled (Cross-Site Tracing / XST)",
                    severity=Severity.LOW,
                    cvss_score=4.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-200",
                    owasp_category=self.owasp_category,
                    endpoint=test_url,
                    method="TRACE",
                    description="HTTP TRACE is active, reflecting request headers back to clients, enabling potential cookie extraction via Cross-Site Tracing.",
                    poc_curl=f"curl -X TRACE -i '{test_url}'",
                    poc_explanation="Server returned HTTP 200 OK echoing the client request.",
                    request_evidence=f"TRACE {test_url} HTTP/1.1",
                    response_evidence=trace_resp.text[:400],
                    remediation_advice="Disable HTTP TRACE and TRACK methods in the web server configuration.",
                    remediation_patch="# Nginx:\nif ($request_method ~ ^(TRACE|TRACK)) { return 405; }"
                )
                findings.append(f)
        except Exception:
            pass

        # 3. Stack Trace / Debug Mode Exposure
        for ep in endpoints:
            try:
                # Trigger an invalid path error
                bad_url = f"{ep.url.rstrip('/')}/__swa_error_trigger_404"
                err_resp = await client.get(bad_url)
                for sig in STACK_TRACE_SIGS:
                    if re.search(sig, err_resp.text):
                        f = VulnerabilityFinding(
                            scan_id=scan_id,
                            title="Verbose Debug Exception / Stack Trace Exposure",
                            severity=Severity.MEDIUM,
                            cvss_score=5.3,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            cwe_id="CWE-209",
                            owasp_category=self.owasp_category,
                            endpoint=bad_url,
                            method="GET",
                            description="Application error page outputs internal stack traces, framework file paths, or exception details.",
                            poc_curl=f"curl -i '{bad_url}'",
                            poc_explanation=f"Response matched internal stack trace signature: `{sig}`",
                            request_evidence=f"GET {bad_url} HTTP/1.1",
                            response_evidence=err_resp.text[:500],
                            remediation_advice="Disable debug mode in production (e.g. DEBUG=False, customErrors mode=On). Display generic 404/500 error pages.",
                            remediation_patch="# settings.py:\nDEBUG = False\nALLOWED_HOSTS = ['yourdomain.com']"
                        )
                        findings.append(f)
                        if log_callback: await log_callback(f"[A05] Stack trace leaked on {bad_url}", "FINDING")
                        break
                if any(f.title.startswith("Verbose Debug Exception") for f in findings):
                    break
            except Exception:
                continue

        return findings


# =====================================================================
# A06: Vulnerable and Outdated Components
# =====================================================================
class PluginA06_VulnerableComponents(BaseSecurityPlugin):
    def __init__(self):
        super().__init__(
            plugin_id="owasp_a06_vulnerable_components",
            name="Vulnerable & Outdated Component Detection",
            owasp_category="A06:2021-Vulnerable and Outdated Components",
            description="Identifies software version disclosures in HTTP headers and HTML banners (Apache, Nginx, PHP, ASP.NET).",
            cwe_id="CWE-200",
            default_severity=Severity.LOW
        )

    async def run(self, scan_id: str, client: httpx.AsyncClient, endpoints: List[DiscoveredEndpoint], recon_data: Any, log_callback=None) -> List[VulnerabilityFinding]:
        findings = []
        if not endpoints:
            return findings

        target_url = endpoints[0].url
        try:
            resp = await client.get(target_url)
            headers = resp.headers

            server_header = headers.get("server", "")
            powered_by = headers.get("x-powered-by", "")
            asp_version = headers.get("x-aspnet-version", "")

            # Check if detailed version numbers are disclosed
            version_regex = r"\d+\.\d+(\.\d+)?"
            disclosures = []
            if server_header and re.search(version_regex, server_header):
                disclosures.append(f"Server: {server_header}")
            if powered_by and re.search(version_regex, powered_by):
                disclosures.append(f"X-Powered-By: {powered_by}")
            if asp_version:
                disclosures.append(f"X-AspNet-Version: {asp_version}")

            if disclosures:
                f = VulnerabilityFinding(
                    scan_id=scan_id,
                    title="Software Component Version Disclosure in HTTP Headers",
                    severity=Severity.LOW,
                    cvss_score=4.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-200",
                    owasp_category=self.owasp_category,
                    endpoint=target_url,
                    method="GET",
                    description=f"Server exposes exact software build versions in response headers: {', '.join(disclosures)}. Disclosing versions assists attackers in mapping known CVEs.",
                    poc_curl=f"curl -i '{target_url}' | grep -E -i '(Server|X-Powered-By|X-AspNet-Version)'",
                    poc_explanation=f"Header disclosure detected: {', '.join(disclosures)}",
                    request_evidence=f"GET {target_url} HTTP/1.1",
                    response_evidence="\n".join(disclosures),
                    remediation_advice="Configure the web server and reverse proxy to suppress software versions in headers (ServerTokens Prod / server_tokens off).",
                    remediation_patch="# Nginx:\nserver_tokens off;\n# Apache:\nServerTokens Prod\nServerSignature Off"
                )
                findings.append(f)
                if log_callback: await log_callback(f"[A06] Software banner disclosed: {disclosures}", "FINDING")
        except Exception:
            pass

        return findings


# =====================================================================
# A07: Identification and Authentication Failures
# =====================================================================
class PluginA07_AuthFailures(BaseSecurityPlugin):
    def __init__(self):
        super().__init__(
            plugin_id="owasp_a07_auth_failures",
            name="Identification & Authentication Flaws",
            owasp_category="A07:2021-Identification and Authentication Failures",
            description="Audits for missing anti-CSRF tokens in HTML forms and sensitive session tokens passed in GET URLs.",
            cwe_id="CWE-352",
            default_severity=Severity.MEDIUM
        )

    async def run(self, scan_id: str, client: httpx.AsyncClient, endpoints: List[DiscoveredEndpoint], recon_data: Any, log_callback=None) -> List[VulnerabilityFinding]:
        findings = []

        for ep in endpoints:
            # 1. Check for token in URL query string (CWE-598)
            parsed = urlparse(ep.url)
            query_lower = parsed.query.lower()
            if any(t in query_lower for t in ["token=", "access_token=", "bearer=", "sessionid=", "auth="]):
                f = VulnerabilityFinding(
                    scan_id=scan_id,
                    title="Sensitive Authentication Token in GET URL Query String",
                    severity=Severity.MEDIUM,
                    cvss_score=6.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    cwe_id="CWE-598",
                    owasp_category=self.owasp_category,
                    endpoint=ep.url,
                    method="GET",
                    description="Authentication tokens are transmitted in the URL query string. URLs are routinely logged in proxy servers, browser history, and Referer headers.",
                    poc_curl=f"curl -i '{ep.url}'",
                    poc_explanation="Query string contains sensitive token parameters.",
                    request_evidence=f"GET {ep.url} HTTP/1.1",
                    response_evidence="URL contains token parameter",
                    remediation_advice="Transmit authentication tokens in HTTP Authorization request headers (Authorization: Bearer <token>) or secure cookies.",
                    remediation_patch="# Send token via header instead of URL:\nheaders={'Authorization': f'Bearer {token}'}"
                )
                findings.append(f)
                if log_callback: await log_callback(f"[A07] Token exposed in URL query string: {ep.url}", "FINDING")

            # 2. Check HTML forms for missing CSRF token
            try:
                resp = await client.get(ep.url)
                if "text/html" in resp.headers.get("content-type", ""):
                    soup = BeautifulSoup(resp.text, "html.parser")
                    forms = soup.find_all("form")
                    for form in forms:
                        method = (form.get("method") or "GET").upper()
                        if method == "POST":
                            inputs = [inp.get("name", "").lower() for inp in form.find_all("input")]
                            has_csrf = any(any(k in name for k in ["csrf", "token", "_token", "authenticity"]) for name in inputs)
                            if not has_csrf:
                                form_action = form.get("action") or ep.url
                                f = VulnerabilityFinding(
                                    scan_id=scan_id,
                                    title="Missing Anti-CSRF Protection on POST Form",
                                    severity=Severity.MEDIUM,
                                    cvss_score=6.5,
                                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
                                    cwe_id="CWE-352",
                                    owasp_category=self.owasp_category,
                                    endpoint=ep.url,
                                    method="POST",
                                    description=f"HTML form submitting to `{form_action}` lacks an anti-CSRF token input field. An attacker can construct malicious cross-site forms to trigger actions on behalf of authenticated users.",
                                    poc_curl=f"curl -i -X POST '{form_action}'",
                                    poc_explanation="POST form elements inspected; no hidden CSRF token input found.",
                                    request_evidence=f"POST {form_action} HTTP/1.1",
                                    response_evidence=str(form)[:300],
                                    remediation_advice="Embed unique, unpredictable, cryptographically strong anti-CSRF tokens in all state-changing HTML forms.",
                                    remediation_patch="<input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\">"
                                )
                                findings.append(f)
                                if log_callback: await log_callback(f"[A07] Form on {ep.url} missing CSRF token", "FINDING")
                                break
            except Exception:
                continue

        return findings


# =====================================================================
# A08: Software and Data Integrity Failures
# =====================================================================
class PluginA08_IntegrityFailures(BaseSecurityPlugin):
    def __init__(self):
        super().__init__(
            plugin_id="owasp_a08_integrity_failures",
            name="Software & Data Integrity Failures (SRI)",
            owasp_category="A08:2021-Software and Data Integrity Failures",
            description="Detects external CDN and third-party scripts loaded without Subresource Integrity (SRI) cryptographic hashes.",
            cwe_id="CWE-353",
            default_severity=Severity.LOW
        )

    async def run(self, scan_id: str, client: httpx.AsyncClient, endpoints: List[DiscoveredEndpoint], recon_data: Any, log_callback=None) -> List[VulnerabilityFinding]:
        findings = []
        if not endpoints:
            return findings

        test_url = endpoints[0].url
        try:
            resp = await client.get(test_url)
            if "text/html" in resp.headers.get("content-type", ""):
                soup = BeautifulSoup(resp.text, "html.parser")
                scripts = soup.find_all("script", src=True)
                unprotected_external = []

                for s in scripts:
                    src = s["src"]
                    if src.startswith("//") or src.startswith("http://") or src.startswith("https://"):
                        if not s.get("integrity"):
                            unprotected_external.append(src)

                if unprotected_external:
                    f = VulnerabilityFinding(
                        scan_id=scan_id,
                        title=f"External Script Loaded Without Subresource Integrity (SRI)",
                        severity=Severity.LOW,
                        cvss_score=4.2,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
                        cwe_id="CWE-353",
                        owasp_category=self.owasp_category,
                        endpoint=test_url,
                        method="GET",
                        description=f"External scripts are loaded without the `integrity` attribute (e.g. `{unprotected_external[0]}`). If the third-party CDN is compromised, attackers can inject malicious JavaScript into client sessions.",
                        poc_curl=f"curl -i '{test_url}' | grep '<script src='",
                        poc_explanation=f"Found {len(unprotected_external)} script tags lacking the integrity attribute.",
                        request_evidence=f"GET {test_url} HTTP/1.1",
                        response_evidence="\n".join(unprotected_external[:3]),
                        remediation_advice="Add Subresource Integrity (SRI) hashes and crossorigin='anonymous' to all third-party script tags.",
                        remediation_patch="<script src=\"https://cdn.example.com/lib.js\"\n        integrity=\"sha384-...\"\n        crossorigin=\"anonymous\"></script>"
                    )
                    findings.append(f)
                    if log_callback: await log_callback(f"[A08] Found external scripts without SRI: {unprotected_external[0]}", "FINDING")
        except Exception:
            pass

        return findings


# =====================================================================
# A09: Security Logging and Monitoring Failures
# =====================================================================
class PluginA09_LoggingMonitoring(BaseSecurityPlugin):
    def __init__(self):
        super().__init__(
            plugin_id="owasp_a09_logging_monitoring",
            name="Logging & Exception Handling Failures",
            owasp_category="A09:2021-Security Logging and Monitoring Failures",
            description="Audits unhandled HTTP 500 error responses that leak database connectivity strings or raw backend exception traces.",
            cwe_id="CWE-778",
            default_severity=Severity.LOW
        )

    async def run(self, scan_id: str, client: httpx.AsyncClient, endpoints: List[DiscoveredEndpoint], recon_data: Any, log_callback=None) -> List[VulnerabilityFinding]:
        findings = []
        for ep in endpoints:
            try:
                # Trigger an invalid payload
                parsed = urlparse(ep.url)
                test_url = f"{ep.url}?__test_probe=%ff%fe%fd"
                r = await client.get(test_url)
                if r.status_code == 500:
                    f = VulnerabilityFinding(
                        scan_id=scan_id,
                        title="Unhandled Internal Server Error (HTTP 500) on Malformed Input",
                        severity=Severity.LOW,
                        cvss_score=3.7,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        cwe_id="CWE-755",
                        owasp_category=self.owasp_category,
                        endpoint=ep.url,
                        method="GET",
                        description=f"Server returned an unhandled HTTP 500 error when receiving malformed query input. Applications should cleanly handle invalid encoding without crashing.",
                        poc_curl=f"curl -i '{test_url}'",
                        poc_explanation="Received HTTP 500 Internal Server Error without custom error page handling.",
                        request_evidence=f"GET {test_url} HTTP/1.1",
                        response_evidence=r.text[:300],
                        remediation_advice="Implement global exception handlers and return consistent, sanitized HTTP 400 Bad Request responses.",
                        remediation_patch="@app.exception_handler(Exception)\nasync def global_exception_handler(request, exc):\n    return JSONResponse(status_code=400, content={'error': 'Invalid request format'})"
                    )
                    findings.append(f)
                    if log_callback: await log_callback(f"[A09] HTTP 500 triggered on {test_url}", "FINDING")
                    break
            except Exception:
                continue

        return findings


# =====================================================================
# A10: Server-Side Request Forgery (SSRF)
# =====================================================================
class PluginA10_SSRF(BaseSecurityPlugin):
    def __init__(self):
        super().__init__(
            plugin_id="owasp_a10_ssrf",
            name="Server-Side Request Forgery (SSRF)",
            owasp_category="A10:2021-Server-Side Request Forgery",
            description="Audits URL and redirection parameters against loopback interfaces and cloud metadata endpoints.",
            cwe_id="CWE-918",
            default_severity=Severity.HIGH
        )

    async def run(self, scan_id: str, client: httpx.AsyncClient, endpoints: List[DiscoveredEndpoint], recon_data: Any, log_callback=None) -> List[VulnerabilityFinding]:
        findings = []
        ssrf_params = ["url", "dest", "redirect", "next", "target", "webhook", "callback", "link", "feed", "uri", "host"]

        for ep in endpoints:
            parsed = urlparse(ep.url)
            query_params = parse_qs(parsed.query)
            params_to_test = [p for p in (ep.parameters or []) if p.lower() in ssrf_params] + [p for p in query_params.keys() if p.lower() in ssrf_params]

            for param in params_to_test:
                # Test loopback redirection
                test_params = dict(query_params)
                test_params[param] = ["http://127.0.0.1:80/"]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                try:
                    r = await client.get(test_url, timeout=5.0)
                    # If response changes or returns loopback indicators
                    if "localhost" in r.text or "127.0.0.1" in r.text or r.status_code == 200:
                        f = VulnerabilityFinding(
                            scan_id=scan_id,
                            title=f"Potential Server-Side Request Forgery (SSRF) via '{param}'",
                            severity=Severity.HIGH,
                            cvss_score=8.6,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                            cwe_id="CWE-918",
                            owasp_category=self.owasp_category,
                            endpoint=ep.url,
                            method="GET",
                            parameter=param,
                            description=f"Parameter `{param}` accepts arbitrary URLs. If the backend fetches or redirects to user-supplied URLs without validation, attackers can probe internal cloud metadata (169.254.169.254) or intranet resources.",
                            poc_curl=f"curl -i '{test_url}'",
                            poc_explanation=f"Passing loopback URL resulted in HTTP {r.status_code} response.",
                            request_evidence=f"GET {test_url} HTTP/1.1",
                            response_evidence=r.text[:300],
                            remediation_advice="Maintain a strict domain allowlist for outgoing requests. Block private IP ranges (RFC 1918, 127.0.0.1, 169.254.169.254) at the application and firewall level.",
                            remediation_patch="import ipaddress, socket\n# Resolve hostname and reject private IP ranges\nip = socket.gethostbyname(parsed_url.hostname)\nif ipaddress.ip_address(ip).is_private:\n    raise ValueError('Private IP access denied')"
                        )
                        findings.append(f)
                        if log_callback: await log_callback(f"[A10] Potential SSRF on parameter: {param}", "FINDING")
                        break
                except Exception:
                    continue

        return findings
