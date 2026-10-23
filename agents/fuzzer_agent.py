"""
SWA AI Advanced Fuzzing Engine
High-accuracy asynchronous Directory & Path Fuzzer, and Hidden Parameter Miner.
Includes dual baseline calibration (root vs wildcard 404/SPA catch-all) to eliminate false positives.
"""

import asyncio
import re
import uuid
from urllib.parse import urljoin, urlparse, urlencode
import httpx
from typing import List, Dict, Any, Optional

from core.models import LogEvent, VulnerabilityFinding, Severity
from core.queue_manager import queue_manager

# Realistic browser headers to bypass CDN/WAF false bot blocks
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Ch-Ua": '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
}

# Curated High-Yield Directory & Path Wordlist
HIGH_YIELD_PATHS = [
    # Sensitive Credentials & Repositories
    ("/.env", Severity.CRITICAL, "Environment Variables"),
    ("/.env.local", Severity.CRITICAL, "Environment File"),
    ("/.git/config", Severity.HIGH, "Git Configuration"),
    ("/.git/HEAD", Severity.HIGH, "Exposed Git Repository"),
    ("/.svn/entries", Severity.HIGH, "Subversion Exposure"),
    ("/.DS_Store", Severity.LOW, "macOS Metadata File"),

    # Backups & Dumps
    ("/backup.sql", Severity.CRITICAL, "Database SQL Dump"),
    ("/database.sql", Severity.CRITICAL, "Database SQL Dump"),
    ("/backup.zip", Severity.HIGH, "Backup Archive"),
    ("/site.zip", Severity.HIGH, "Website Source Archive"),
    ("/backup.tar.gz", Severity.HIGH, "Compressed Archive"),
    ("/wp-config.php.bak", Severity.HIGH, "WordPress Config Backup"),

    # Configuration Files
    ("/config.json", Severity.HIGH, "Configuration JSON"),
    ("/web.config", Severity.MEDIUM, "IIS Web Config"),
    ("/settings.py", Severity.HIGH, "Django Settings"),

    # Administrative & Management Panels
    ("/admin", Severity.INFO, "Admin Portal"),
    ("/admin/", Severity.INFO, "Admin Directory"),
    ("/administrator", Severity.INFO, "Admin Portal"),
    ("/admin/login", Severity.INFO, "Admin Login"),
    ("/wp-admin/", Severity.INFO, "WordPress Admin Directory"),
    ("/wp-login.php", Severity.INFO, "WordPress Login"),
    ("/cpanel", Severity.INFO, "Control Panel"),
    ("/webmail", Severity.INFO, "Webmail Portal"),
    ("/dashboard", Severity.INFO, "Dashboard"),
    ("/portal", Severity.INFO, "User Portal"),
    ("/phpmyadmin", Severity.MEDIUM, "phpMyAdmin Database Portal"),
    ("/manager/html", Severity.MEDIUM, "Tomcat Web Manager"),

    # APIs & Specs
    ("/api", Severity.INFO, "API Root"),
    ("/api/", Severity.INFO, "API Directory"),
    ("/api/v1", Severity.INFO, "API v1 Endpoint"),
    ("/api/v2", Severity.INFO, "API v2 Endpoint"),
    ("/docs", Severity.LOW, "API Documentation"),
    ("/graphql", Severity.LOW, "GraphQL Endpoint"),
    ("/graphiql", Severity.LOW, "GraphiQL Interactive IDE"),
    ("/swagger.json", Severity.LOW, "Swagger API Specification"),
    ("/openapi.json", Severity.LOW, "OpenAPI Specification"),
    ("/swagger-ui.html", Severity.INFO, "Swagger UI Portal"),
    ("/v2/api-docs", Severity.LOW, "Springfox API Docs"),

    # Telemetry, Debug & Actuators
    ("/actuator/health", Severity.MEDIUM, "Spring Boot Actuator Health"),
    ("/actuator/env", Severity.CRITICAL, "Spring Boot Exposed Environment"),
    ("/server-status", Severity.MEDIUM, "Apache Server Status"),
    ("/metrics", Severity.LOW, "Prometheus Metrics"),
    ("/debug", Severity.MEDIUM, "Debug Console"),
    ("/console", Severity.MEDIUM, "Interactive Web Console"),
    ("/trace", Severity.LOW, "Trace Endpoint"),
    ("/phpinfo.php", Severity.MEDIUM, "PHP Info Disclosure"),

    # Informational & Common Root Assets
    ("/robots.txt", Severity.INFO, "Robots.txt"),
    ("/sitemap.xml", Severity.INFO, "Sitemap.xml"),
    ("/.well-known/security.txt", Severity.INFO, "Security.txt RFC 9116"),
    ("/favicon.ico", Severity.INFO, "Favicon Asset")
]

# High-Frequency Hidden Parameters to mine
HIDDEN_PARAMETERS = [
    "debug", "admin", "redirect", "url", "file", "path", "user_id",
    "id", "role", "next", "cmd", "token", "test", "action", "view",
    "page", "callback", "dest", "auth", "query", "load", "include"
]

class FuzzerAgent:
    def __init__(self, scan_id: str, base_url: str, concurrency: int = 8, timeout: int = 8):
        self.scan_id = scan_id
        self.base_url = base_url.rstrip("/")
        self.concurrency = concurrency
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)
        
        # Dual Baselines: Root Clean vs 404 Wildcard
        self.root_status: Optional[int] = 200
        self.root_length: Optional[int] = 0
        self.wildcard_status: Optional[int] = 404
        self.wildcard_length: Optional[int] = 0

    async def log(self, message: str, level: str = "INFO"):
        event = LogEvent(scan_id=self.scan_id, agent="FuzzerAgent", level=level, message=message)
        await queue_manager.emit_log(event)

    async def run(self) -> Dict[str, Any]:
        await self.log(f"Calibrating dual baselines (clean root vs wildcard 404/catch-all) on {self.base_url}...", "INFO")
        
        async with httpx.AsyncClient(headers=BROWSER_HEADERS, verify=False, timeout=self.timeout, follow_redirects=False) as client:
            # 1. Establish Baselines
            await self._calibrate_baseline(client)

            # 2. Path & Directory Fuzzing
            await self.log("Starting high-accuracy directory and sensitive endpoint fuzzing...", "INFO")
            discovered_paths = await self._fuzz_paths(client)

            # 3. Parameter Mining
            await self.log("Starting anomaly-filtered hidden parameter fuzzing...", "INFO")
            discovered_params = await self._fuzz_parameters(client)

        await self.log(f"Fuzzing completed: {len(discovered_paths)} paths confirmed, {len(discovered_params)} parameter anomalies verified.", "SUCCESS")
        return {
            "paths": discovered_paths,
            "parameters": discovered_params
        }

    async def _calibrate_baseline(self, client: httpx.AsyncClient):
        """Measure clean root page vs random wildcard slug to detect 404 or SPA 200 catch-all."""
        # 1. Clean root baseline (for parameter comparison)
        try:
            r_root = await client.get(f"{self.base_url}/")
            self.root_status = r_root.status_code
            self.root_length = len(r_root.content)
        except Exception:
            self.root_status = 200
            self.root_length = 0

        # 2. Wildcard baseline (for path comparison)
        random_slug = f"/swa_anomaly_probe_{uuid.uuid4().hex[:12]}"
        try:
            r_404 = await client.get(f"{self.base_url}{random_slug}")
            self.wildcard_status = r_404.status_code
            self.wildcard_length = len(r_404.content)
            await self.log(f"Baseline calibrated: Root HTTP {self.root_status} ({self.root_length}B) | Wildcard HTTP {self.wildcard_status} ({self.wildcard_length}B)", "INFO")
        except Exception:
            self.wildcard_status = 404
            self.wildcard_length = 0

    async def _fuzz_paths(self, client: httpx.AsyncClient) -> List[Dict[str, Any]]:
        results = []

        async def probe_path(path: str, severity: Severity, title: str):
            async with self.semaphore:
                url = f"{self.base_url}{path}"
                try:
                    resp = await client.get(url)
                    status = resp.status_code
                    length = len(resp.content)
                    content_type = resp.headers.get("content-type", "").lower()

                    # Filter out standard dead error responses
                    if status in [404, 502, 503, 504]:
                        return None
                    
                    is_valid = False

                    # Wildcard SPA Handling: If random slug returned 200 (Single Page App catch-all)
                    if self.wildcard_status == 200:
                        # 401/403 on protected directories is a true hit
                        if status in [401, 403]:
                            is_valid = True
                        elif status in [301, 302, 307, 308]:
                            is_valid = True
                        elif status == 200:
                            # If length differs noticeably or content is not generic html (e.g. plain text, xml, json)
                            if abs(length - (self.wildcard_length or 0)) > 25:
                                is_valid = True
                            elif "text/plain" in content_type or "xml" in content_type or "json" in content_type or "image" in content_type:
                                is_valid = True
                    elif self.wildcard_status == 404:
                        if status in [200, 204, 301, 302, 307, 308, 401, 403]:
                            is_valid = True
                    else:
                        # Non-standard wildcard (e.g. 403 default)
                        if status != self.wildcard_status or abs(length - (self.wildcard_length or 0)) > 35:
                            if status in [200, 204, 301, 302, 307, 308, 401, 403]:
                                is_valid = True

                    if not is_valid:
                        return None

                    # Extract page title if HTML
                    page_title = ""
                    if "text/html" in content_type:
                        m = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE)
                        if m:
                            page_title = m.group(1).strip()

                    result_item = {
                        "path": path,
                        "url": url,
                        "status": status,
                        "content_length": length,
                        "content_type": content_type.split(";")[0],
                        "title": page_title or title
                    }

                    # If sensitive or critical, raise vulnerability finding
                    if status in [200, 403] and severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
                        score = 8.5 if severity == Severity.CRITICAL else (7.2 if severity == Severity.HIGH else 5.3)
                        finding = VulnerabilityFinding(
                            scan_id=self.scan_id,
                            title=f"Fuzzed Asset Discovered: {title} ({path})",
                            severity=severity,
                            cvss_score=score,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            cwe_id="CWE-200",
                            owasp_category="A01:2021-Broken Access Control",
                            endpoint=url,
                            method="GET",
                            description=f"Path fuzzing confirmed exposed resource at {path} returning HTTP {status} (Content-Length: {length} bytes).",
                            poc_curl=f"curl -i -s -k '{url}'",
                            poc_explanation=f"A direct HTTP GET request to {url} returns status {status} with distinctive length {length} bytes differing from wildcard baseline.",
                            request_evidence=f"GET {path} HTTP/1.1\nHost: {urlparse(self.base_url).netloc}",
                            response_evidence=resp.text[:500],
                            remediation_advice=f"Restrict public web access to {path} at the web server / reverse proxy layer.",
                            remediation_patch=f"# Nginx rule:\nlocation = {path} {{\n    deny all;\n    return 404;\n}}"
                        )
                        await queue_manager.emit_finding(finding)

                    await self.log(f"Fuzzed endpoint verified: {path} [HTTP {status}, {length}B]", "FINDING")
                    return result_item
                except Exception:
                    return None

        tasks = [probe_path(p, s, t) for p, s, t in HIGH_YIELD_PATHS]
        probe_results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in probe_results:
            if isinstance(r, dict) and r:
                results.append(r)

        return results

    async def _fuzz_parameters(self, client: httpx.AsyncClient) -> List[Dict[str, Any]]:
        """Fuzz for hidden query parameters comparing strictly against the clean root page."""
        results = []
        canary = "swa_fuzz_canary_3918"

        async def probe_param(param_name: str):
            async with self.semaphore:
                test_url = f"{self.base_url}/?{param_name}={canary}"
                try:
                    resp = await client.get(test_url)
                    reflected = canary in resp.text
                    status = resp.status_code
                    length = len(resp.content)

                    # Anomaly detection against ROOT baseline (NOT 404!)
                    is_anomaly = False
                    anomaly_type = ""

                    if reflected:
                        is_anomaly = True
                        anomaly_type = "Reflected Parameter (Potential XSS / Injection)"
                    elif status != self.root_status and status not in [404, 502]:
                        is_anomaly = True
                        anomaly_type = f"Status Code Alteration (HTTP {status} vs clean root {self.root_status})"
                    elif abs(length - (self.root_length or 0)) > 40:
                        is_anomaly = True
                        anomaly_type = f"Significant Content Length Shift (Delta: {length - (self.root_length or 0)} bytes)"

                    if is_anomaly:
                        item = {
                            "parameter": param_name,
                            "url": test_url,
                            "status": status,
                            "length": length,
                            "anomaly": anomaly_type,
                            "reflected": reflected
                        }

                        # Emit Finding for parameter mining
                        finding = VulnerabilityFinding(
                            scan_id=self.scan_id,
                            title=f"Hidden Parameter Discovered: {param_name}",
                            severity=Severity.MEDIUM if reflected else Severity.LOW,
                            cvss_score=6.1 if reflected else 4.3,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                            cwe_id="CWE-200",
                            owasp_category="A05:2021-Security Misconfiguration",
                            endpoint=test_url,
                            parameter=param_name,
                            method="GET",
                            description=f"Automated parameter mining identified responsive hidden parameter '{param_name}'. Anomaly: {anomaly_type}.",
                            poc_curl=f"curl -i -s -k '{test_url}'",
                            poc_explanation=f"Injecting parameter '{param_name}' altered the application server response behavior compared to the clean root baseline.",
                            request_evidence=f"GET /?{param_name}={canary} HTTP/1.1\nHost: {urlparse(self.base_url).netloc}",
                            response_evidence=resp.text[:500],
                            remediation_advice=f"Review whether query parameter '{param_name}' should be accessible to unauthenticated callers. Implement strict input validation.",
                            remediation_patch=f"# Sanitize/Reject unexpected parameter:\nif request.GET.get('{param_name}'):\n    # ensure validation or drop"
                        )
                        await queue_manager.emit_finding(finding)
                        await self.log(f"Parameter anomaly confirmed: ?{param_name}=... [{anomaly_type}]", "FINDING")
                        return item
                    return None
                except Exception:
                    return None

        param_tasks = [probe_param(param) for param in HIDDEN_PARAMETERS]
        param_results = await asyncio.gather(*param_tasks, return_exceptions=True)
        for r in param_results:
            if isinstance(r, dict) and r:
                results.append(r)

        return results
