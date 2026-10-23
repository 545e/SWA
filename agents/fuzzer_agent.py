"""
SWA AI Advanced Fuzzing Engine
High-accuracy asynchronous Directory & Path Fuzzer, and Hidden Parameter Miner.
Includes baseline anomaly filtering to eliminate Single Page App (SPA) wildcard false positives.
"""

import asyncio
import re
import uuid
from urllib.parse import urljoin, urlparse, urlencode
import httpx
from typing import List, Dict, Any, Optional

from core.models import LogEvent, VulnerabilityFinding, Severity
from core.queue_manager import queue_manager

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
    ("/administrator", Severity.INFO, "Admin Portal"),
    ("/admin/login", Severity.INFO, "Admin Login"),
    ("/cpanel", Severity.INFO, "Control Panel"),
    ("/phpmyadmin", Severity.MEDIUM, "phpMyAdmin Database Portal"),
    ("/manager/html", Severity.MEDIUM, "Tomcat Web Manager"),
    
    # APIs & Specs
    ("/api", Severity.INFO, "API Root"),
    ("/api/v1", Severity.INFO, "API v1 Endpoint"),
    ("/api/v2", Severity.INFO, "API v2 Endpoint"),
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
    
    # Informational
    ("/robots.txt", Severity.INFO, "Robots.txt"),
    ("/sitemap.xml", Severity.INFO, "Sitemap.xml"),
    ("/.well-known/security.txt", Severity.INFO, "Security.txt RFC 9116")
]

# High-Frequency Hidden Parameters
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
        self.baseline_status: Optional[int] = None
        self.baseline_length: Optional[int] = None

    async def log(self, message: str, level: str = "INFO"):
        event = LogEvent(scan_id=self.scan_id, agent="FuzzerAgent", level=level, message=message)
        await queue_manager.emit_log(event)

    async def run(self) -> Dict[str, Any]:
        await self.log(f"Calibrating baseline anomaly filters against {self.base_url}...", "INFO")
        
        async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=False) as client:
            # 1. Establish Wildcard / 404 Baseline
            await self._calibrate_baseline(client)

            # 2. Path & Directory Fuzzing
            await self.log("Starting high-accuracy directory and sensitive endpoint fuzzing...", "INFO")
            discovered_paths = await self._fuzz_paths(client)

            # 3. Parameter Mining
            await self.log("Starting hidden parameter fuzzing on root endpoints...", "INFO")
            discovered_params = await self._fuzz_parameters(client)

        await self.log(f"Fuzzing completed: {len(discovered_paths)} paths confirmed, {len(discovered_params)} parameter anomalies identified.", "SUCCESS")
        return {
            "paths": discovered_paths,
            "parameters": discovered_params
        }

    async def _calibrate_baseline(self, client: httpx.AsyncClient):
        """Request a non-existent random URL to measure default 404 / SPA redirect length and status."""
        random_slug = f"/swa_anomaly_probe_{uuid.uuid4().hex[:12]}"
        try:
            resp = await client.get(f"{self.base_url}{random_slug}")
            self.baseline_status = resp.status_code
            self.baseline_length = len(resp.content)
            await self.log(f"Wildcard baseline calibrated: HTTP {self.baseline_status} (Length: {self.baseline_length} bytes)", "INFO")
        except Exception:
            self.baseline_status = 404
            self.baseline_length = 0

    async def _fuzz_paths(self, client: httpx.AsyncClient) -> List[Dict[str, Any]]:
        results = []

        async def probe_path(path: str, severity: Severity, title: str):
            async with self.semaphore:
                url = f"{self.base_url}{path}"
                try:
                    resp = await client.get(url)
                    status = resp.status_code
                    length = len(resp.content)

                    # Filter out standard 404 or identical wildcard SPA responses
                    if status in [404, 502, 503, 504]:
                        return None
                    
                    # If server returns 200 for everything, check if content length matches baseline
                    if status == self.baseline_status and abs(length - (self.baseline_length or 0)) < 40:
                        return None

                    # If valid asset discovered
                    if status in [200, 204, 301, 302, 307, 401, 403]:
                        # Extract title if HTML
                        page_title = ""
                        content_type = resp.headers.get("content-type", "")
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
                                description=f"Path fuzzing confirmed exposed resource at {path} returning HTTP {status} (Content-Length: {length}).",
                                poc_curl=f"curl -i -s -k '{url}'",
                                poc_explanation=f"A direct HTTP GET request to {url} returns status {status} with distinctive length {length} bytes differing from baseline.",
                                request_evidence=f"GET {path} HTTP/1.1\nHost: {urlparse(self.base_url).netloc}",
                                response_evidence=resp.text[:500],
                                remediation_advice=f"Restrict public web access to {path} at the web server / reverse proxy layer.",
                                remediation_patch=f"# Nginx rule:\nlocation = {path} {{\n    deny all;\n    return 404;\n}}"
                            )
                            await queue_manager.emit_finding(finding)

                        await self.log(f"Fuzzed endpoint found: {path} [HTTP {status}, {length}B]", "FINDING")
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
        """Fuzz for hidden query parameters that alter application flow or reflect input."""
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

                    # Anomaly detection: reflection, status change, or significant length delta
                    is_anomaly = False
                    anomaly_type = "Parameter Accepted"

                    if reflected:
                        is_anomaly = True
                        anomaly_type = "Parameter Reflection (Potential XSS / Injection Vector)"
                    elif status != self.baseline_status and status not in [404, 502]:
                        is_anomaly = True
                        anomaly_type = f"Status Code Anomaly (HTTP {status})"
                    elif abs(length - (self.baseline_length or 0)) > 200:
                        is_anomaly = True
                        anomaly_type = f"Length Anomaly ({length}B vs baseline {self.baseline_length}B)"

                    if is_anomaly:
                        item = {
                            "parameter": param_name,
                            "url": test_url,
                            "anomaly_type": anomaly_type,
                            "reflected": reflected,
                            "status": status
                        }
                        await self.log(f"Parameter anomaly detected on '{param_name}': {anomaly_type}", "FINDING")
                        return item
                except Exception:
                    return None

        tasks = [probe_param(p) for p in HIDDEN_PARAMETERS]
        param_results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in param_results:
            if isinstance(r, dict) and r:
                results.append(r)

        return results
