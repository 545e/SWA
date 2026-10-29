"""
SWA AI Reconnaissance Agent
Autonomous OSINT, DNS analysis, Port Scanning, Tech Stack Fingerprinting,
SSL Inspection, and Sensitive Asset Discovery.
"""

import asyncio
import socket
import ssl
import re
from urllib.parse import urlparse
import httpx
from typing import List, Dict, Any, Optional

from core.models import ReconResult, LogEvent, VulnerabilityFinding, Severity
from core.queue_manager import queue_manager

COMMON_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 22, 21, 3306, 5432, 6379, 27017]

COMMON_SUBDOMAINS = [
    "api", "dev", "staging", "test", "admin", "app", "portal", "mail",
    "auth", "vpn", "corp", "cdn", "stage", "beta", "status", "dashboard",
    "internal", "demo", "gateway", "backend", "docs", "prod", "uat", "qa",
    "m", "static", "assets", "cloud", "sso", "login", "secure", "monitor"
]

SENSITIVE_PATHS = [
    ("/.env", "Environment Variables Disclosure", Severity.CRITICAL, "DB_PASS|SECRET|AWS_|KEY=|TOKEN="),
    ("/.git/HEAD", "Exposed Git Repository", Severity.HIGH, "ref: refs/"),
    ("/robots.txt", "Robots.txt Information Disclosure", Severity.INFO, "User-agent:|Disallow:"),
    ("/sitemap.xml", "Sitemap Asset Mapping", Severity.INFO, "<urlset|<sitemapindex"),
    ("/openapi.json", "Exposed OpenAPI Specification", Severity.LOW, "openapi|swagger|paths"),
    ("/swagger.json", "Exposed Swagger Specification", Severity.LOW, "swagger|paths"),
    ("/api-docs", "API Documentation Discovered", Severity.INFO, "swagger|redoc|api"),
    ("/.well-known/security.txt", "Security Policy txt Discovered", Severity.INFO, "Contact:"),
    ("/server-status", "Apache Server-Status Exposure", Severity.MEDIUM, "Apache Server Status"),
    ("/actuator/health", "Spring Boot Actuator Exposure", Severity.MEDIUM, "UP|status"),
    ("/config.json", "Sensitive Configuration Exposure", Severity.HIGH, "{"),
    ("/backup.sql", "Exposed Database SQL Dump", Severity.CRITICAL, "CREATE TABLE|INSERT INTO"),
]

TECH_SIGNATURES = {
    "Nginx": [r"nginx", r"Server:.*nginx"],
    "Apache": [r"Apache", r"Server:.*Apache"],
    "Cloudflare": [r"cloudflare", r"cf-ray", r"__cfduid"],
    "Next.js": [r"/_next/", r"__NEXT_DATA__", r"x-powered-by:.*Next\.js"],
    "React": [r"react", r"react-dom", r"data-reactroot"],
    "Vue.js": [r"vue", r"data-v-"],
    "WordPress": [r"wp-content", r"wp-includes", r"xmlrpc.php"],
    "Django": [r"csrftoken", r"django"],
    "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
    "Express.js": [r"X-Powered-By:.*Express"],
    "FastAPI": [r"FastAPI", r"/docs#/default/"],
    "PHP": [r"PHPSESSID", r"X-Powered-By:.*PHP"],
    "ASP.NET": [r"ASP\.NET", r"ASPSESSIONID", r"__VIEWSTATE"],
}

class ReconAgent:
    def __init__(self, scan_id: str, target_url: str, timeout: int = 10):
        self.scan_id = scan_id
        self.raw_target = target_url
        self.timeout = timeout
        self.parsed = self._normalize_url(target_url)
        self.domain = self.parsed.hostname or target_url
        self.base_url = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.takeover_findings: List[VulnerabilityFinding] = []

    def _normalize_url(self, target: str):
        if not target.startswith(("http://", "https://")):
            t_lower = target.lower()
            if any(h in t_lower for h in ["127.0.0.1", "localhost", "0.0.0.0", "[::1]"]):
                target = f"http://{target}"
            else:
                target = f"https://{target}"
        return urlparse(target)

    async def log(self, message: str, level: str = "INFO"):
        event = LogEvent(scan_id=self.scan_id, agent="ReconAgent", level=level, message=message)
        await queue_manager.emit_log(event)

    async def run(self) -> ReconResult:
        await self.log(f"Starting autonomous reconnaissance on target: {self.base_url} [High-Speed Concurrent Engine]", "INFO")
        
        recon = ReconResult(target=self.base_url)

        # 1. DNS & IP resolution first (needed for connection routing)
        await self.resolve_dns(recon)

        # 2. Execute Subdomain Discovery, Port Probing, HTTP Tech Stack, SSL, and Sensitive Paths in PARALLEL
        parallel_recon_tasks = [
            self.enumerate_subdomains(recon),
            self.scan_ports(recon),
            self.inspect_http_and_tech(recon),
            self.discover_sensitive_paths(recon)
        ]
        if self.parsed.scheme == "https":
            parallel_recon_tasks.append(self.inspect_ssl(recon))

        await asyncio.gather(*parallel_recon_tasks, return_exceptions=True)

        await self.log(f"Reconnaissance phase completed successfully. Discovered {len(recon.subdomains)} subdomains, {len(recon.open_ports)} open ports.", "SUCCESS")
        return recon

    async def resolve_dns(self, recon: ReconResult):
        await self.log(f"Resolving DNS records for {self.domain}...", "INFO")
        try:
            loop = asyncio.get_running_loop()
            addr_info = await loop.getaddrinfo(self.domain, None)
            ips = list(set([item[4][0] for item in addr_info if item[4]]))
            recon.ip_addresses = ips
            recon.dns_records["A"] = ips
            await self.log(f"DNS resolved IPs: {', '.join(ips)}", "SUCCESS")
        except Exception as e:
            await self.log(f"DNS resolution notice: {str(e)}", "WARN")

    async def enumerate_subdomains(self, recon: ReconResult):
        # Do not enumerate if target is an IP address
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", self.domain):
            return

        from agents.amass_engine import AmassSubdomainEngine
        amass_engine = AmassSubdomainEngine(
            scan_id=self.scan_id,
            base_domain=self.domain,
            concurrency=16,
            timeout=self.timeout
        )
        subdomain_details, takeovers = await amass_engine.run()
        recon.subdomains = subdomain_details
        recon.subdomain_metrics = getattr(amass_engine, "metrics", {
            "discovered": len(subdomain_details),
            "resolved": sum(1 for s in subdomain_details if s.get("dns_confirmed")),
            "wildcard_filtered": getattr(amass_engine, "wildcard_filtered_count", 0),
            "failed_resolution": sum(1 for s in subdomain_details if s.get("validation_status") == "unresolved"),
            "live_http": sum(1 for s in subdomain_details if s.get("status"))
        })
        self.takeover_findings.extend(takeovers)
        await self.log(f"OWASP Amass discovery complete. Found {len(subdomain_details)} active subdomains ({recon.subdomain_metrics.get('resolved', 0)} resolved, {recon.subdomain_metrics.get('live_http', 0)} live).", "SUCCESS")

    async def scan_ports(self, recon: ReconResult):
        await self.log(f"Probing standard TCP ports on {self.domain}...", "INFO")
        open_ports = []

        async def check_port(port: int):
            try:
                conn = asyncio.open_connection(self.domain, port)
                reader, writer = await asyncio.wait_for(conn, timeout=1.2)
                writer.close()
                await writer.wait_closed()
                service = "http" if port in [80, 8080, 3000, 5000, 8000] else "https" if port in [443, 8443] else "service"
                return {"port": port, "state": "open", "service": service}
            except Exception:
                return None

        tasks = [check_port(p) for p in COMMON_PORTS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict) and r:
                open_ports.append(r)

        recon.open_ports = open_ports
        port_list = [str(p["port"]) for p in open_ports]
        await self.log(f"Port scan completed. Open ports detected: {', '.join(port_list) if port_list else 'None'}", "INFO")

    async def inspect_http_and_tech(self, recon: ReconResult):
        await self.log("Analyzing HTTP headers, security policies, and tech signatures...", "INFO")
        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(self.base_url)
                
                # Security Headers Check
                headers = dict(resp.headers)
                sec_headers = {
                    "Strict-Transport-Security": headers.get("strict-transport-security"),
                    "Content-Security-Policy": headers.get("content-security-policy"),
                    "X-Frame-Options": headers.get("x-frame-options"),
                    "X-Content-Type-Options": headers.get("x-content-type-options"),
                    "Referrer-Policy": headers.get("referrer-policy"),
                    "Permissions-Policy": headers.get("permissions-policy")
                }
                recon.security_headers = {k: v for k, v in sec_headers.items() if v}

                # Evaluate Missing Critical Headers
                missing = [k for k, v in sec_headers.items() if not v]
                if missing:
                    await self.log(f"Missing security headers: {', '.join(missing[:3])}", "WARN")
                    finding = VulnerabilityFinding(
                        scan_id=self.scan_id,
                        title=f"Missing Critical Security Headers ({', '.join(missing[:2])})",
                        severity=Severity.LOW,
                        cvss_score=4.3,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                        cwe_id="CWE-693",
                        owasp_category="A05:2021-Security Misconfiguration",
                        endpoint=self.base_url,
                        method="GET",
                        description=f"The application does not enforce important defensive HTTP response headers: {', '.join(missing)}.",
                        poc_curl=f"curl -I '{self.base_url}'",
                        poc_explanation="Inspecting the HTTP response headers shows these security directives are omitted.",
                        request_evidence=f"GET {self.base_url} HTTP/1.1",
                        response_evidence="\n".join([f"{k}: {v}" for k, v in headers.items()]),
                        remediation_advice="Configure standard security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) in reverse proxy or web server.",
                        remediation_patch="add_header X-Content-Type-Options 'nosniff' always;\nadd_header X-Frame-Options 'SAMEORIGIN' always;\nadd_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;"
                    )
                    await queue_manager.emit_finding(finding)

                # Tech Stack Detection
                raw_content = resp.text
                detected_tech = []
                for tech, sigs in TECH_SIGNATURES.items():
                    found = False
                    for sig in sigs:
                        if re.search(sig, raw_content, re.IGNORECASE) or any(re.search(sig, f"{k}: {v}", re.IGNORECASE) for k, v in headers.items()):
                            found = True
                            break
                    if found:
                        detected_tech.append({"technology": tech, "category": "Framework/Server"})
                
                recon.technologies = detected_tech
                tech_names = [t["technology"] for t in detected_tech]
                await self.log(f"Fingerprinted technologies: {', '.join(tech_names) if tech_names else 'Generic / Obfuscated'}", "SUCCESS")

        except Exception as e:
            await self.log(f"HTTP inspection notice: {str(e)}", "WARN")

    async def inspect_ssl(self, recon: ReconResult):
        try:
            loop = asyncio.get_running_loop()
            def get_cert():
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((self.domain, 443), timeout=3.0) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                        return ssock.getpeercert(binary_form=False)
            
            cert = await loop.run_in_executor(None, get_cert)
            if cert:
                recon.ssl_info = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "valid_until": cert.get("notAfter")
                }
                await self.log("SSL/TLS certificate verified and inspected.", "INFO")
        except Exception:
            pass

    async def discover_sensitive_paths(self, recon: ReconResult):
        await self.log("Scanning for sensitive files, backups, and config disclosures (Concurrent)...", "INFO")
        discovered = []
        sem = asyncio.Semaphore(10)

        limits = httpx.Limits(max_keepalive_connections=15, max_connections=25)
        async with httpx.AsyncClient(verify=False, timeout=3.5, follow_redirects=False, limits=limits) as client:
            async def probe_single_path(path: str, title: str, severity: Severity, pattern: str):
                url = f"{self.base_url}{path}"
                async with sem:
                    try:
                        resp = await client.get(url)
                        # Zero False Positive: Strict 200 check with signature validation
                        if resp.status_code == 200 and re.search(pattern, resp.text, re.IGNORECASE):
                            discovered.append({"path": path, "url": url, "status": 200, "title": title})
                            await self.log(f"Discovered: {path} ({title})", "FINDING")

                            finding = VulnerabilityFinding(
                                scan_id=self.scan_id,
                                title=title,
                                severity=severity,
                                cvss_score=8.5 if severity == Severity.CRITICAL else (7.2 if severity == Severity.HIGH else 5.0),
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                cwe_id="CWE-200",
                                owasp_category="A01:2021-Broken Access Control",
                                endpoint=url,
                                method="GET",
                                description=f"Publicly accessible sensitive asset found at {path}. Exposing this file may lead to credential theft or architecture exposure.",
                                poc_curl=f"curl -i -s -k '{url}'",
                                poc_explanation=f"A direct GET request to {url} returns HTTP 200 OK with sensitive contents matching `{pattern}`.",
                                request_evidence=f"GET {path} HTTP/1.1\nHost: {self.domain}",
                                response_evidence=resp.text[:600],
                                remediation_advice=f"Block public access to {path} in web server rules and never commit secrets to production web roots.",
                                remediation_patch=f"# Nginx rule:\nlocation = {path} {{\n    deny all;\n    return 404;\n}}"
                            )
                            await queue_manager.emit_finding(finding)
                    except Exception:
                        pass

            tasks = [probe_single_path(p, t, s, pat) for p, t, s, pat in SENSITIVE_PATHS]
            await asyncio.gather(*tasks, return_exceptions=True)

        recon.sensitive_files = discovered
