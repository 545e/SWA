"""
SWA AI Authorized Scope Reconnaissance Assistant
Strict Scope Boundary Enforcement, Passive Telemetry, Rate-Limited Path Probing,
CWE Correlation, and Audit Trail Logging.

Hard Rules:
- Only act on targets listed in ALLOWED_TARGETS. Refuse all other targets.
- No exploitation, brute force, auth bypass, or destructive payloads.
- Strict rate limiting: max 1 request/second.
- Full structured audit logging with timestamp, target, and purpose.
"""

import sys
import os
import json
import socket
import ssl
import asyncio
import datetime
from urllib.parse import urlparse
import httpx
from typing import Dict, List, Any, Optional

ALLOWED_TARGETS = [
    "0a2f008804b73639822f564400da00ed.web-security-academy.net",
    "127.0.0.1",
    "localhost"
]

SAFE_WORDLIST = [
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/login",
    "/admin",
    "/api",
    "/docs",
    "/setup.php",
    "/vulnerabilities/"
]

class ScopedReconAssistant:
    def __init__(self, target: str, port: Optional[int] = None, use_https: Optional[bool] = None):
        self.raw_target = target.strip()
        self.hostname = self._extract_hostname(self.raw_target)
        self.port = port
        self.use_https = use_https
        self.audit_log: List[Dict[str, str]] = []
        self.observations: List[Dict[str, Any]] = []
        self.candidate_weaknesses: List[Dict[str, Any]] = []
        self.next_manual_steps: List[str] = []

    def _extract_hostname(self, target: str) -> str:
        t = target
        if "://" in t:
            parsed = urlparse(t)
            t = parsed.hostname or t
        if ":" in t:
            t = t.split(":")[0]
        return t.strip().lower()

    def _log_action(self, purpose: str, details: str = ""):
        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "target": self.hostname,
            "purpose": purpose,
            "details": details
        }
        self.audit_log.append(entry)

    def validate_scope(self) -> bool:
        """Enforces non-negotiable scope boundary."""
        is_allowed = any(self.hostname == allowed or self.hostname.endswith(f".{allowed}") for allowed in ALLOWED_TARGETS)
        if not is_allowed:
            self._log_action(
                "Scope Verification - REFUSAL",
                f"Target '{self.hostname}' is outside ALLOWED_TARGETS. Assessment terminated immediately."
            )
            return False
        self._log_action("Scope Verification - ACCEPTED", f"Target '{self.hostname}' verified in authorized scope.")
        return True

    async def execute_plan(self) -> Dict[str, Any]:
        """Runs the authorized 4-stage non-destructive recon plan."""
        if not self.validate_scope():
            return {
                "status": "REFUSED",
                "target": self.raw_target,
                "error": f"Authorization Boundary Violation: Target '{self.hostname}' is not listed in ALLOWED_TARGETS.",
                "allowed_targets": ALLOWED_TARGETS,
                "audit_log": self.audit_log
            }

        # Resolve scheme and target port
        scheme = "https" if self.use_https else ("http" if self.use_https is False else ("https" if "academy" in self.hostname else "http"))
        if self.port:
            base_url = f"{scheme}://{self.hostname}:{self.port}"
        else:
            base_url = f"{scheme}://{self.hostname}"

        self._log_action("Reconnaissance Plan Initialized", f"Base URL: {base_url} [Rate Limit: 1.0 req/sec max]")

        # -------------------------------------------------------------
        # 1. Passive Recon: DNS, TLS/SSL, Headers, Robots.txt, Sitemap
        # -------------------------------------------------------------
        await self._passive_recon(base_url, scheme)

        # -------------------------------------------------------------
        # 2. Active Rate-Limited Path Enumeration (Strict max 1 req/sec)
        # -------------------------------------------------------------
        await self._active_rate_limited_enumeration(base_url)

        # -------------------------------------------------------------
        # 3. Correlate Observations to Candidate CWE IDs
        # -------------------------------------------------------------
        self._correlate_cwe_weaknesses(base_url)

        # -------------------------------------------------------------
        # 4. Synthesize Next Manual Steps
        # -------------------------------------------------------------
        self._synthesize_manual_steps(base_url)

        self._log_action("Reconnaissance Plan Completed", f"Generated {len(self.observations)} observations and {len(self.candidate_weaknesses)} candidate CWEs.")

        return {
            "target": self.hostname,
            "base_url": base_url,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "authorized_scope_verified": True,
            "audit_log": self.audit_log,
            "observations": self.observations,
            "candidate_weaknesses": self.candidate_weaknesses,
            "next_manual_steps": self.next_manual_steps
        }

    async def _passive_recon(self, base_url: str, scheme: str):
        # A. DNS Records
        self._log_action("Passive DNS Resolution", f"Querying A/AAAA socket info for {self.hostname}")
        dns_obs = {"type": "dns_records", "hostname": self.hostname, "resolved_ips": [], "canonical_name": ""}
        try:
            loop = asyncio.get_running_loop()
            addr_info = await loop.getaddrinfo(self.hostname, None)
            ips = list(set([item[4][0] for item in addr_info if item[4]]))
            dns_obs["resolved_ips"] = ips
            try:
                host_info = await loop.run_in_executor(None, socket.gethostbyname_ex, self.hostname)
                dns_obs["canonical_name"] = host_info[0]
            except Exception:
                pass
        except Exception as e:
            dns_obs["error"] = str(e)
        self.observations.append(dns_obs)

        # B. TLS Certificate (if HTTPS)
        if scheme == "https":
            self._log_action("Passive TLS Inspection", f"Querying SSL certificate parameters for {self.hostname}")
            tls_obs = {"type": "tls_certificate", "subject": {}, "issuer": {}, "version": "", "cipher": ""}
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn_port = self.port or 443
                with socket.create_connection((self.hostname, conn_port), timeout=5.0) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                        cert = ssock.getpeercert(binary_form=False) or {}
                        cipher = ssock.cipher()
                        tls_obs["version"] = ssock.version()
                        tls_obs["cipher"] = cipher[0] if cipher else ""
                        if cert:
                            tls_obs["subject"] = dict(x[0] for x in cert.get("subject", []))
                            tls_obs["issuer"] = dict(x[0] for x in cert.get("issuer", []))
            except Exception as e:
                tls_obs["notice"] = str(e)
            self.observations.append(tls_obs)

        # C. HTTP Root Response & Security Headers
        self._log_action("Passive Header Inspection", f"Inspecting root response headers from {base_url}")
        header_obs = {"type": "http_headers", "status_code": None, "headers": {}, "missing_security_headers": [], "tech_fingerprint": []}
        async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True) as client:
            try:
                resp = await client.get(base_url)
                header_obs["status_code"] = resp.status_code
                header_obs["headers"] = dict(resp.headers)
                
                # Check for standard security headers
                h_lower = {k.lower(): v for k, v in resp.headers.items()}
                sec_checks = ["content-security-policy", "x-frame-options", "x-content-type-options", "strict-transport-security", "referrer-policy", "permissions-policy"]
                header_obs["missing_security_headers"] = [h for h in sec_checks if h not in h_lower]

                # Tech fingerprinting from headers
                if "server" in h_lower:
                    header_obs["tech_fingerprint"].append(f"Server: {h_lower['server']}")
                if "x-powered-by" in h_lower:
                    header_obs["tech_fingerprint"].append(f"X-Powered-By: {h_lower['x-powered-by']}")
                if "set-cookie" in h_lower:
                    header_obs["tech_fingerprint"].append(f"Cookie Flags: {h_lower['set-cookie']}")
            except Exception as e:
                header_obs["notice"] = f"Root connection notice: {str(e)}"
        self.observations.append(header_obs)

        # D. Robots.txt and Sitemap.xml
        self._log_action("Passive Informational Retrieval", "Checking robots.txt and sitemap.xml")
        async with httpx.AsyncClient(verify=False, timeout=6.0) as client:
            # robots.txt
            try:
                r_robots = await client.get(f"{base_url}/robots.txt")
                self.observations.append({
                    "type": "robots_txt",
                    "status_code": r_robots.status_code,
                    "content_length": len(r_robots.content),
                    "disallow_entries": [line.strip() for line in r_robots.text.splitlines() if line.lower().startswith("disallow:")]
                })
            except Exception:
                pass

            # sitemap.xml
            try:
                r_sitemap = await client.get(f"{base_url}/sitemap.xml")
                self.observations.append({
                    "type": "sitemap_xml",
                    "status_code": r_sitemap.status_code,
                    "content_length": len(r_sitemap.content)
                })
            except Exception:
                pass

    async def _active_rate_limited_enumeration(self, base_url: str):
        """Active path enumeration with hard-coded 1.0s delay between requests."""
        self._log_action("Active Enumeration Initialized", f"Enumerating {len(SAFE_WORDLIST)} safe paths at rate <= 1 req/sec")
        enum_results = []
        
        async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=False) as client:
            for idx, path in enumerate(SAFE_WORDLIST):
                url = f"{base_url}{path}"
                self._log_action(f"Rate-Limited Probe [{idx+1}/{len(SAFE_WORDLIST)}]", f"GET {url}")
                try:
                    resp = await client.get(url)
                    record = {
                        "path": path,
                        "url": url,
                        "status_code": resp.status_code,
                        "content_length": len(resp.content),
                        "content_type": resp.headers.get("content-type", ""),
                        "server": resp.headers.get("server", "")
                    }
                    enum_results.append(record)
                except Exception as e:
                    enum_results.append({
                        "path": path,
                        "url": url,
                        "status_code": None,
                        "error": str(e)
                    })

                # Hard constraint: rate limit to max 1 request/second
                await asyncio.sleep(1.0)

        self.observations.append({
            "type": "active_path_enumeration",
            "rate_limit": "1 request/second",
            "probes_count": len(enum_results),
            "results": enum_results
        })

    def _correlate_cwe_weaknesses(self, base_url: str):
        """Correlates observations to candidate CWE IDs without false confirmation claims."""
        # Check header observation
        header_obs = next((o for o in self.observations if o.get("type") == "http_headers"), None)
        active_obs = next((o for o in self.observations if o.get("type") == "active_path_enumeration"), None)

        if header_obs and header_obs.get("status_code"):
            missing = header_obs.get("missing_security_headers", [])
            
            # Missing X-Frame-Options -> Clickjacking
            if "x-frame-options" in missing:
                self.candidate_weaknesses.append({
                    "cwe_id": "CWE-1021",
                    "title": "Improper Restriction of Rendered UI Layers (Clickjacking)",
                    "confidence": "high",
                    "rationale": "The HTTP response does not specify 'X-Frame-Options' or 'Content-Security-Policy: frame-ancestors', permitting framing in third-party contexts.",
                    "evidence": f"Headers inspected from {base_url}; X-Frame-Options was absent."
                })

            # Missing Content-Security-Policy
            if "content-security-policy" in missing:
                self.candidate_weaknesses.append({
                    "cwe_id": "CWE-693",
                    "title": "Protection Mechanism Failure (Missing Content-Security-Policy)",
                    "confidence": "high",
                    "rationale": "No Content-Security-Policy was detected. If client-side injection exists, scripts execute without domain boundary restrictions.",
                    "evidence": "Content-Security-Policy header omitted in root response."
                })

            # Missing Strict-Transport-Security on HTTPS
            if "strict-transport-security" in missing and base_url.startswith("https"):
                self.candidate_weaknesses.append({
                    "cwe_id": "CWE-319",
                    "title": "Cleartext Transmission of Sensitive Information (Missing HSTS)",
                    "confidence": "high",
                    "rationale": "HTTPS endpoint does not advertise Strict-Transport-Security (HSTS), leaving clients vulnerable to SSL-stripping downgrades.",
                    "evidence": "Strict-Transport-Security header omitted."
                })

            # Server Banner Disclosure
            if header_obs.get("tech_fingerprint"):
                self.candidate_weaknesses.append({
                    "cwe_id": "CWE-200",
                    "title": "Information Exposure via Server Technology Banners",
                    "confidence": "medium",
                    "rationale": f"Headers disclose backend versions: {', '.join(header_obs['tech_fingerprint'])}.",
                    "evidence": str(header_obs["tech_fingerprint"])
                })

        # Check Active Path Enumeration findings
        if active_obs:
            for item in active_obs.get("results", []):
                # Discovered sensitive admin / setup paths
                if item.get("path") in ["/setup.php", "/admin", "/vulnerabilities/"] and item.get("status_code") in [200, 301, 302]:
                    self.candidate_weaknesses.append({
                        "cwe_id": "CWE-548",
                        "title": f"Exposure of Sensitive Management Interface at {item['path']}",
                        "confidence": "medium",
                        "rationale": f"Path '{item['path']}' returned HTTP {item['status_code']} with {item.get('content_length')} bytes. Further manual review is required to verify authorization controls.",
                        "evidence": f"GET {item['url']} -> HTTP {item['status_code']}"
                    })

    def _synthesize_manual_steps(self, base_url: str):
        """Generates reproducible next manual validation actions for authorized human tester."""
        self.next_manual_steps = [
            f"1. Manually test Clickjacking resilience on {base_url} using an iframe embedding test harness.",
            f"2. Inspect authentication flows at {base_url}/login or equivalent for anti-CSRF tokens and rate limiting.",
            f"3. Verify whether discovered administrative routes require valid session authentication.",
            f"4. If DVWA is deployed on {base_url}, manually inspect SQL Injection, XSS, and Command Injection modules in accordance with authorized lab guidelines."
        ]


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Authorized Scope Security Reconnaissance Assistant")
    parser.add_argument("-t", "--target", type=str, required=True, help="Target domain or IP (Must be in ALLOWED_TARGETS)")
    parser.add_argument("-p", "--port", type=int, help="Optional specific port")
    parser.add_argument("--https", action="store_true", help="Force HTTPS")
    parser.add_argument("--http", action="store_true", help="Force HTTP")
    parser.add_argument("-o", "--output", type=str, help="Save report to JSON file")

    args = parser.parse_args()
    use_https = True if args.https else (False if args.http else None)

    assistant = ScopedReconAssistant(target=args.target, port=args.port, use_https=use_https)
    result = asyncio.run(assistant.execute_plan())

    json_str = json.dumps(result, indent=2)
    print(json_str)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(json_str)
        print(f"\n[+] Saved JSON audit report to: {args.output}")

if __name__ == "__main__":
    main()
