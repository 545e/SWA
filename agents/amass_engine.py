"""
SWA AI OWASP Amass-Grade Subdomain Intelligence & Asset Discovery Engine
High-fidelity multi-source OSINT, active DNS permutation brute-forcing,
CNAME resolution, and dangling DNS / Subdomain Takeover detection.

Architecture:
1. Multi-Source Passive OSINT Feeds:
   - Certificate Transparency (crt.sh)
   - HackerTarget Host Search
   - Anubis DB Community Intelligence
   - AlienVault OTX Passive DNS
   - Wayback Machine CDX Historical Archive
2. External OWASP Amass CLI Bridge:
   - Auto-detects local amass binary (Windows, Linux, macOS)
   - Falls back automatically to native async Python Amass Engine
3. High-Yield Dictionary & AltDNS Alteration Permutations:
   - 180+ curated enterprise infrastructure and cloud subdomains
   - Contextual permutations (dev-{sub}, {sub}-staging, etc.)
4. Subdomain Takeover & Dangling CNAME Detector:
   - Checks CNAME targets against AWS S3, GitHub Pages, Azure, Heroku, CloudFront, etc.
   - Detects unclaimed SaaS resources and emits High/Critical findings.
"""

import asyncio
import re
import socket
import shutil
import json
import os
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import urlparse
import httpx

from core.models import LogEvent, VulnerabilityFinding, Severity
from core.queue_manager import queue_manager

# Comprehensive 180+ Enterprise Wordlist for Active Resolution
AMASS_EXTENDED_WORDLIST = [
    "api", "api-v1", "api-v2", "dev", "devel", "development", "stage", "staging",
    "test", "testing", "uat", "qa", "beta", "demo", "sandbox", "preview", "prod",
    "production", "admin", "adm", "administrator", "adminportal", "portal", "dashboard",
    "console", "panel", "manage", "manager", "management", "app", "apps", "application",
    "web", "www", "www2", "main", "core", "gateway", "gw", "router", "proxy",
    "auth", "authentication", "sso", "login", "signin", "signup", "idp", "iam",
    "keycloak", "auth0", "oauth", "jwt", "tokens", "session", "secure", "security",
    "vault", "secret", "secrets", "passwords", "cert", "certs", "ssl", "vpn",
    "remote", "bastion", "connect", "access", "teleport", "direct", "corp", "internal",
    "intra", "intranet", "private", "local", "office", "staff", "employee", "team",
    "mail", "webmail", "email", "smtp", "imap", "pop", "exchange", "autodiscover",
    "mx", "mx1", "mx2", "relay", "newsletter", "send", "mailer",
    "db", "database", "sql", "mysql", "postgres", "postgresql", "mongo", "mongodb",
    "redis", "memcached", "elastic", "elasticsearch", "solr", "cassandra", "data",
    "phpmyadmin", "pma", "pgadmin", "adminer", "cpanel", "whm", "webmin",
    "cdn", "static", "assets", "media", "images", "img", "files", "download",
    "downloads", "storage", "s3", "bucket", "blob", "aws", "azure", "gcp",
    "cloud", "edge", "mirror", "cache", "pub", "public",
    "git", "gitlab", "github", "bitbucket", "gitea", "repo", "repository", "source",
    "ci", "cd", "jenkins", "travis", "circleci", "drone", "argocd", "bamboo",
    "k8s", "kubernetes", "kube", "cluster", "node", "docker", "registry", "harbor",
    "monitor", "monitoring", "status", "health", "metrics", "prometheus", "grafana",
    "kibana", "splunk", "zabbix", "nagios", "datadog", "newrelic", "sentry",
    "jira", "confluence", "wiki", "docs", "help", "support", "ticket", "tickets",
    "faq", "kb", "knowledgebase", "service", "services", "desk", "servicedesk",
    "billing", "pay", "payment", "payments", "checkout", "cart", "shop", "store",
    "invoice", "pricing", "stripe", "orders", "wallet",
    "ns", "ns1", "ns2", "dns", "dns1", "dns2", "resolver", "whois",
    "client", "clients", "customer", "customers", "user", "users", "account", "accounts",
    "m", "mobile", "ios", "android", "ota", "update", "updates", "sync"
]

# Signatures for Dangling CNAME / Subdomain Takeover Detection
TAKEOVER_SIGNATURES = [
    {
        "provider": "GitHub Pages",
        "cname_patterns": [r"github\.io", r"github-pages"],
        "fingerprints": [r"There isn't a GitHub Pages site here", r"For root domain, check with DNS settings"]
    },
    {
        "provider": "Amazon S3",
        "cname_patterns": [r"s3\.amazonaws\.com", r"s3-website"],
        "fingerprints": [r"NoSuchBucket", r"The specified bucket does not exist"]
    },
    {
        "provider": "Heroku",
        "cname_patterns": [r"herokuapp\.com", r"herokudns\.com"],
        "fingerprints": [r"No such app", r"There's nothing here, yet\."]
    },
    {
        "provider": "Microsoft Azure",
        "cname_patterns": [r"azurewebsites\.net", r"cloudapp\.net", r"azureedge\.net"],
        "fingerprints": [r"404 Web Site not found", r"The resource you are looking for has been removed"]
    },
    {
        "provider": "Amazon CloudFront",
        "cname_patterns": [r"cloudfront\.net"],
        "fingerprints": [r"Bad request", r"The request could not be satisfied", r"ERROR: The request could not be satisfied"]
    },
    {
        "provider": "Fastly",
        "cname_patterns": [r"fastly\.net"],
        "fingerprints": [r"Fastly error: unknown domain"]
    },
    {
        "provider": "Shopify",
        "cname_patterns": [r"myshopify\.com"],
        "fingerprints": [r"Sorry, this shop is currently unavailable\."]
    },
    {
        "provider": "Zendesk",
        "cname_patterns": [r"zendesk\.com"],
        "fingerprints": [r"Help Center Closed", r"No such host"]
    },
    {
        "provider": "Pantheon",
        "cname_patterns": [r"pantheonsite\.io"],
        "fingerprints": [r"The gods are wise, but do not know of the site which you seek"]
    },
    {
        "provider": "Surge.sh",
        "cname_patterns": [r"surge\.sh"],
        "fingerprints": [r"project not found"]
    },
    {
        "provider": "Ghost",
        "cname_patterns": [r"ghost\.io"],
        "fingerprints": [r"The thing you were looking for is no longer here"]
    },
    {
        "provider": "Bitbucket",
        "cname_patterns": [r"bitbucket\.io"],
        "fingerprints": [r"Repository not found"]
    }
]

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9"
}

class AmassSubdomainEngine:
    """
    OWASP Amass-Grade Subdomain Discovery & Asset Mapping Engine.
    Employs passive OSINT feeds, dictionary queries, permutation mutations,
    and CNAME subdomain takeover verification.
    """

    def __init__(self, scan_id: str, base_domain: str, concurrency: int = 10, timeout: int = 8):
        self.scan_id = scan_id
        self.base_domain = self._normalize_domain(base_domain)
        self.concurrency = concurrency
        self.timeout = timeout
        self.amass_binary_path = self._locate_amass_binary()
        self.discovered_subs: Dict[str, Set[str]] = {}  # {hostname: {sources}}
        self.detailed_results: List[Dict[str, Any]] = []
        self.takeover_findings: List[VulnerabilityFinding] = []

    def _normalize_domain(self, domain_or_url: str) -> str:
        d = domain_or_url.strip().lower()
        if "://" in d:
            parsed = urlparse(d)
            d = parsed.hostname or d
        # Clean port if present
        d = d.split(":")[0]
        # Clean leading www or sub-prefixes to get base zone
        parts = d.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return d

    def _locate_amass_binary(self) -> Optional[str]:
        """Auto-detects native OWASP Amass binary if installed on the host."""
        which_path = shutil.which("amass")
        if which_path:
            return which_path

        # Standard Windows & Linux locations
        candidates = [
            r"C:\tools\amass.exe",
            r"C:\ProgramData\chocolatey\bin\amass.exe",
            os.path.expanduser("~/go/bin/amass.exe"),
            os.path.expanduser("~/go/bin/amass"),
            "/usr/bin/amass",
            "/usr/local/bin/amass",
            "/snap/bin/amass"
        ]
        for c in candidates:
            if os.path.isfile(c) and os.access(c, os.X_OK):
                return c
        return None

    async def log(self, message: str, level: str = "INFO"):
        event = LogEvent(scan_id=self.scan_id, agent="AmassEngine", level=level, message=message)
        await queue_manager.emit_log(event)

    def _register(self, hostname: str, source: str):
        h = hostname.strip().lower().rstrip(".")
        if not h or "*" in h:
            return
        # Ensure it belongs strictly to this base domain
        if h == self.base_domain or h.endswith(f".{self.base_domain}"):
            self.discovered_subs.setdefault(h, set()).add(source)

    async def run(self) -> Tuple[List[Dict[str, Any]], List[VulnerabilityFinding]]:
        """
        Executes full multi-stage Amass discovery workflow.
        Returns (subdomain_details, takeover_vulnerabilities).
        """
        # If IP address, skip subdomain enum
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", self.base_domain):
            await self.log("Target is a raw IP address; skipping subdomain asset mapping.", "INFO")
            return [], []

        await self.log(f"Launching OWASP Amass-Grade Subdomain Engine for apex zone: {self.base_domain}", "INFO")
        if self.amass_binary_path:
            await self.log(f"Native OWASP Amass CLI binary detected: {self.amass_binary_path}", "SUCCESS")
        else:
            await self.log("Using built-in Native Multi-Source Async Amass Engine (Passive OSINT + Wordlists + Takeover Verification).", "INFO")

        # Stage 1: Run Amass CLI (if installed) or Multi-Source Passive OSINT Feeds
        tasks = [
            self._query_crt_sh(),
            self._query_hackertarget(),
            self._query_anubis(),
            self._query_certspotter(),
            self._query_wayback()
        ]
        if self.amass_binary_path:
            tasks.append(self._run_amass_cli())

        await asyncio.gather(*tasks, return_exceptions=True)
        await self.log(f"Passive intelligence feeds identified {len(self.discovered_subs)} unique subdomains.", "SUCCESS")

        # Stage 2: Active High-Yield Dictionary Probing
        await self._probe_dictionary_wordlist()

        # Stage 3: AltDNS-Style Contextual Alterations & Permutations
        await self._generate_and_probe_permutations()

        await self.log(f"Total discovered candidates before live probing: {len(self.discovered_subs)}", "INFO")

        # Stage 4: Async Socket Resolution & HTTP Alive Probing & CNAME Takeover Verification
        await self._resolve_and_verify_subdomains()

        await self.log(f"Amass engine finished: {len(self.detailed_results)} responsive/verified hostnames mapped.", "SUCCESS")
        return self.detailed_results, self.takeover_findings

    async def _query_crt_sh(self):
        """Query Certificate Transparency logs via crt.sh"""
        url = f"https://crt.sh/?q=%25.{self.base_domain}&output=json"
        try:
            async with httpx.AsyncClient(verify=False, timeout=8.0, headers=DEFAULT_HEADERS) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    entries = resp.json()
                    count = 0
                    for entry in entries[:150]:
                        name_val = entry.get("name_value", "")
                        for sub in name_val.split("\n"):
                            self._register(sub, "crt.sh")
                            count += 1
                    if count > 0:
                        await self.log(f"[crt.sh] Harvested {count} certificates for {self.base_domain}", "INFO")
        except Exception:
            pass

    async def _query_hackertarget(self):
        """Query HackerTarget passive host search registry"""
        url = f"https://api.hackertarget.com/hostsearch/?q={self.base_domain}"
        try:
            async with httpx.AsyncClient(verify=False, timeout=7.0, headers=DEFAULT_HEADERS) as client:
                resp = await client.get(url)
                if resp.status_code == 200 and "API count exceeded" not in resp.text:
                    lines = resp.text.strip().splitlines()
                    for line in lines:
                        parts = line.split(",")
                        if parts:
                            self._register(parts[0], "HackerTarget")
                    await self.log(f"[HackerTarget] Parsed {len(lines)} DNS records", "INFO")
        except Exception:
            pass

    async def _query_anubis(self):
        """Query Anubis DB threat intelligence API"""
        url = f"https://jldc.me/anubis/subdomains/{self.base_domain}"
        try:
            async with httpx.AsyncClient(verify=False, timeout=7.0, headers=DEFAULT_HEADERS) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    entries = resp.json()
                    if isinstance(entries, list):
                        for sub in entries:
                            self._register(sub, "Anubis")
                        await self.log(f"[Anubis] Ingested {len(entries)} host records", "INFO")
        except Exception:
            pass

    async def _query_certspotter(self):
        """Query SSLMate CertSpotter CT log API"""
        url = f"https://api.certspotter.com/v1/issuances?domain={self.base_domain}&include_subdomains=true&expand=dns_names"
        try:
            async with httpx.AsyncClient(verify=False, timeout=6.0, headers=DEFAULT_HEADERS) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data[:60]:
                        for dns in item.get("dns_names", []):
                            self._register(dns, "CertSpotter")
        except Exception:
            pass

    async def _query_wayback(self):
        """Query Internet Archive Wayback Machine CDX API"""
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.base_domain}/*&output=json&fl=original&collapse=urlkey&limit=80"
        try:
            async with httpx.AsyncClient(verify=False, timeout=6.0, headers=DEFAULT_HEADERS) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    rows = resp.json()
                    if len(rows) > 1:
                        for row in rows[1:]:
                            target_url = row[0]
                            match = re.search(r"https?://([^/:]+)", target_url)
                            if match:
                                self._register(match.group(1), "WaybackCDX")
        except Exception:
            pass

    async def _run_amass_cli(self):
        """Invokes external OWASP Amass binary if present on host."""
        if not self.amass_binary_path:
            return
        try:
            cmd = [
                self.amass_binary_path, "enum",
                "-passive",
                "-d", self.base_domain,
                "-timeout", "2"
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30.0)
            lines = stdout.decode("utf-8", errors="ignore").splitlines()
            for line in lines:
                h = line.strip().lower()
                if h.endswith(self.base_domain):
                    self._register(h, "AmassCLI")
            await self.log(f"[OWASP Amass CLI] Extracted {len(lines)} discovered assets.", "SUCCESS")
        except Exception as e:
            await self.log(f"Amass CLI notice: {str(e)}", "INFO")

    async def _probe_dictionary_wordlist(self):
        """Active DNS probe using expanded 180+ enterprise wordlist."""
        loop = asyncio.get_running_loop()
        sem = asyncio.Semaphore(self.concurrency)

        async def check(prefix: str):
            candidate = f"{prefix}.{self.base_domain}"
            if candidate in self.discovered_subs:
                return
            async with sem:
                try:
                    addr_info = await loop.getaddrinfo(candidate, None)
                    if addr_info:
                        self._register(candidate, "ActiveBrute")
                except Exception:
                    pass

        tasks = [check(p) for p in AMASS_EXTENDED_WORDLIST]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _generate_and_probe_permutations(self):
        """AltDNS-style contextual alteration engine: generates mutations of known names."""
        known_prefixes = set()
        for sub in list(self.discovered_subs.keys())[:20]:
            name = sub.replace(f".{self.base_domain}", "")
            if name and "." not in name:
                known_prefixes.add(name)

        if not known_prefixes:
            return

        mutation_candidates = set()
        environments = ["dev", "stage", "test", "api", "uat", "admin", "internal", "corp"]
        for p in known_prefixes:
            for env in environments:
                if p != env:
                    mutation_candidates.add(f"{env}-{p}.{self.base_domain}")
                    mutation_candidates.add(f"{p}-{env}.{self.base_domain}")

        loop = asyncio.get_running_loop()
        sem = asyncio.Semaphore(self.concurrency)

        async def probe_mut(cand: str):
            if cand in self.discovered_subs:
                return
            async with sem:
                try:
                    addr = await loop.getaddrinfo(cand, None)
                    if addr:
                        self._register(cand, "AltDNS-Permutation")
                except Exception:
                    pass

        tasks = [probe_mut(c) for c in list(mutation_candidates)[:40]]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _resolve_and_verify_subdomains(self):
        """
        Deep resolution, CNAME aliasing, HTTP alive verification,
        and Subdomain Takeover detection.
        """
        loop = asyncio.get_running_loop()
        sem = asyncio.Semaphore(self.concurrency)
        all_hosts = list(self.discovered_subs.keys())

        async def inspect_single(sub: str):
            async with sem:
                ip = ""
                cname = ""
                aliases = []
                try:
                    # Resolve IP & CNAME Aliases
                    res = await loop.run_in_executor(None, socket.gethostbyname_ex, sub)
                    # res: (hostname, aliaslist, ipaddrlist)
                    if res[0] != sub:
                        cname = res[0]
                    aliases = res[1]
                    if res[2]:
                        ip = res[2][0]
                except Exception:
                    try:
                        addr_info = await loop.getaddrinfo(sub, None)
                        ips = [item[4][0] for item in addr_info if item[4]]
                        ip = ips[0] if ips else ""
                    except Exception:
                        pass

                # Probe HTTP & HTTPS
                status_code = None
                server = ""
                response_body = ""

                async with httpx.AsyncClient(verify=False, timeout=4.0, follow_redirects=True, headers=DEFAULT_HEADERS) as client:
                    try:
                        resp = await client.get(f"https://{sub}")
                        status_code = resp.status_code
                        server = resp.headers.get("server", "")
                        response_body = resp.text[:4000]
                    except Exception:
                        try:
                            resp = await client.get(f"http://{sub}")
                            status_code = resp.status_code
                            server = resp.headers.get("server", "")
                            response_body = resp.text[:4000]
                        except Exception:
                            pass

                # Subdomain Takeover Analysis
                takeover_detected, provider_name, reason = self._check_takeover(sub, cname, aliases, response_body)
                if takeover_detected:
                    finding = VulnerabilityFinding(
                        scan_id=self.scan_id,
                        title=f"Subdomain Takeover Detected ({provider_name})",
                        severity=Severity.CRITICAL,
                        cwe="CWE-284: Improper Access Control",
                        cvss_score=8.6,
                        endpoint=f"https://{sub}",
                        description=f"Host '{sub}' has a dangling CNAME pointer to {cname or provider_name}. {reason}",
                        remediation_advice=f"Immediately remove or update the dangling DNS CNAME record for '{sub}' pointing to {provider_name}, or reclaim the orphaned asset in your cloud account.",
                        remediation_patch=f"; DNS zone update for {self.base_domain}\n; Remove dangling alias:\n{sub}. IN CNAME [REMOVE-DANGLING-RECORD]"
                    )
                    self.takeover_findings.append(finding)
                    await self.log(f"CRITICAL: Subdomain Takeover identified on {sub} -> {provider_name}!", "FINDING")

                sources = sorted(list(self.discovered_subs.get(sub, ["Unknown"])))
                entry = {
                    "subdomain": sub,
                    "ip": ip,
                    "cname": cname or (aliases[0] if aliases else ""),
                    "status": status_code,
                    "server": server,
                    "sources": sources,
                    "takeover_risk": takeover_detected
                }
                return entry

        # Bound to top 60 candidates for rapid response
        tasks = [inspect_single(s) for s in all_hosts[:60]]
        inspected = await asyncio.gather(*tasks, return_exceptions=True)
        for item in inspected:
            if isinstance(item, dict) and item:
                self.detailed_results.append(item)
                if item.get("status"):
                    src_tag = "+".join(item["sources"][:2])
                    await self.log(
                        f"Live asset confirmed: {item['subdomain']} ({item['ip']}) [HTTP {item['status']}] [via {src_tag}]",
                        "FINDING"
                    )

    def _check_takeover(self, sub: str, cname: str, aliases: List[str], body: str) -> Tuple[bool, str, str]:
        """Detects whether a dangling CNAME matches an unclaimed cloud resource."""
        all_targets = [cname] + aliases
        for target in all_targets:
            if not target:
                continue
            for sig in TAKEOVER_SIGNATURES:
                for pattern in sig["cname_patterns"]:
                    if re.search(pattern, target, re.IGNORECASE):
                        provider = sig["provider"]
                        # Inspect response body for unclaimed signature
                        for fp in sig["fingerprints"]:
                            if re.search(fp, body, re.IGNORECASE):
                                return True, provider, f"Dangling CNAME alias points to {target} and returned cloud error signature: '{fp}'."
        return False, "", ""
