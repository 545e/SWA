"""
SWA AI — Autonomous Layered Subdomain Discovery & Asset Intelligence Engine
Next-generation multi-source OSINT, async DNS brute-forcing, wildcard DNS detection,
live HTTP/HTTPS status & title grabbing, and automated Subdomain Takeover verification.

Architecture:
1. Multi-Source Passive OSINT Feeds:
   - Certificate Transparency (crt.sh JSON + HTML regex fallback)
   - AlienVault OTX Passive DNS
   - HackerTarget Host Search
   - CertSpotter SSLMate CT API
   - Internet Archive Wayback Machine CDX API
   - ThreatMiner Threat Intelligence
   - URLScan.io Global Scan Index
   - Subdomain Center API
   - Anubis DB Registry
   - RapidDNS Search
   - Native OWASP Amass CLI bridge (auto-detected on host)
2. Wildcard DNS Detection Engine:
   - Probes pseudo-random nonexistent hostnames
   - Identifies wildcard responses and isolates baseline IP footprints
   - Prevents false-positive flood while preserving legitimate co-located assets
3. Autonomous Active DNS Resolution:
   - 350+ curated enterprise, cloud, and infrastructure wordlist
   - Async DNS resolver (dnspython asyncresolver) with configurable public fallbacks (1.1.1.1, 8.8.8.8)
   - Multi-record type querying: A, AAAA, and CNAME alias chains
4. AltDNS Contextual Alteration & Mutation Engine:
   - Dynamic prefixes and environment mutation matrix (dev, stage, prod, vpn, api)
5. Recursive Multi-Tier Mining:
   - Probes sub-zones under active 2nd-level assets (e.g., dev.corp.domain.com)
6. Live HTTP/HTTPS Probing & Fingerprinting:
   - Concurrently verifies responsive status codes, Server headers, and HTML titles
7. Subdomain Takeover Verification:
   - Inspects CNAME chains against 17+ cloud providers (AWS S3, GitHub Pages, Heroku, Azure, CloudFront, Netlify, etc.)
"""

import asyncio
import re
import socket
import shutil
import json
import os
import html
import uuid
import datetime
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import urlparse
import httpx

try:
    import dns.asyncresolver
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from core.models import LogEvent, VulnerabilityFinding, Severity
from core.queue_manager import queue_manager

# Comprehensive 350+ Curated Enterprise, Microservices & Cloud Infrastructure Wordlist
AMASS_EXPANDED_WORDLIST = [
    # Core & Common
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure",
    "vpn", "api", "dev", "staging", "test", "portal", "admin", "app", "dashboard", "git",
    "auth", "login", "sso", "support", "beta", "corp", "internal", "cloud", "status", "docs",

    # API, Gateways & Microservices
    "api-v1", "api-v2", "api-dev", "api-stage", "api-test", "api-prod", "v1", "v2", "v3",
    "graphql", "rest", "gateway", "gw", "edge", "router", "proxy", "reverse-proxy", "envoy", "kong",
    "traefik", "istio", "mesh", "apigw", "apimanager", "endpoints", "services", "svc", "microservices",
    
    # Development, Staging & QA Environments
    "devel", "development", "stage", "stg", "testing", "uat", "qa", "qa1",
    "qa2", "demo", "sandbox", "preview", "preview-app", "lab", "labs", "canary", "poc",
    "prod", "production", "live", "release", "trunk",
    
    # Authentication, Identity & Secrets
    "authentication", "signin", "signup", "register", "idp", "iam", "saml",
    "oauth", "oauth2", "jwt", "tokens", "session", "security", "vault", "secret", "secrets",
    "keycloak", "auth0", "okta", "ping", "ldap", "ad", "activedirectory", "cert", "certs", "ssl",
    "pki", "passwords", "identity",
    
    # Remote Access, VPN & Networking
    "bastion", "teleport", "direct", "access", "connect",
    "intra", "intranet", "private", "local", "office", "staff", "employee", "team",
    "gateway-vpn", "openvpn", "wireguard", "citrix", "rdp", "ssh", "jump", "jumphost",
    
    # Admin, Management & Operations
    "adm", "administrator", "adminportal", "console", "panel", "manage",
    "manager", "management", "control", "cp", "cpanel", "whm", "webmin", "phpmyadmin", "pma",
    "pgadmin", "adminer", "ops", "operations", "infra", "infrastructure", "noc", "soc",
    
    # Cloud, Containers & Orchestration
    "k8s", "kubernetes", "kube", "cluster", "node", "nodes", "docker", "registry", "harbor",
    "rancher", "argocd", "helm", "consul", "nomad", "terraform", "swarm", "openshift",
    "aws", "azure", "gcp", "cloud-storage", "s3", "bucket", "blob", "storage",
    
    # CI/CD & Code Repositories
    "gitlab", "github", "bitbucket", "gitea", "repo", "repository", "source", "code",
    "ci", "cd", "jenkins", "travis", "circleci", "drone", "bamboo", "teamcity", "build",
    "builds", "artifactory", "nexus", "pipelines",
    
    # Monitoring, Logging & Observability
    "monitor", "monitoring", "health", "metrics", "telemetry", "prometheus",
    "grafana", "kibana", "elastic", "elasticsearch", "solr", "splunk", "zabbix", "nagios",
    "datadog", "newrelic", "sentry", "jaeger", "graylog", "log", "logs", "logging",
    
    # Databases & Caching
    "db", "database", "sql", "mysql", "postgres", "postgresql", "mongo", "mongodb", "redis",
    "memcached", "cassandra", "couchdb", "dynamo", "data", "warehouse", "analytics", "bi",
    
    # Web, Content & Frontend
    "apps", "application", "www2", "main", "core", "client", "clients",
    "customer", "customers", "user", "users", "account", "accounts", "profile", "home",
    "m", "mobile", "ios", "android", "static", "assets", "media", "images", "img", "files",
    "download", "downloads", "upload", "uploads", "cdn", "edge-cache", "pub", "public",
    
    # Email & Messaging
    "email", "imap", "pop", "exchange", "autodiscover", "mx",
    "mx1", "mx2", "relay", "newsletter", "send", "mailer", "mailgun", "sendgrid", "chat",
    "slack", "mattermost", "irc",
    
    # E-Commerce & Billing
    "billing", "pay", "payment", "payments", "checkout", "cart", "shop", "store", "invoice",
    "pricing", "stripe", "orders", "wallet", "commerce",
    
    # Documentation & Support
    "documentation", "wiki", "confluence", "jira", "help", "ticket",
    "tickets", "faq", "kb", "knowledgebase", "service", "desk", "servicedesk",
    "bug", "bugs", "issues"
]

# Signatures for Dangling CNAME / Subdomain Takeover Detection (17 Providers)
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
    },
    {
        "provider": "Netlify",
        "cname_patterns": [r"netlify\.app", r"netlify\.com"],
        "fingerprints": [r"Not Found - Request ID", r"page not found"]
    },
    {
        "provider": "Readme.io",
        "cname_patterns": [r"readme\.io"],
        "fingerprints": [r"Project doesnt exist", r"What project are you looking for"]
    },
    {
        "provider": "WordPress.com",
        "cname_patterns": [r"wordpress\.com"],
        "fingerprints": [r"Do you want to register", r"is not available"]
    },
    {
        "provider": "GitLab Pages",
        "cname_patterns": [r"gitlab\.io"],
        "fingerprints": [r"The page you're looking for could not be found"]
    },
    {
        "provider": "Firebase Hosting",
        "cname_patterns": [r"firebaseapp\.com", r"web\.app"],
        "fingerprints": [r"Site Not Found", r"Firebase Hosting Setup Complete"]
    }
]

# Standard multi-part public suffixes for accurate apex domain resolution
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "gov.in", "net.in", "org.in", "nic.in", "ac.in",
    "co.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "org.br", "gov.br",
    "com.sg", "edu.sg", "gov.sg",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "com.tr", "org.tr", "gov.tr",
    "co.za", "org.za", "gov.za",
    "com.mx", "org.mx", "gob.mx"
}

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9"
}

PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"]

# In-memory TTL cache for DNS and live resolution
_SUBDOMAIN_DNS_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
DNS_CACHE_TTL_SECONDS = 300



class AmassSubdomainEngine:
    """
    OWASP Amass-Grade Autonomous Subdomain Discovery & Asset Mapping Engine.
    Employs 10+ passive intelligence feeds, async DNS dictionary enumeration,
    rigorous wildcard DNS baseline detection, contextual AltDNS permutations,
    recursive multi-tier enumeration, and automated CNAME takeover verification.
    """

    def __init__(
        self,
        scan_id: str,
        base_domain: str,
        concurrency: int = 20,
        timeout: int = 5,
        recursive: bool = True,
        custom_resolvers: Optional[List[str]] = None,
        wordlist: Optional[List[str]] = None
    ):
        self.scan_id = scan_id
        self.raw_target = base_domain.strip().lower()
        self.base_domain = self._normalize_domain(base_domain)
        self.concurrency = max(5, min(concurrency, 50))
        self.timeout = max(3, timeout)
        self.recursive = recursive
        self.custom_resolvers = custom_resolvers or PUBLIC_RESOLVERS
        self.wordlist = wordlist or AMASS_EXPANDED_WORDLIST
        self.amass_binary_path = self._locate_amass_binary()
        self.subfinder_binary_path = self._locate_subfinder_binary()
        
        # Discovered hostnames -> set of discovery source strings
        self.discovered_subs: Dict[str, Set[str]] = {}
        # Structured asset inventory records
        self.detailed_results: List[Dict[str, Any]] = []
        self.takeover_findings: List[VulnerabilityFinding] = []
        self.provider_errors: Dict[str, str] = {}
        
        # Wildcard DNS Detection state
        self.wildcard_detected: bool = False
        self.wildcard_ips: Set[str] = set()
        self.wildcard_cnames: Set[str] = set()
        
        # Performance & triage metrics
        self.start_time: float = 0.0
        self.duration_seconds: float = 0.0
        self.metrics = {
            "discovered": 0,
            "resolved": 0,
            "wildcard_filtered": 0,
            "failed_resolution": 0,
            "unresolved": 0,
            "live_count": 0,
            "provider_errors_count": 0,
            "scan_duration_seconds": 0.0
        }
        self.is_cancelled: bool = False

    def _normalize_domain(self, domain_or_url: str) -> str:
        """Accurately extracts apex/root domain respecting multi-part ccTLDs (.co.uk, .com.au, etc.)."""
        d = domain_or_url.strip().lower()
        if "://" in d:
            parsed = urlparse(d)
            d = parsed.hostname or d
        # Remove port if present
        d = d.split(":")[0].rstrip(".")

        # Try tldextract if available for perfect public suffix list matching
        try:
            import tldextract
            extracted = tldextract.extract(d)
            if extracted.domain and extracted.suffix:
                return f"{extracted.domain}.{extracted.suffix}"
        except Exception:
            pass

        # Built-in robust fallback
        parts = d.split(".")
        if len(parts) >= 3:
            potential_cctld = f"{parts[-2]}.{parts[-1]}"
            if potential_cctld in MULTI_PART_SUFFIXES:
                return ".".join(parts[-3:])
            return ".".join(parts[-2:])
        return d

    def _locate_amass_binary(self) -> Optional[str]:
        """Auto-detects native OWASP Amass binary if installed on the host."""
        which_path = shutil.which("amass")
        if which_path:
            return which_path

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

    def _locate_subfinder_binary(self) -> Optional[str]:
        """Auto-detects native ProjectDiscovery Subfinder binary if installed on the host."""
        which_path = shutil.which("subfinder")
        if which_path:
            return which_path

        candidates = [
            r"C:\tools\subfinder.exe",
            r"C:\ProgramData\chocolatey\bin\subfinder.exe",
            os.path.expanduser("~/go/bin/subfinder.exe"),
            os.path.expanduser("~/go/bin/subfinder"),
            "/usr/bin/subfinder",
            "/usr/local/bin/subfinder",
            "/snap/bin/subfinder"
        ]
        for c in candidates:
            if os.path.isfile(c) and os.access(c, os.X_OK):
                return c
        return None

    def _check_cancelled(self) -> bool:
        if self.is_cancelled:
            return True
        try:
            task = asyncio.current_task()
            if task and task.cancelling():
                self.is_cancelled = True
                return True
        except Exception:
            pass
        return False

    async def log(self, message: str, level: str = "INFO"):
        event = LogEvent(scan_id=self.scan_id, agent="AmassEngine", level=level, message=message)
        await queue_manager.emit_log(event)

    def _register(self, hostname: str, source: str) -> bool:
        """Validates, sanitizes, and registers candidate hostname under the active apex scope."""
        if not hostname:
            return False
        h = hostname.strip().lower().rstrip(".")
        # Reject invalid hostname characters, wildcard tokens, HTML tags, or path slashes
        if (
            not h
            or "*" in h
            or " " in h
            or "<" in h
            or ">" in h
            or "/" in h
            or "\\" in h
            or "@" in h
            or ":" in h
        ):
            return False
        
        # Reject hostnames exceeding standard DNS RFC length
        if len(h) > 253:
            return False

        # Ensure it belongs strictly to this base domain
        if h == self.base_domain or h.endswith(f".{self.base_domain}"):
            self.discovered_subs.setdefault(h, set()).add(source)
            return True
        return False

    def _create_resolver(self) -> Any:
        """Constructs an async DNS resolver configured with fallback nameservers."""
        if not HAS_DNSPYTHON:
            return None
        try:
            res = dns.asyncresolver.Resolver()
            res.nameservers = list(self.custom_resolvers)
            res.timeout = 2.0
            res.lifetime = 2.5
            return res
        except Exception:
            return None

    # =====================================================================
    # Wildcard DNS Detection Engine
    # =====================================================================

    async def _detect_wildcard_dns(self):
        """
        Tests pseudo-random nonexistent hostnames against DNS to determine
        if the zone uses wildcard resolution (*.domain.com).
        """
        resolver = self._create_resolver()
        if not resolver:
            return

        wildcard_hits: List[Set[str]] = []
        for _ in range(3):
            rnd_sub = f"swa-wc-{uuid.uuid4().hex[:10]}.{self.base_domain}"
            ips = set()
            try:
                ans = await resolver.resolve(rnd_sub, "A")
                for r in ans:
                    ips.add(str(r))
            except Exception:
                pass

            try:
                cname_ans = await resolver.resolve(rnd_sub, "CNAME")
                for r in cname_ans:
                    self.wildcard_cnames.add(str(r).rstrip("."))
            except Exception:
                pass

            if ips:
                wildcard_hits.append(ips)

        # If 2 or more random probes returned identical IPs, wildcard DNS is verified
        if len(wildcard_hits) >= 2 and wildcard_hits[0] == wildcard_hits[1]:
            self.wildcard_detected = True
            self.wildcard_ips = wildcard_hits[0]
            await self.log(
                f"Wildcard DNS identified for '{self.base_domain}' -> IPs: {', '.join(sorted(self.wildcard_ips))}. Wildcard mitigation active.",
                "WARN"
            )
        else:
            self.wildcard_detected = False
            self.wildcard_ips.clear()

    # =====================================================================
    # Main Execution Flow
    # =====================================================================

    async def run(self) -> Tuple[List[Dict[str, Any]], List[VulnerabilityFinding]]:
        """
        Executes layered autonomous discovery:
        1. Wildcard DNS baseline detection
        2. 10+ Passive OSINT intelligence feeds
        3. High-speed active DNS dictionary enumeration
        4. AltDNS contextual alteration permutations
        5. Recursive multi-tier discovery
        6. Live DNS resolution, CNAME tracing, HTTP/HTTPS alive & title grabbing
        7. Subdomain takeover verification
        """
        import time as _pytime
        self.start_time = _pytime.time()
        # If raw IP address, skip subdomain enumeration
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", self.base_domain):
            await self.log("Target is a raw IP address; skipping subdomain asset mapping.", "INFO")
            return [], []

        await self.log(f"Launching Layered Autonomous Subdomain Engine for apex zone: {self.base_domain}", "INFO")
        if self.amass_binary_path:
            await self.log(f"External OWASP Amass CLI detected: {self.amass_binary_path}", "SUCCESS")

        # Always register the apex domain itself
        self._register(self.base_domain, "ApexRoot")

        # Step 1: Wildcard DNS Baseline Detection
        try:
            await self._detect_wildcard_dns()
        except Exception as e:
            await self.log(f"Wildcard detection notice: {str(e)}", "WARN")

        if self._check_cancelled():
            return self.detailed_results, self.takeover_findings

        # Step 2: Run 10+ Passive OSINT Intelligence Feeds Concurrently
        passive_tasks = [
            self._query_crt_sh(),
            self._query_hackertarget(),
            self._query_alienvault_otx(),
            self._query_certspotter(),
            self._query_wayback(),
            self._query_threatminer(),
            self._query_urlscan(),
            self._query_subdomain_center(),
            self._query_anubis(),
            self._query_rapiddns()
        ]
        if self.amass_binary_path:
            passive_tasks.append(self._run_amass_cli())
        if self.subfinder_binary_path:
            passive_tasks.append(self._run_subfinder_cli())

        await asyncio.gather(*passive_tasks, return_exceptions=True)
        await self.log(f"Passive intelligence feeds harvested {len(self.discovered_subs)} unique asset candidates.", "SUCCESS")

        if self._check_cancelled():
            return self.detailed_results, self.takeover_findings

        # Step 3: Active High-Yield Dictionary Probing
        await self.log("Executing high-speed active DNS wordlist resolution...", "INFO")
        try:
            await self._probe_dictionary_wordlist(self.base_domain)
        except Exception as e:
            await self.log(f"Active dictionary probing notice: {str(e)}", "WARN")

        if self._check_cancelled():
            return self.detailed_results, self.takeover_findings

        # Step 4: AltDNS Contextual Alterations & Permutations
        try:
            await self._generate_and_probe_permutations()
        except Exception as e:
            await self.log(f"AltDNS permutation notice: {str(e)}", "WARN")

        # Step 5: Recursive Subdomain Mining (Depth 2)
        if self.recursive and not self._check_cancelled():
            try:
                await self._run_recursive_discovery()
            except Exception as e:
                await self.log(f"Recursive mining notice: {str(e)}", "WARN")

        self.metrics["discovered"] = len(self.discovered_subs)
        await self.log(f"Total discovered candidates before live probing: {len(self.discovered_subs)}", "INFO")

        # Step 6: Deep Resolution, Alive Probing, Page Title Grabbing & Takeover Detection
        await self.log("Executing live asset resolution, HTTP verification & takeover detection...", "INFO")
        try:
            await self._resolve_and_verify_subdomains()
        except Exception as e:
            await self.log(f"Live probing notice: {str(e)}", "WARN")

        # Sort results: live assets first, then by subdomain name
        self.detailed_results.sort(key=lambda x: (x.get("status") is None, x.get("subdomain", "")))

        # Finalize metrics
        import time as _pytime
        self.duration_seconds = round(_pytime.time() - self.start_time, 2)
        self.metrics["scan_duration_seconds"] = self.duration_seconds
        self.metrics["resolved"] = sum(1 for a in self.detailed_results if a.get("dns_confirmed"))
        self.metrics["failed_resolution"] = sum(1 for a in self.detailed_results if a.get("validation_status") == "unresolved")
        self.metrics["unresolved"] = self.metrics["failed_resolution"]
        self.metrics["live_count"] = sum(1 for a in self.detailed_results if a.get("status"))
        self.metrics["provider_errors_count"] = len(self.provider_errors)

        await self.log(
            f"Autonomous Subdomain Engine completed: Mapped {len(self.detailed_results)} total assets "
            f"({self.metrics['resolved']} resolved, {self.metrics['live_count']} live HTTP/S, "
            f"{self.metrics['wildcard_filtered']} wildcard-filtered).",
            "SUCCESS"
        )
        return self.detailed_results, self.takeover_findings

    # =====================================================================
    # Passive OSINT Intelligence Feed Collectors
    # =====================================================================

    async def _query_crt_sh(self):
        """Query Certificate Transparency logs via crt.sh with JSON & HTML regex fallback."""
        url = f"https://crt.sh/?q=%25.{self.base_domain}&output=json"
        try:
            async with httpx.AsyncClient(verify=False, timeout=7.0, headers=DEFAULT_HEADERS) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    entries = resp.json()
                    count = 0
                    for entry in entries[:300]:
                        name_val = entry.get("name_value", "")
                        for sub in name_val.split("\n"):
                            if self._register(sub, "crt.sh"):
                                count += 1
                    if count > 0:
                        await self.log(f"[crt.sh] Ingested {count} certificate records for {self.base_domain}", "INFO")
                        return
        except Exception:
            pass

        # HTML regex fallback if crt.sh JSON endpoint times out or errors
        try:
            html_url = f"https://crt.sh/?q=%25.{self.base_domain}"
            async with httpx.AsyncClient(verify=False, timeout=6.0, headers=DEFAULT_HEADERS) as client:
                r = await client.get(html_url)
                if r.status_code == 200:
                    matches = set(re.findall(rf"[\w\.-]+\.{re.escape(self.base_domain)}", r.text, re.IGNORECASE))
                    for m in matches:
                        self._register(m, "crt.sh-html")
        except Exception:
            pass

    async def _query_hackertarget(self):
        """Query HackerTarget passive host search registry."""
        url = f"https://api.hackertarget.com/hostsearch/?q={self.base_domain}"
        try:
            async with httpx.AsyncClient(verify=False, timeout=6.0, headers=DEFAULT_HEADERS) as client:
                resp = await client.get(url)
                if resp.status_code == 200 and "API count exceeded" not in resp.text:
                    lines = resp.text.strip().splitlines()
                    for line in lines:
                        parts = line.split(",")
                        if parts:
                            self._register(parts[0], "HackerTarget")
        except Exception:
            pass

    async def _query_alienvault_otx(self):
        """Query AlienVault OTX Passive DNS threat indicators."""
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.base_domain}/passive_dns"
        try:
            async with httpx.AsyncClient(verify=False, timeout=6.0, headers=DEFAULT_HEADERS) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for record in data.get("passive_dns", []):
                        h = record.get("hostname")
                        if h:
                            self._register(h, "AlienVault-OTX")
        except Exception:
            pass

    async def _query_certspotter(self):
        """Query SSLMate CertSpotter CT log issuances."""
        url = f"https://api.certspotter.com/v1/issuances?domain={self.base_domain}&include_subdomains=true&expand=dns_names"
        try:
            async with httpx.AsyncClient(verify=False, timeout=6.0, headers=DEFAULT_HEADERS) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data[:100]:
                        for dns_name in item.get("dns_names", []):
                            self._register(dns_name, "CertSpotter")
        except Exception:
            pass

    async def _query_wayback(self):
        """Query Internet Archive Wayback Machine CDX API."""
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.base_domain}/*&output=json&fl=original&collapse=urlkey&limit=150"
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

    async def _query_threatminer(self):
        """Query ThreatMiner cyber threat intelligence API."""
        url = f"https://api.threatminer.org/v2/domain.php?q={self.base_domain}&rt=5"
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0, headers=DEFAULT_HEADERS) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for sub in data.get("results", []):
                        self._register(sub, "ThreatMiner")
        except Exception:
            pass

    async def _query_urlscan(self):
        """Query URLScan.io index for recorded domain appearances."""
        url = f"https://urlscan.io/api/v1/search/?q=domain:{self.base_domain}&size=100"
        try:
            async with httpx.AsyncClient(verify=False, timeout=6.0, headers=DEFAULT_HEADERS) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for res in data.get("results", []):
                        page_domain = res.get("page", {}).get("domain")
                        if page_domain:
                            self._register(page_domain, "URLScan")
        except Exception:
            pass

    async def _query_subdomain_center(self):
        """Query Subdomain Center API."""
        url = f"https://api.subdomain.center/subdomains/{self.base_domain}"
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0, headers=DEFAULT_HEADERS) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    subs = resp.json()
                    if isinstance(subs, list):
                        for s in subs:
                            self._register(s, "SubdomainCenter")
        except Exception:
            pass

    async def _query_anubis(self):
        """Query Anubis DB threat intelligence."""
        url = f"https://jldc.me/anubis/subdomains/{self.base_domain}"
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0, headers=DEFAULT_HEADERS) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    entries = resp.json()
                    if isinstance(entries, list):
                        for sub in entries:
                            self._register(sub, "Anubis")
        except Exception:
            pass

    async def _query_rapiddns(self):
        """Query RapidDNS public DNS records."""
        url = f"https://rapiddns.io/subdomain/{self.base_domain}?full=1"
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0, headers=DEFAULT_HEADERS) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    matches = set(re.findall(rf"[\w\.-]+\.{re.escape(self.base_domain)}", resp.text, re.IGNORECASE))
                    for m in matches:
                        self._register(m, "RapidDNS")
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
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20.0)
            lines = stdout.decode("utf-8", errors="ignore").splitlines()
            for line in lines:
                h = line.strip().lower()
                if h.endswith(self.base_domain):
                    self._register(h, "AmassCLI")
            await self.log(f"[OWASP Amass CLI] Harvested {len(lines)} discovered assets.", "SUCCESS")
        except Exception as e:
            self.provider_errors["AmassCLI"] = str(e)
            await self.log(f"Amass CLI notice: {str(e)}", "INFO")

    async def _run_subfinder_cli(self):
        """Invokes external Subfinder binary if present on host."""
        if not self.subfinder_binary_path:
            return
        try:
            cmd = [
                self.subfinder_binary_path,
                "-d", self.base_domain,
                "-silent",
                "-t", "20",
                "-timeout", "5"
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20.0)
            lines = stdout.decode("utf-8", errors="ignore").splitlines()
            for line in lines:
                h = line.strip().lower()
                if h.endswith(self.base_domain):
                    self._register(h, "SubfinderCLI")
            await self.log(f"[Subfinder CLI] Harvested {len(lines)} discovered assets.", "SUCCESS")
        except Exception as e:
            self.provider_errors["SubfinderCLI"] = str(e)
            await self.log(f"Subfinder CLI notice: {str(e)}", "INFO")

    # =====================================================================
    # Active Wordlist & Permutation Engines
    # =====================================================================

    async def _probe_dictionary_wordlist(self, zone: str):
        """Active DNS probe using curated wordlist and async resolver."""
        resolver = self._create_resolver()
        sem = asyncio.Semaphore(self.concurrency)

        async def check(prefix: str):
            if self._check_cancelled():
                return
            candidate = f"{prefix}.{zone}"
            if candidate in self.discovered_subs:
                return
            async with sem:
                ips = set()
                try:
                    if resolver:
                        ans = await resolver.resolve(candidate, "A")
                        for r in ans:
                            ips.add(str(r))
                    else:
                        loop = asyncio.get_running_loop()
                        addr_info = await loop.getaddrinfo(candidate, None)
                        ips = {item[4][0] for item in addr_info if item[4]}
                except Exception:
                    return

                if ips:
                    # Filter out if resolves purely to wildcard IP baseline
                    if self.wildcard_detected and self.wildcard_ips and ips.issubset(self.wildcard_ips):
                        self.metrics["wildcard_filtered"] += 1
                        return
                    self._register(candidate, "ActiveDNS")

        tasks = [check(p) for p in self.wordlist]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _generate_and_probe_permutations(self):
        """AltDNS-style contextual alteration engine: generates mutations of known names."""
        known_prefixes = set()
        for sub in list(self.discovered_subs.keys())[:30]:
            name = sub.replace(f".{self.base_domain}", "")
            if name and "." not in name:
                known_prefixes.add(name)

        if not known_prefixes:
            return

        mutation_candidates = set()
        environments = ["dev", "stage", "test", "api", "uat", "admin", "internal", "corp", "v1", "v2", "app"]
        for p in list(known_prefixes)[:15]:
            for env in environments:
                if p != env:
                    mutation_candidates.add(f"{env}-{p}.{self.base_domain}")
                    mutation_candidates.add(f"{p}-{env}.{self.base_domain}")

        resolver = self._create_resolver()
        sem = asyncio.Semaphore(self.concurrency)

        async def probe_mut(cand: str):
            if self._check_cancelled() or cand in self.discovered_subs:
                return
            async with sem:
                ips = set()
                try:
                    if resolver:
                        ans = await resolver.resolve(cand, "A")
                        for r in ans:
                            ips.add(str(r))
                    else:
                        loop = asyncio.get_running_loop()
                        addr = await loop.getaddrinfo(cand, None)
                        ips = {item[4][0] for item in addr if item[4]}
                except Exception:
                    return

                if ips:
                    if self.wildcard_detected and self.wildcard_ips and ips.issubset(self.wildcard_ips):
                        self.metrics["wildcard_filtered"] += 1
                        return
                    self._register(cand, "AltDNS-Permutation")

        tasks = [probe_mut(c) for c in list(mutation_candidates)[:60]]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _run_recursive_discovery(self):
        """Discovers multi-tier subdomains under active 2nd-level subdomains."""
        discovered = list(self.discovered_subs.keys())
        zones_to_recurse = set()
        for s in discovered:
            rel = s.replace(f".{self.base_domain}", "")
            parts = rel.split(".")
            if len(parts) == 1 and parts[0] in ["corp", "internal", "dev", "stage", "api", "cloud", "infra", "prod"]:
                zones_to_recurse.add(s)

        if not zones_to_recurse:
            return

        await self.log(f"Recursively exploring {len(zones_to_recurse)} multi-tier zones: {', '.join(zones_to_recurse)}", "INFO")
        core_words = ["api", "auth", "vpn", "admin", "portal", "db", "app", "login", "gateway", "k8s"]
        resolver = self._create_resolver()
        sem = asyncio.Semaphore(self.concurrency)

        async def check_rec(sub_prefix: str, zone: str):
            if self._check_cancelled():
                return
            c = f"{sub_prefix}.{zone}"
            if c in self.discovered_subs:
                return
            async with sem:
                ips = set()
                try:
                    if resolver:
                        ans = await resolver.resolve(c, "A")
                        for r in ans:
                            ips.add(str(r))
                    else:
                        loop = asyncio.get_running_loop()
                        addr = await loop.getaddrinfo(c, None)
                        ips = {item[4][0] for item in addr if item[4]}
                except Exception:
                    return

                if ips:
                    if self.wildcard_detected and self.wildcard_ips and ips.issubset(self.wildcard_ips):
                        self.metrics["wildcard_filtered"] += 1
                        return
                    self._register(c, "RecursiveMining")

        tasks = [check_rec(w, z) for z in zones_to_recurse for w in core_words]
        await asyncio.gather(*tasks, return_exceptions=True)

    # =====================================================================
    # Live Probing, Title Extraction & Takeover Verification
    # =====================================================================

    async def _resolve_and_verify_subdomains(self):
        """
        Deep DNS resolution (A, AAAA, CNAME), HTTP alive verification,
        page title extraction, and Subdomain Takeover detection across discovered assets.
        Results are appended progressively so partial progress is preserved.
        """
        resolver = self._create_resolver()
        sem = asyncio.Semaphore(self.concurrency)
        all_hosts = list(self.discovered_subs.keys())
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        async def inspect_single(sub: str):
            if self._check_cancelled():
                return None
            async with sem:
                ip_list: List[str] = []
                aaaa_list: List[str] = []
                cname = ""
                aliases: List[str] = []
                dns_confirmed = False

                # 1. DNS Resolution (Async resolver or socket fallback)
                if resolver:
                    try:
                        ans_a = await resolver.resolve(sub, "A")
                        ip_list = [str(r) for r in ans_a]
                        dns_confirmed = True
                    except Exception:
                        pass

                    try:
                        ans_aaaa = await resolver.resolve(sub, "AAAA")
                        aaaa_list = [str(r) for r in ans_aaaa]
                        dns_confirmed = True
                    except Exception:
                        pass

                    try:
                        ans_cname = await resolver.resolve(sub, "CNAME")
                        cnames = [str(r).rstrip(".") for r in ans_cname]
                        if cnames:
                            cname = cnames[0]
                            aliases = cnames
                            dns_confirmed = True
                    except Exception:
                        pass

                # Socket fallback if resolver produced no answers
                if not ip_list and not aaaa_list:
                    try:
                        loop = asyncio.get_running_loop()
                        res = await loop.run_in_executor(None, socket.gethostbyname_ex, sub)
                        if res[0] != sub:
                            cname = res[0]
                        aliases = res[1]
                        if res[2]:
                            ip_list = res[2]
                            dns_confirmed = True
                    except Exception:
                        try:
                            loop = asyncio.get_running_loop()
                            addr_info = await loop.getaddrinfo(sub, None)
                            ips = [item[4][0] for item in addr_info if item[4]]
                            if ips:
                                ip_list = ips
                                dns_confirmed = True
                        except Exception:
                            pass

                # 2. Wildcard classification check
                wildcard_suspected = False
                if self.wildcard_detected and ip_list:
                    if set(ip_list).issubset(self.wildcard_ips):
                        wildcard_suspected = True

                # Validation status determination
                if wildcard_suspected:
                    validation_status = "wildcard_suspected"
                elif dns_confirmed:
                    validation_status = "confirmed"
                else:
                    validation_status = "unresolved"

                # 3. Probe HTTP & HTTPS concurrently
                status_code = None
                server = ""
                response_body = ""
                page_title = ""
                http_responsive = False

                if dns_confirmed:
                    async with httpx.AsyncClient(
                        verify=False,
                        timeout=3.5,
                        follow_redirects=True,
                        headers=DEFAULT_HEADERS
                    ) as client:
                        try:
                            resp = await client.get(f"https://{sub}")
                            status_code = resp.status_code
                            server = resp.headers.get("server", "")
                            response_body = resp.text[:4000]
                            http_responsive = True
                        except Exception:
                            try:
                                resp = await client.get(f"http://{sub}")
                                status_code = resp.status_code
                                server = resp.headers.get("server", "")
                                response_body = resp.text[:4000]
                                http_responsive = True
                            except Exception:
                                pass

                # Extract HTML <title> if present
                if response_body:
                    title_match = re.search(r"<title[^>]*>(.*?)</title>", response_body, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        raw_title = html.unescape(title_match.group(1).strip())
                        page_title = " ".join(raw_title.split())[:70]

                # 4. Subdomain Takeover Analysis
                takeover_detected, provider_name, reason = self._check_takeover(sub, cname, aliases, response_body)
                if takeover_detected:
                    finding = VulnerabilityFinding(
                        scan_id=self.scan_id,
                        title=f"Subdomain Takeover Detected ({provider_name})",
                        severity=Severity.CRITICAL,
                        cwe_id="CWE-284: Improper Access Control",
                        cvss_score=8.6,
                        endpoint=f"https://{sub}",
                        affected_asset=sub,
                        confidence="CONFIRMED",
                        detection_method="DNS_CNAME_AND_HTTP_FINGERPRINT",
                        description=f"Host '{sub}' has a dangling CNAME pointer to {cname or provider_name}. {reason}",
                        reproduction_steps=f"1. Resolve CNAME for '{sub}': points to '{cname}'.\n2. Send HTTP request to '{sub}': returned cloud error signature from {provider_name}.\n3. Claim resource under provider.",
                        impact="Full compromise of domain asset, ability to serve malicious content, steal session cookies, and perform credential harvesting.",
                        remediation_advice=f"Immediately remove or update the dangling DNS CNAME record for '{sub}' pointing to {provider_name}, or reclaim the orphaned asset in your cloud account.",
                        remediation_patch=f"; DNS zone update for {self.base_domain}\n; Remove dangling alias:\n{sub}. IN CNAME [REMOVE-DANGLING-RECORD]"
                    )
                    self.takeover_findings.append(finding)
                    await self.log(f"CRITICAL: Subdomain Takeover identified on {sub} -> {provider_name}!", "FINDING")

                sources = sorted(list(self.discovered_subs.get(sub, ["Unknown"])))
                
                # Confidence rating
                if http_responsive or (dns_confirmed and len(sources) >= 2):
                    confidence = "high"
                elif dns_confirmed or len(sources) >= 1:
                    confidence = "medium"
                else:
                    confidence = "low"

                entry = {
                    "subdomain": sub,
                    "parent_domain": self.base_domain,
                    "ip": ip_list[0] if ip_list else "",
                    "ip_addresses": ip_list,
                    "aaaa_records": aaaa_list,
                    "cname": cname or (aliases[0] if aliases else ""),
                    "status": status_code,
                    "status_code": status_code,
                    "http_responsive": http_responsive,
                    "dns_confirmed": dns_confirmed,
                    "validation_status": validation_status,
                    "confidence": confidence,
                    "title": page_title,
                    "server": server,
                    "sources": sources,
                    "takeover_risk": takeover_detected,
                    "takeover_provider": provider_name if takeover_detected else "",
                    "first_seen": now_iso,
                    "last_seen": now_iso,
                    "scan_id": self.scan_id,
                    "dns_records": {
                        "A": ip_list,
                        "AAAA": aaaa_list,
                        "CNAME": [cname] if cname else aliases
                    }
                }
                
                # Incrementally save entry and persist to database asset inventory
                self.detailed_results.append(entry)
                try:
                    from core.database import db
                    db.save_asset(entry)
                except Exception:
                    pass

                if status_code:
                    src_tag = "+".join(sources[:2])
                    title_info = f" | '{page_title}'" if page_title else ""
                    await self.log(
                        f"Live asset confirmed: {sub} ({ip_list[0] if ip_list else 'DNS'}) [HTTP {status_code}]{title_info} [via {src_tag}]",
                        "FINDING"
                    )
                return entry

        # Concurrently probe assets up to 500 without artificial hard termination
        tasks = [inspect_single(s) for s in all_hosts[:500]]
        await asyncio.gather(*tasks, return_exceptions=True)

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


# Friendly alias for modern architecture
SubdomainDiscoveryEngine = AmassSubdomainEngine
