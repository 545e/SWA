"""
SWA AI Dependency Confusion & Supply-Chain Security Agent
Autonomous detection of unclaimed internal / private npm packages
discovered in JavaScript bundles, source-maps, and exposed lockfiles.
Prevents remote code execution (RCE) via public package hijacking.
"""

import re
import asyncio
import httpx
from typing import List, Dict, Any, Set
from urllib.parse import urlparse

from core.models import VulnerabilityFinding, Severity, LogEvent
from core.queue_manager import queue_manager
from core.database import db

# Common public generic packages to ignore (reduces noise)
POPULAR_PUBLIC_PACKAGES = {
    "react", "react-dom", "vue", "angular", "lodash", "axios", "jquery",
    "moment", "redux", "express", "core-js", "tslib", "next", "nuxt",
    "webpack", "babel", "rxjs", "bootstrap", "tailwindcss", "chalk",
    "debug", "dotenv", "uuid", "classnames", "prop-types", "dayjs"
}

class DependencyConfusionAgent:
    def __init__(self, scan_id: str, js_urls: List[str], base_url: str):
        self.scan_id = scan_id
        self.js_urls = js_urls[:20]  # Analyze up to 20 representative JS bundles
        self.base_url = base_url
        self.discovered_packages: Set[str] = set()
        self.findings: List[VulnerabilityFinding] = []

    async def log(self, message: str, level: str = "INFO"):
        event = LogEvent(scan_id=self.scan_id, agent="DependencyConfusionAgent", level=level, message=message)
        await queue_manager.emit_log(event)

    def extract_package_candidates(self, js_code: str) -> Set[str]:
        """Extract npm package names from webpack/vite bundles, import statements, and source maps."""
        candidates = set()

        # 1. Scoped packages (@org/pkg-name)
        scoped_matches = re.findall(r"['\"](@[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\.\-]+)['\"]", js_code)
        for pkg in scoped_matches:
            candidates.add(pkg)

        # 2. Node module path references in source maps / webpack manifests
        node_module_matches = re.findall(r"node_modules/([@a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\.\-]+)?)/", js_code)
        for pkg in node_module_matches:
            if not pkg.startswith("."):
                candidates.add(pkg)

        # 3. Require / dynamic imports
        require_matches = re.findall(r"(?:require|import)\s*\(\s*['\"]([@a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\.\-]+)?)['\"]\s*\)", js_code)
        for pkg in require_matches:
            if not pkg.startswith(".") and not pkg.startswith("/"):
                candidates.add(pkg)

        # Filter out common standard public libraries
        return {p for p in candidates if p not in POPULAR_PUBLIC_PACKAGES and len(p) > 2}

    async def check_npm_registry(self, client: httpx.AsyncClient, package_name: str) -> bool:
        """
        Queries the official npm registry.
        Returns True if package is UNCLAIMED (HTTP 404), meaning it can be hijacked!
        """
        registry_url = f"https://registry.npmjs.org/{package_name}"
        try:
            resp = await client.get(registry_url, timeout=5.0)
            if resp.status_code == 404:
                return True  # Unclaimed! High risk of dependency confusion
            return False  # Already registered / claimed
        except Exception:
            return False

    async def run(self) -> List[VulnerabilityFinding]:
        await self.log("Starting autonomous Dependency Confusion & Supply-Chain audit across client assets...", "INFO")
        
        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            # 1. Download and extract package candidates from JS files
            for js_url in self.js_urls:
                try:
                    resp = await client.get(js_url)
                    if resp.status_code == 200:
                        pkgs = self.extract_package_candidates(resp.text)
                        self.discovered_packages.update(pkgs)
                except Exception:
                    continue

            if not self.discovered_packages:
                await self.log("No internal or third-party npm package dependencies discovered in client bundles.", "SUCCESS")
                return []

            await self.log(f"Discovered {len(self.discovered_packages)} package candidates. Verifying public registry ownership...", "INFO")

            # 2. Check each candidate against the public npm registry
            for pkg in self.discovered_packages:
                is_unclaimed = await self.check_npm_registry(client, pkg)
                if is_unclaimed:
                    # An internal package is NOT claimed on npmjs.org!
                    finding = VulnerabilityFinding(
                        scan_id=self.scan_id,
                        title=f"Dependency Confusion Vulnerability (Unclaimed Package: {pkg})",
                        severity=Severity.CRITICAL,
                        cvss_score=9.3,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        cwe_id="CWE-427: Uncontrolled Search Path Element",
                        owasp_category="A06:2021-Vulnerable and Outdated Components",
                        endpoint=f"https://registry.npmjs.org/{pkg}",
                        method="GET",
                        description=(
                            f"Internal dependency '{pkg}' was discovered in client-side bundles but is UNCLAIMED on the public npm registry. "
                            f"An external adversary can register '{pkg}' on npmjs.org with a high semantic version number (e.g. 99.0.0), "
                            "causing developer workstations and CI/CD pipelines to automatically install and execute arbitrary attacker code."
                        ),
                        poc_curl=f"curl -s 'https://registry.npmjs.org/{pkg}'",
                        poc_explanation=(
                            f"HTTP GET https://registry.npmjs.org/{pkg} returned 404 Not Found. "
                            "This verifies the package name is currently available for public registration."
                        ),
                        request_evidence=f"GET /{pkg} HTTP/1.1\\nHost: registry.npmjs.org",
                        response_evidence='{"error":"Not found"}',
                        remediation_advice=(
                            f"1. Immediately register a placeholder package for '{pkg}' on the public npm registry.\\n"
                            "2. If using a private npm organization scope, enforce scope mapping in .npmrc (`@org:registry=https://private-npm.corp`).\\n"
                            "3. Configure your internal package proxy (Verdaccio / Artifactory / Nexus) to disallow public uplink fallback for internal scopes."
                        ),
                        remediation_patch=f"# .npmrc configuration:\\n@your-org:registry=https://internal-npm.yourdomain.com/\\nalways-auth=true"
                    )
                    db.save_finding(finding)
                    await queue_manager.emit_finding(finding)
                    self.findings.append(finding)
                    await self.log(f"CRITICAL SUPPLY-CHAIN RISK: Unclaimed package '{pkg}' discovered!", "FINDING")

        await self.log(f"Supply-chain audit complete. Found {len(self.findings)} unclaimed package vulnerabilities.", "SUCCESS")
        return self.findings
