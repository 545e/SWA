"""
SWA AI Attack Surface & API Discovery Agent
Crawls target web application, extracts HTML forms, links, script endpoints,
and discovers REST/GraphQL/OpenAPI endpoints for vulnerability probing.
"""

import asyncio
import re
from urllib.parse import urljoin, urlparse, parse_qs
import httpx
from bs4 import BeautifulSoup
from typing import List, Set, Dict, Any

from core.models import DiscoveredEndpoint, LogEvent
from core.queue_manager import queue_manager

COMMON_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/graphql", "/auth/login",
    "/api/users", "/api/search", "/api/data", "/api/items",
    "/api/config", "/api/upload", "/api/status", "/v1/auth"
]

class AttackSurfaceAgent:
    def __init__(self, scan_id: str, base_url: str, max_depth: int = 2, concurrency: int = 5):
        self.scan_id = scan_id
        self.base_url = base_url
        self.max_depth = max_depth
        self.concurrency = concurrency
        self.parsed_base = urlparse(base_url)
        self.visited_urls: Set[str] = set()
        self.endpoints: Dict[str, DiscoveredEndpoint] = {}

    async def log(self, message: str, level: str = "INFO"):
        event = LogEvent(scan_id=self.scan_id, agent="AttackSurfaceAgent", level=level, message=message)
        await queue_manager.emit_log(event)

    async def run(self) -> List[DiscoveredEndpoint]:
        await self.log(f"Mapping attack surface and API routes starting from {self.base_url}...", "INFO")
        
        # 1. Crawl seed URL
        queue = [(self.base_url, 0)]
        
        async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=True) as client:
            while queue and len(self.visited_urls) < 40:
                current_url, depth = queue.pop(0)
                if current_url in self.visited_urls:
                    continue
                self.visited_urls.add(current_url)

                try:
                    resp = await client.get(current_url)
                    content_type = resp.headers.get("content-type", "")
                    title = ""
                    params = list(parse_qs(urlparse(current_url).query).keys())

                    if "text/html" in content_type:
                        soup = BeautifulSoup(resp.text, "html.parser")
                        title_el = soup.find("title")
                        title = title_el.text.strip() if title_el else ""

                        # Register current page
                        self.endpoints[current_url] = DiscoveredEndpoint(
                            url=current_url,
                            method="GET",
                            parameters=params,
                            status_code=resp.status_code,
                            content_type=content_type,
                            title=title,
                            is_api=False
                        )

                        # Parse HTML Forms
                        forms = soup.find_all("form")
                        for f in forms:
                            action = f.get("action") or current_url
                            form_url = urljoin(current_url, action)
                            method = (f.get("method") or "GET").upper()
                            form_inputs = [inp.get("name") for inp in f.find_all(["input", "textarea", "select"]) if inp.get("name")]
                            
                            self.endpoints[f"{method}:{form_url}"] = DiscoveredEndpoint(
                                url=form_url,
                                method=method,
                                parameters=form_inputs,
                                status_code=None,
                                content_type="form-submission",
                                title=f"Form on {title or current_url}",
                                is_api=False
                            )

                        # Extract Next Links if depth permits
                        if depth < self.max_depth:
                            for a in soup.find_all("a", href=True):
                                href = a["href"].split("#")[0].strip()
                                if not href or href.startswith(("javascript:", "mailto:", "tel:")):
                                    continue
                                full_link = urljoin(current_url, href)
                                link_parsed = urlparse(full_link)
                                if link_parsed.netloc == self.parsed_base.netloc:
                                    if full_link not in self.visited_urls:
                                        queue.append((full_link, depth + 1))

                    elif "application/json" in content_type:
                        self.endpoints[current_url] = DiscoveredEndpoint(
                            url=current_url,
                            method="GET",
                            parameters=params,
                            status_code=resp.status_code,
                            content_type=content_type,
                            title="JSON API Endpoint",
                            is_api=True
                        )

                except Exception:
                    continue

            # 2. Probe Common API & REST Routes
            await self.log("Probing REST and GraphQL API routes...", "INFO")
            for api_path in COMMON_API_PATHS:
                test_url = urljoin(self.base_url, api_path)
                try:
                    api_resp = await client.get(test_url)
                    if api_resp.status_code in [200, 201, 400, 401, 403, 405]:
                        self.endpoints[f"API:{test_url}"] = DiscoveredEndpoint(
                            url=test_url,
                            method="GET",
                            status_code=api_resp.status_code,
                            content_type=api_resp.headers.get("content-type", ""),
                            title=f"API Route (Status {api_resp.status_code})",
                            is_api=True
                        )
                except Exception:
                    continue

        endpoint_list = list(self.endpoints.values())
        await self.log(f"Attack surface mapping complete. Discovered {len(endpoint_list)} active endpoints and input vectors.", "SUCCESS")
        return endpoint_list
