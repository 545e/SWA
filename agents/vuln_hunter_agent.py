"""
SWA AI Vulnerability Hunter Agent
Modular OWASP Top 10 vulnerability scanner orchestrating extensible plugins:
- A01: Broken Access Control (CORS, LFI, Admin Routes)
- A02: Cryptographic Failures (Cleartext transmission, Insecure Cookies)
- A03: Injection (SQL Injection, Reflected XSS)
- A04: Insecure Design (Missing Rate Limits)
- A05: Security Misconfiguration (Missing Headers, Stack Traces, HTTP TRACE)
- A06: Vulnerable and Outdated Components (Server Banners)
- A07: Authentication Failures (Missing CSRF on Forms, Tokens in URL)
- A08: Software and Data Integrity Failures (SRI)
- A09: Logging and Exception Failures (HTTP 500 Dumps)
- A10: Server-Side Request Forgery (SSRF)
"""

import asyncio
from typing import List, Dict, Any, Optional

from core.models import DiscoveredEndpoint, VulnerabilityFinding, LogEvent
from core.queue_manager import queue_manager
from plugins.plugin_manager import plugin_manager

class VulnHunterAgent:
    def __init__(self, scan_id: str, endpoints: List[DiscoveredEndpoint], concurrency: int = 5):
        self.scan_id = scan_id
        self.endpoints = endpoints
        self.concurrency = concurrency

    async def log(self, message: str, level: str = "INFO"):
        event = LogEvent(scan_id=self.scan_id, agent="VulnHunterAgent", level=level, message=message)
        await queue_manager.emit_log(event)

    async def run(self, recon_data: Any = None) -> List[VulnerabilityFinding]:
        await self.log(f"Initiating OWASP Top 10 security audit across {len(self.endpoints)} endpoints...", "INFO")
        
        # Execute all registered and active security plugins
        findings = await plugin_manager.execute_all(
            scan_id=self.scan_id,
            endpoints=self.endpoints,
            recon_data=recon_data,
            log_callback=self.log
        )

        # Broadcast each discovered finding
        for f in findings:
            await queue_manager.emit_finding(f)

        await self.log(f"OWASP Top 10 hunting completed. Identified {len(findings)} confirmed security issues.", "SUCCESS")
        return findings
