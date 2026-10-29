"""
SWA AI Master Multi-Agent Orchestrator
Coordinates multi-phase security assessments, drives background execution,
and synchronizes live state with the database and real-time event bus.
"""

import asyncio
import time
import datetime
from typing import Optional

from core.models import ScanJob, ScanStatus, ScanProfile, LogEvent
from core.database import db
from core.queue_manager import queue_manager
from core.llm_client import SWALLMClient

from agents.recon_agent import ReconAgent
from agents.attack_surface_agent import AttackSurfaceAgent
from agents.fuzzer_agent import FuzzerAgent
from agents.vuln_hunter_agent import VulnHunterAgent
from agents.exploit_validator_agent import ExploitValidatorAgent
from agents.remediation_agent import RemediationAgent

class SWAOrchestrator:
    def __init__(self, job: ScanJob):
        self.job = job
        self.scan_id = job.id
        self.config = job.config
        
        provider = self.config.ai_provider if self.config.ai_provider != "auto" else db.get_setting("ai_provider", "auto")
        model = self.config.ai_model or db.get_setting("ai_model", "minimax/minimax-m3.1-flash:free")
        api_key = self.config.ai_api_key or db.get_setting("ai_api_key")
        base_url = self.config.ai_base_url or db.get_setting("ai_base_url")

        self.llm = SWALLMClient(
            provider=provider,
            model=model,
            api_key=api_key,
            base_url=base_url
        )

    async def log(self, message: str, level: str = "INFO", agent: str = "Orchestrator"):
        event = LogEvent(scan_id=self.scan_id, agent=agent, level=level, message=message)
        await queue_manager.emit_log(event)

    async def execute(self):
        start_time = time.time()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        db.update_scan_status(self.scan_id, ScanStatus.RUNNING, started_at=now_iso)
        await queue_manager.broadcast_event("SCAN_STARTED", {"scan_id": self.scan_id, "target": self.job.target_url})

        try:
            # Phase 1: Target Scope Validation & SSRF Enforcement
            await queue_manager.emit_progress(self.scan_id, 5, "Target Scope & Authorization Verification")
            from core.scope_policy import scope_policy
            is_lab = getattr(self.config, "lab_mode", False) or self.job.profile == ScanProfile.LAB_ASSESSMENT
            scope_res = scope_policy.validate_target(
                self.job.target_url,
                explicit_lab_authorization=is_lab
            )
            if not scope_res.is_allowed:
                refusal_msg = f"Scope Policy Refusal: {scope_res.reason}"
                await self.log(refusal_msg, "ERROR")
                db.update_scan_status(self.scan_id, ScanStatus.FAILED)
                db.update_scan_progress(self.scan_id, 100, "Refused - Out of Scope", error=refusal_msg)
                return

            await self.log(f"Scope Verified: {scope_res.reason}", "SUCCESS")

            # Check and log tool inventory status
            from core.scanner_integrations import ScannerIntegrations
            inventory = ScannerIntegrations.get_tool_inventory()
            active_tools = [name for name, meta in inventory.items() if meta["installed"]]
            await self.log(f"Active Scanner Engines: {', '.join(active_tools)}", "INFO")

            # Phase 2: Autonomous Reconnaissance
            await queue_manager.emit_progress(self.scan_id, 15, "Phase 1/5: Autonomous Reconnaissance & OSINT")
            recon_agent = ReconAgent(self.scan_id, self.job.target_url, timeout=self.config.timeout_sec)
            recon_data = await recon_agent.run()
            db.update_scan_recon(self.scan_id, recon_data, 0)
            self.job.recon_data = recon_data

            # Harvest any Subdomain Takeover findings discovered by Amass engine
            takeover_findings = getattr(recon_agent, "takeover_findings", [])
            for tf in takeover_findings:
                db.save_finding(tf)
                await queue_manager.emit_finding(tf)

            if self.job.profile in [ScanProfile.RECON_ONLY, ScanProfile.PASSIVE_RECON]:
                await self._finalize_scan(start_time, recon_data)
                return

            # Phase 3: Attack Surface & API Discovery
            await queue_manager.emit_progress(self.scan_id, 35, "Phase 2/6: Attack Surface & API Route Discovery")
            surface_agent = AttackSurfaceAgent(
                self.scan_id,
                recon_agent.base_url,
                max_depth=self.config.max_depth,
                concurrency=self.config.concurrency
            )
            endpoints = await surface_agent.run()

            # Phase 4: High-Accuracy Path & Parameter Fuzzing
            if self.config.enable_fuzzing:
                await queue_manager.emit_progress(self.scan_id, 55, "Phase 3/6: Anomaly-Filtered Path & Parameter Fuzzing")
                fuzzer = FuzzerAgent(
                    self.scan_id,
                    recon_agent.base_url,
                    concurrency=self.config.concurrency,
                    timeout=self.config.timeout_sec
                )
                fuzz_results = await fuzzer.run()
                recon_data.fuzzing_results = fuzz_results.get("paths", [])
                recon_data.fuzzed_parameters = fuzz_results.get("parameters", [])

                # Integrate discovered fuzzed routes into endpoint testing
                from core.models import DiscoveredEndpoint
                for p in fuzz_results.get("paths", []):
                    endpoints.append(DiscoveredEndpoint(
                        url=p["url"],
                        method="GET",
                        status_code=p.get("status"),
                        content_type=p.get("content_type"),
                        title=p.get("title"),
                        is_api="api" in p.get("path", "").lower()
                    ))

            # Incorporate live discovered subdomains into the assessment scope
            if recon_data and recon_data.subdomains:
                from core.models import DiscoveredEndpoint
                proto = "https" if recon_agent.base_url.startswith("https") else "http"
                for sub in recon_data.subdomains[:6]:
                    sub_name = sub.get("subdomain")
                    sub_status = sub.get("status") or sub.get("status_code")
                    if sub_name and sub_status in [200, 301, 302, 307, 308, 401, 403]:
                        sub_url = f"{proto}://{sub_name}"
                        if not any(ep.url.startswith(sub_url) for ep in endpoints):
                            endpoints.append(DiscoveredEndpoint(
                                url=sub_url,
                                method="GET",
                                status_code=sub_status,
                                content_type="text/html",
                                title=f"Discovered Subdomain: {sub_name}",
                                is_api="api" in sub_name.lower() or "billing" in sub_name.lower() or "admin" in sub_name.lower()
                            ))

            db.update_scan_recon(self.scan_id, recon_data, len(endpoints))

            # Ensure at least root endpoint is in target list
            if not endpoints:
                from core.models import DiscoveredEndpoint
                endpoints.append(DiscoveredEndpoint(
                    url=recon_agent.base_url,
                    method="GET",
                    status_code=200,
                    content_type="text/html",
                    title="Root Target"
                ))

            # Phase 5: Vulnerability Hunting with Modular OWASP Plugins & Scanner Integrations
            await queue_manager.emit_progress(self.scan_id, 70, "Phase 4/6: Autonomous OWASP Top 10 Hunting")
            vuln_agent = VulnHunterAgent(self.scan_id, endpoints, concurrency=self.config.concurrency)
            candidate_findings = await vuln_agent.run(recon_data=recon_data)
            if takeover_findings:
                candidate_findings.extend(takeover_findings)

            # Check for Nuclei Safe Scan if binary is present
            from core.scanner_integrations import ScannerIntegrations
            inventory = ScannerIntegrations.get_tool_inventory()
            if inventory.get("nuclei", {}).get("installed"):
                await self.log("Invoking Nuclei safe detection templates...", "INFO")
                nuclei_findings, nuclei_meta = await ScannerIntegrations.run_nuclei_safe(recon_agent.base_url, self.scan_id)
                candidate_findings.extend(nuclei_findings)
                await self.log(f"Nuclei completed with {len(nuclei_findings)} findings.", "SUCCESS")

            # Check for Optional SQLmap Lab Detection (Disabled by default, non-destructive only)
            if getattr(self.config, "enable_sqlmap_lab", False) and getattr(self.config, "lab_mode", False):
                await self.log("Authorized Lab Mode: Running non-destructive SQLmap detection...", "INFO")
                target_test_url = endpoints[0].url if endpoints else recon_agent.base_url
                sqlmap_findings, sqlmap_meta = await ScannerIntegrations.run_sqlmap_safe_detection(
                    target_test_url,
                    self.scan_id,
                    is_lab_mode_authorized=True
                )
                candidate_findings.extend(sqlmap_findings)

            # Phase 6: Exploit Validation & PoC Generation
            await queue_manager.emit_progress(self.scan_id, 85, "Phase 5/6: Active Exploit & PoC Validation")
            validator_agent = ExploitValidatorAgent(self.scan_id, self.llm)
            validated_findings = await validator_agent.run(candidate_findings)

            # Phase 7: Tailored Remediation Patches
            await queue_manager.emit_progress(self.scan_id, 95, "Phase 6/6: Synthesizing Code Patches & Reports")
            remediation_agent = RemediationAgent(self.scan_id, self.llm, recon_data)
            final_findings = await remediation_agent.run(validated_findings)

            # Finalize
            await self._finalize_scan(start_time, recon_data)

        except asyncio.CancelledError:
            await self.log("Scan was cancelled by user.", "WARN")
            db.update_scan_status(self.scan_id, ScanStatus.CANCELLED)
        except Exception as e:
            await self.log(f"Scan encountered an unexpected error: {str(e)}", "ERROR")
            db.update_scan_status(self.scan_id, ScanStatus.FAILED)
            db.update_scan_progress(self.scan_id, 100, "Failed", error=str(e))
        finally:
            if self.scan_id in queue_manager.active_tasks:
                del queue_manager.active_tasks[self.scan_id]

    async def _finalize_scan(self, start_time: float, recon_data):
        duration = round(time.time() - start_time, 2)
        completed_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        db.update_scan_status(self.scan_id, ScanStatus.COMPLETED, completed_at=completed_iso, duration_seconds=duration)
        db.update_scan_progress(self.scan_id, 100, "Completed")
        db.update_scan_counts(self.scan_id)
        
        updated_scan = db.get_scan(self.scan_id)
        findings_count = updated_scan.findings_count if updated_scan else 0
        await self.log(f"Assessment completed in {duration}s. Found {findings_count} verified vulnerabilities.", "SUCCESS")
        await queue_manager.broadcast_event("SCAN_COMPLETED", {
            "scan_id": self.scan_id,
            "duration_seconds": duration,
            "findings_count": findings_count
        })
