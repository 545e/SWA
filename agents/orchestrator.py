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
            # Phase 1: Target Validation & Initialization
            await queue_manager.emit_progress(self.scan_id, 5, "Initializing & Target Validation")
            await self.log(f"SWA AI autonomous red team initialized against target: {self.job.target_url} [Profile: {self.job.profile.value}]", "INFO")
            await asyncio.sleep(0.5)

            # Phase 2: Autonomous Reconnaissance
            await queue_manager.emit_progress(self.scan_id, 15, "Phase 1/5: Autonomous Reconnaissance & OSINT")
            recon_agent = ReconAgent(self.scan_id, self.job.target_url, timeout=self.config.timeout_sec)
            recon_data = await recon_agent.run()
            db.update_scan_recon(self.scan_id, recon_data, 0)
            self.job.recon_data = recon_data

            if self.job.profile == ScanProfile.RECON_ONLY:
                await self._finalize_scan(start_time, recon_data)
                return

            # Phase 3: Attack Surface & API Discovery
            await queue_manager.emit_progress(self.scan_id, 40, "Phase 2/5: Attack Surface & API Route Discovery")
            surface_agent = AttackSurfaceAgent(
                self.scan_id,
                recon_agent.base_url,
                max_depth=self.config.max_depth,
                concurrency=self.config.concurrency
            )
            endpoints = await surface_agent.run()
            db.update_scan_recon(self.scan_id, recon_data, len(endpoints))

            # Phase 4: Vulnerability Hunting
            await queue_manager.emit_progress(self.scan_id, 65, "Phase 3/5: Autonomous Vulnerability Hunting")
            vuln_agent = VulnHunterAgent(self.scan_id, endpoints, concurrency=self.config.concurrency)
            candidate_findings = await vuln_agent.run()

            # Phase 5: Exploit Validation & PoC Generation
            await queue_manager.emit_progress(self.scan_id, 85, "Phase 4/5: Active Exploit & PoC Validation")
            validator_agent = ExploitValidatorAgent(self.scan_id, self.llm)
            validated_findings = await validator_agent.run(candidate_findings)

            # Phase 6: Tailored Remediation Patches
            await queue_manager.emit_progress(self.scan_id, 95, "Phase 5/5: Synthesizing Code Patches & Reports")
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
