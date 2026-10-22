"""
SWA AI Remediation Agent
Generates developer-first code patches, configuration snippets, and compliance mitigations
for validated vulnerabilities based on detected technology stack.
"""

from typing import List
from core.models import VulnerabilityFinding, ReconResult, LogEvent
from core.queue_manager import queue_manager
from core.llm_client import SWALLMClient

class RemediationAgent:
    def __init__(self, scan_id: str, llm_client: SWALLMClient, recon: ReconResult):
        self.scan_id = scan_id
        self.llm = llm_client
        self.recon = recon

    async def log(self, message: str, level: str = "INFO"):
        event = LogEvent(scan_id=self.scan_id, agent="RemediationAgent", level=level, message=message)
        await queue_manager.emit_log(event)

    async def run(self, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        await self.log("Generating tailored code patches and defensive remediations...", "INFO")
        tech_names = [t.get("technology", "") for t in self.recon.technologies] if self.recon and self.recon.technologies else []

        for finding in findings:
            if not finding.remediation_patch or not finding.remediation_advice:
                res = await self.llm.generate_remediation(
                    finding_title=finding.title,
                    endpoint=finding.endpoint,
                    tech_stack=tech_names
                )
                if not finding.remediation_advice:
                    finding.remediation_advice = res.get("advice", "")
                if not finding.remediation_patch:
                    finding.remediation_patch = res.get("patch", "")

        await self.log(f"Remediation patches synthesized for {len(findings)} findings.", "SUCCESS")
        return findings
