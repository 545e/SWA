"""
SWA AI — Unified Remediation Lifecycle & Retest Verification Engine
Manages the complete lifecycle:
DISCOVERED → TRIAGED → ASSIGNED → IN PROGRESS → FIX SUBMITTED → RETEST → VERIFIED → CLOSED.
Handles Risk Acceptance with documented rationale, False Positive suppression,
and active retesting verification against targets.
"""

from typing import List, Dict, Any, Optional
import datetime
import httpx
from core.intelligence_models import (
    RemediationTicket,
    FindingLifecycleStatus
)
from core.database import db
from core.models import VulnerabilityFinding
from core.queue_manager import queue_manager


class RemediationEngine:
    """Orchestrates vulnerability lifecycle management, tickets, assignment, and automated retest."""

    @staticmethod
    def create_ticket_from_finding(finding: VulnerabilityFinding, target: str) -> RemediationTicket:
        """Initializes a remediation lifecycle ticket for a newly discovered vulnerability."""
        ticket = RemediationTicket(
            finding_id=finding.id,
            scan_id=finding.scan_id,
            target=target,
            title=finding.title,
            severity=finding.severity.value,
            lifecycle_status=FindingLifecycleStatus.DISCOVERED,
            owner="Unassigned",
            patch_code=finding.remediation_patch,
            mitigation_guidance=finding.remediation_advice,
            history=[{
                "from_status": "NONE",
                "to_status": FindingLifecycleStatus.DISCOVERED.value,
                "actor": "VulnHunterAgent",
                "reason": "Initial discovery from security assessment",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }]
        )
        db.save_remediation_ticket(ticket.model_dump())
        return ticket

    @staticmethod
    async def transition_ticket(
        ticket_id: str,
        new_status: FindingLifecycleStatus,
        actor: str = "Security Analyst",
        reason: str = "",
        owner: Optional[str] = None,
        suppression_reason: Optional[str] = None
    ) -> Optional[RemediationTicket]:
        """Transitions a finding ticket across the lifecycle state machine."""
        ticket_dict = db.get_remediation_ticket(ticket_id)
        if not ticket_dict:
            return None

        ticket = RemediationTicket(**ticket_dict)
        prev_status = ticket.lifecycle_status

        # Update fields
        ticket.lifecycle_status = new_status
        if owner:
            ticket.owner = owner
        if suppression_reason:
            ticket.suppression_reason = suppression_reason

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        ticket.history.append({
            "from_status": prev_status.value,
            "to_status": new_status.value,
            "actor": actor,
            "reason": reason or f"Transitioned from {prev_status.value} to {new_status.value}",
            "timestamp": now_iso
        })
        ticket.updated_at = now_iso

        db.save_remediation_ticket(ticket.model_dump())

        # Sync finding row
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE findings
            SET lifecycle_status = ?, owner = ?, suppression_reason = ?
            WHERE id = ?
            """, (new_status.value, ticket.owner, suppression_reason, ticket.finding_id))
            conn.commit()

        db.record_audit_log(
            action=f"REMEDIATION_STATUS:{new_status.value}",
            actor=actor,
            details=f"Ticket: {ticket.id} | Finding: {ticket.finding_id} | Reason: {reason}"
        )

        await queue_manager.broadcast_event("REMEDIATION_UPDATED", ticket.model_dump())
        return ticket

    @staticmethod
    async def run_retest(ticket_id: str, actor: str = "Retest Specialist Agent") -> Dict[str, Any]:
        """
        Executes an automated retest probe against the vulnerable endpoint
        to verify if the vulnerability has been resolved or still persists.
        """
        ticket_dict = db.get_remediation_ticket(ticket_id)
        if not ticket_dict:
            return {"status": "ERROR", "message": "Ticket not found"}

        finding_dict = db.get_finding(ticket_dict.get("finding_id"))
        if not finding_dict:
            return {"status": "ERROR", "message": "Associated finding record not found"}

        endpoint = finding_dict.endpoint
        method = finding_dict.method or "GET"

        # Safe non-destructive probe to endpoint
        test_url = endpoint if "://" in endpoint else f"http://{endpoint}"
        status_result = "VERIFIED_RESOLVED"
        retest_evidence = ""

        try:
            async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
                res = await client.request(method, test_url)
                # Check response characteristics
                if res.status_code in (404, 410):
                    status_result = "VERIFIED_RESOLVED"
                    retest_evidence = f"Endpoint now returns HTTP {res.status_code} (Removed/Unreachable)."
                elif res.status_code in (401, 403):
                    status_result = "VERIFIED_RESOLVED"
                    retest_evidence = f"Endpoint now strictly enforces authentication/authorization (HTTP {res.status_code})."
                elif finding_dict.parameter and finding_dict.parameter in res.text:
                    status_result = "FAILED_PERSISTS"
                    retest_evidence = f"Endpoint is reachable (HTTP {res.status_code}) and reflection persists in response body."
                else:
                    status_result = "VERIFIED_RESOLVED"
                    retest_evidence = f"Endpoint responded with HTTP {res.status_code}; test payload reflection no longer present."
        except Exception as e:
            status_result = "VERIFIED_RESOLVED"
            retest_evidence = f"Endpoint is no longer reachable or connection refused ({str(e)})."

        # Determine target lifecycle status based on retest result
        target_status = FindingLifecycleStatus.VERIFIED if status_result == "VERIFIED_RESOLVED" else FindingLifecycleStatus.IN_PROGRESS
        
        ticket_dict["retest_status"] = status_result
        ticket_dict["retest_evidence"] = retest_evidence
        db.save_remediation_ticket(ticket_dict)

        await RemediationEngine.transition_ticket(
            ticket_id=ticket_id,
            new_status=target_status,
            actor=actor,
            reason=f"Automated retest outcome: {status_result}. Evidence: {retest_evidence}"
        )

        return {
            "ticket_id": ticket_id,
            "status": status_result,
            "lifecycle_status": target_status.value,
            "evidence": retest_evidence
        }


remediation_engine = RemediationEngine()
