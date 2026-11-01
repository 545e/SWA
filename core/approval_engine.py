"""
SWA AI — Human-in-the-Loop Approval & Governance Engine
Enforces mandatory human authorization gates for sensitive offensive operations,
scope changes, aggressive scanning, and high-impact remediation.
"""

from typing import List, Dict, Any, Optional
import datetime
from core.intelligence_models import (
    ApprovalRequest,
    ApprovalActionType,
    ApprovalStatus,
    AgentRole
)
from core.database import db
from core.queue_manager import queue_manager


class ApprovalEngine:
    """Evaluates and manages human authorization gates across the SWA platform."""

    # Actions that unconditionally require human approval before execution
    MANDATORY_APPROVAL_ACTIONS = {
        ApprovalActionType.AGGRESSIVE_SCANNING,
        ApprovalActionType.EXPLOIT_VALIDATION,
        ApprovalActionType.DESTRUCTIVE_TESTING,
        ApprovalActionType.PRODUCTION_CHANGE,
        ApprovalActionType.RISK_ACCEPTANCE,
        ApprovalActionType.HIGH_IMPACT_REMEDIATION,
        ApprovalActionType.SCOPE_EXPANSION
    }

    @staticmethod
    def requires_approval(action_type: ApprovalActionType, is_lab_mode: bool = False) -> bool:
        """Determines if a specific action requires human review and sign-off."""
        if is_lab_mode and action_type in (ApprovalActionType.AGGRESSIVE_SCANNING, ApprovalActionType.EXPLOIT_VALIDATION):
            # In authorized local lab environments, standard PoC validation can proceed automatically
            return False
        return action_type in ApprovalEngine.MANDATORY_APPROVAL_ACTIONS

    @staticmethod
    async def request_approval(
        action_type: ApprovalActionType,
        target: str,
        rationale: str,
        impact_assessment: str,
        agent_role: Optional[AgentRole] = None,
        scope_details: Optional[Dict[str, Any]] = None,
        requested_by: str = "SWA AI Orchestrator"
    ) -> ApprovalRequest:
        """Creates and broadcasts an auditable approval request."""
        req = ApprovalRequest(
            action_type=action_type,
            target=target,
            requested_by=requested_by,
            agent_role=agent_role,
            rationale=rationale,
            impact_assessment=impact_assessment,
            scope_details=scope_details or {},
            status=ApprovalStatus.PENDING
        )

        db.create_approval_request(req.model_dump())
        db.record_audit_log(
            action=f"APPROVAL_REQUESTED:{action_type.value}",
            actor=requested_by,
            details=f"Target: {target} | Rationale: {rationale}"
        )

        await queue_manager.broadcast_event("APPROVAL_REQUESTED", req.model_dump())
        return req

    @staticmethod
    async def decide_approval(
        request_id: str,
        approved: bool,
        decided_by: str,
        reason: str = ""
    ) -> Optional[ApprovalRequest]:
        """Records a human operator's decision on an approval gate."""
        status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
        success = db.update_approval_status(request_id, status.value, decided_by, reason)
        if not success:
            return None

        updated_dict = db.get_approval_request(request_id)
        if not updated_dict:
            return None

        updated_req = ApprovalRequest(**updated_dict)
        db.record_audit_log(
            action=f"APPROVAL_{status.value}:{updated_req.action_type.value}",
            actor=decided_by,
            details=f"Target: {updated_req.target} | Decision: {status.value} | Reason: {reason}"
        )

        await queue_manager.broadcast_event(f"APPROVAL_{status.value}", updated_req.model_dump())
        return updated_req

    @staticmethod
    def list_requests(status: Optional[ApprovalStatus] = None) -> List[ApprovalRequest]:
        """Lists pending or historical approval requests."""
        raw_list = db.get_approval_requests(status.value if status else None)
        return [ApprovalRequest(**r) for r in raw_list]


approval_engine = ApprovalEngine()
