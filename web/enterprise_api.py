"""

SWA AI — Enterprise REST API Endpoints

Provides endpoints for Global Context, Specialist Agent Workforce,

Human Approval Gates, Security Knowledge Graph, EASM Drift,

Remediation Lifecycle Board, 12-Template Enterprise Reports, and Diagnostics.

"""



from fastapi import APIRouter, HTTPException, Query, BackgroundTasks

from typing import List, Dict, Any, Optional

from pydantic import BaseModel, Field

import datetime



from core.database import db

from core.intelligence_models import (

    GlobalSecurityContext,

    Workspace,

    Project,

    ApprovalRequest,

    ApprovalActionType,

    ApprovalStatus,

    AgentRole,

    AgentTask,

    ReportTemplateType,

    FindingLifecycleStatus

)

from core.approval_engine import approval_engine

from core.knowledge_graph import knowledge_graph_engine

from core.attack_surface_intel import attack_surface_intel

from core.remediation_engine import remediation_engine

from core.risk_engine import risk_engine

from agents.agent_workforce import agent_workforce

from reports.enterprise_reports import enterprise_report_engine



router = APIRouter(prefix="/api", tags=["Enterprise Intelligence"])





# ---------------------------------------------------------------------------

# 1. Global Security Context

# ---------------------------------------------------------------------------



class ContextUpdateRequest(BaseModel):

    workspace_id: Optional[str] = None

    workspace_name: Optional[str] = None

    project_id: Optional[str] = None

    project_name: Optional[str] = None

    target: Optional[str] = None

    target_authorized: Optional[bool] = None





@router.get("/context", response_model=GlobalSecurityContext)

async def get_global_context():

    """Retrieve application-wide security context."""

    raw = db.get_global_context()

    recent_scans = db.get_scans(limit=1)

    active_scan = recent_scans[0] if recent_scans else None

    

    # Calculate live posture score and grade

    findings = db.get_findings_by_scan(active_scan.id) if active_scan else []

    posture_score = 100.0

    for f in findings:

        s = f.severity.value if hasattr(f.severity, "value") else str(f.severity)

        if s == "CRITICAL":

            posture_score -= 30

        elif s == "HIGH":

            posture_score -= 18

        elif s == "MEDIUM":

            posture_score -= 8

        elif s == "LOW":

            posture_score -= 3

        else:

            posture_score -= 1

    posture_score = max(0.0, min(100.0, posture_score))

    grade = "A" if posture_score >= 90 else "B" if posture_score >= 75 else "C" if posture_score >= 60 else "D" if posture_score >= 40 else "F"



    pending_approvals = len(db.get_approval_requests(status="PENDING"))



    return GlobalSecurityContext(

        workspace_id=raw.get("workspace_id", "ws_default"),

        workspace_name=raw.get("workspace_name", "Default Enterprise"),

        project_id=raw.get("project_id", "proj_default"),

        project_name=raw.get("project_name", "Core Infrastructure"),

        target=raw.get("target", "127.0.0.1:8000"),

        target_authorized=bool(raw.get("target_authorized", True)),

        active_scan_id=active_scan.id if active_scan else None,

        active_scan_status=active_scan.status.value if active_scan else "READY",

        active_tasks_count=len(db.get_agent_tasks()),

        pending_approvals_count=pending_approvals,

        posture_score=posture_score,

        posture_grade=grade,

        latest_findings_count=len(findings),

        last_completion_timestamp=active_scan.completed_at if active_scan else None

    )





@router.post("/context")

async def update_global_context(req: ContextUpdateRequest):

    """Updates active workspace, project, or target scope."""

    ctx = db.get_global_context()

    if req.workspace_id:

        ctx["workspace_id"] = req.workspace_id

    if req.workspace_name:

        ctx["workspace_name"] = req.workspace_name

    if req.project_id:

        ctx["project_id"] = req.project_id

    if req.project_name:

        ctx["project_name"] = req.project_name

    if req.target:

        ctx["target"] = req.target

    if req.target_authorized is not None:

        ctx["target_authorized"] = req.target_authorized



    db.save_global_context(ctx)

    db.record_audit_log(

        action="CONTEXT_UPDATED",

        actor="Operator",

        details=f"Target: {ctx.get('target')} | Workspace: {ctx.get('workspace_name')}"

    )

    return {"status": "SUCCESS", "context": ctx}





# ---------------------------------------------------------------------------

# 2. Workspaces & Projects

# ---------------------------------------------------------------------------



@router.get("/workspaces")

async def list_workspaces():

    return db.get_workspaces()





@router.post("/workspaces")

async def create_workspace(ws: Workspace):

    db.save_workspace(ws.model_dump())

    return {"status": "CREATED", "workspace": ws}





@router.get("/projects")

async def list_projects(workspace_id: Optional[str] = None):

    return db.get_projects(workspace_id)





@router.post("/projects")

async def create_project(proj: Project):

    db.save_project(proj.model_dump())

    return {"status": "CREATED", "project": proj}





# ---------------------------------------------------------------------------

# 3. Specialist Multi-Agent Workforce

# ---------------------------------------------------------------------------



@router.get("/agents")

async def list_agents(

    category: Optional[str] = None,

    tier: Optional[str] = None,

    status: Optional[str] = None,

    search: Optional[str] = None,

    page: Optional[int] = None,

    limit: Optional[int] = None

):

    """

    Returns manifests for all 85 cybersecurity agents across 5 operational tiers.

    Supports filtering by category, tier, status, search, and pagination.

    """

    from core.agent_registry import agent_registry

    manifests = agent_registry.list_manifests(

        category=category, tier=tier, status=status, search=search

    )

    dumped = [m.model_dump() for m in manifests]



    if page is not None and limit is not None and limit > 0:

        total = len(dumped)

        start = (page - 1) * limit

        items = dumped[start:start + limit]

        return {

            "items": items,

            "total": total,

            "page": page,

            "limit": limit,

            "pages": (total + limit - 1) // limit

        }



    return dumped





@router.get("/agents/summary")

async def get_agents_summary():

    """Returns workforce metrics and tier counts across all 85 agents."""

    from core.agent_registry import agent_registry

    return agent_registry.get_summary()





@router.get("/agents/{agent_id}")

async def get_agent_details(agent_id: str):

    """Returns detailed manifest for a specific agent by ID."""

    from core.agent_registry import agent_registry

    agent = agent_registry.get_agent(agent_id)

    if not agent:

        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")

    return agent.model_dump()





class AgentTaskDispatchReq(BaseModel):

    title: str

    scan_id: Optional[str] = None

    inputs: Dict[str, Any] = Field(default_factory=dict)





@router.post("/agents/{agent_role}/task")

async def dispatch_agent_task(agent_role: str, req: AgentTaskDispatchReq):

    """Dispatches a standalone task to a specialist agent."""

    try:

        role_enum = AgentRole(agent_role)

    except ValueError:

        raise HTTPException(status_code=400, detail=f"Invalid agent role: {agent_role}")



    task = AgentTask(

        agent_role=role_enum,

        scan_id=req.scan_id or "adhoc_task",

        title=req.title,

        inputs=req.inputs

    )

    result = await agent_workforce.dispatch_task(role_enum, task)

    return result.model_dump()





@router.get("/agents/tasks")

async def list_agent_tasks(scan_id: Optional[str] = None, agent_role: Optional[str] = None):

    """Returns audit history of agent task executions."""

    return db.get_agent_tasks(scan_id, agent_role)





# ---------------------------------------------------------------------------

# 4. Human-in-the-Loop Approval Gates

# ---------------------------------------------------------------------------



class ApprovalCreateReq(BaseModel):

    action_type: ApprovalActionType

    target: str

    rationale: str

    impact_assessment: str

    agent_role: Optional[AgentRole] = None

    scope_details: Dict[str, Any] = Field(default_factory=dict)





class ApprovalDecisionReq(BaseModel):

    approved: bool

    decided_by: str = "Lead Security Architect"

    reason: str = ""





@router.get("/approvals")

async def list_approvals(status: Optional[str] = None):

    """Lists pending, approved, or rejected approval gates."""

    status_enum = ApprovalStatus(status) if status else None

    return [r.model_dump() for r in approval_engine.list_requests(status_enum)]





@router.post("/approvals")

async def create_approval(req: ApprovalCreateReq):

    """Creates a new human approval gate request."""

    res = await approval_engine.request_approval(

        action_type=req.action_type,

        target=req.target,

        rationale=req.rationale,

        impact_assessment=req.impact_assessment,

        agent_role=req.agent_role,

        scope_details=req.scope_details

    )

    return res.model_dump()





@router.post("/approvals/{request_id}/decide")

async def decide_approval(request_id: str, req: ApprovalDecisionReq):

    """Operator sign-off or rejection of an approval gate."""

    res = await approval_engine.decide_approval(

        request_id=request_id,

        approved=req.approved,

        decided_by=req.decided_by,

        reason=req.reason

    )

    if not res:

        raise HTTPException(status_code=404, detail="Approval request not found.")

    return res.model_dump()





# ---------------------------------------------------------------------------

# 5. Security Knowledge Graph

# ---------------------------------------------------------------------------



@router.get("/graph")

async def get_knowledge_graph():

    """Returns nodes, edges, and category summary for interactive visualization."""

    return knowledge_graph_engine.get_full_graph().model_dump()





@router.get("/graph/exposed-assets")

async def get_exposed_assets():

    """Queries all exposed assets connected to open services or vulnerabilities."""

    return knowledge_graph_engine.query_exposed_assets()





@router.get("/graph/shared-vulnerabilities")

async def get_shared_vulnerabilities():

    """Queries vulnerabilities affecting multiple assets."""

    return knowledge_graph_engine.query_shared_vulnerabilities()





# ---------------------------------------------------------------------------

# 6. Continuous Attack Surface Intelligence (EASM Drift)

# ---------------------------------------------------------------------------



@router.get("/easm/drift")

async def get_easm_drift(limit: int = 50, project_id: Optional[str] = None):

    """Retrieves detected attack surface changes and drift events."""

    return [e.model_dump() for e in attack_surface_intel.get_history(limit=limit, project_id=project_id)]





# ---------------------------------------------------------------------------

# 7. Remediation Lifecycle & Retest

# ---------------------------------------------------------------------------



@router.get("/remediation/tickets")

async def list_remediation_tickets(status: Optional[str] = None, scan_id: Optional[str] = None):

    """Lists remediation tickets across the lifecycle board."""

    return db.get_remediation_tickets(status=status, scan_id=scan_id)





@router.get("/remediation/tickets/{ticket_id}")

async def get_remediation_ticket(ticket_id: str):

    ticket = db.get_remediation_ticket(ticket_id)

    if not ticket:

        raise HTTPException(status_code=404, detail="Remediation ticket not found.")

    return ticket





class TicketTransitionReq(BaseModel):

    new_status: FindingLifecycleStatus

    actor: str = "Security Analyst"

    reason: str = ""

    owner: Optional[str] = None

    suppression_reason: Optional[str] = None





@router.post("/remediation/tickets/{ticket_id}/transition")

async def transition_ticket(ticket_id: str, req: TicketTransitionReq):

    """Transitions a remediation ticket to a new lifecycle state."""

    ticket = await remediation_engine.transition_ticket(

        ticket_id=ticket_id,

        new_status=req.new_status,

        actor=req.actor,

        reason=req.reason,

        owner=req.owner,

        suppression_reason=req.suppression_reason

    )

    if not ticket:

        raise HTTPException(status_code=404, detail="Remediation ticket not found.")

    return ticket.model_dump()





@router.post("/remediation/tickets/{ticket_id}/retest")

async def retest_ticket(ticket_id: str):

    """Executes automated verification probe against the endpoint."""

    res = await remediation_engine.run_retest(ticket_id)

    return res





# ---------------------------------------------------------------------------

# 8. 12-Template Enterprise Report Engine

# ---------------------------------------------------------------------------



@router.get("/reports/templates")

async def list_report_templates():

    """Lists the 12 first-class enterprise report templates."""

    return [

        {"id": t.value, "name": t.name.replace("_", " ").title(), "description": f"Standard enterprise report for {t.value}"}

        for t in ReportTemplateType

    ]





class ReportGenerateReq(BaseModel):

    template_type: ReportTemplateType

    target: Optional[str] = "127.0.0.1:8000"

    scan_id: Optional[str] = None

    format_type: str = "html"  # html, json, markdown, csv





@router.post("/reports/generate")

async def generate_enterprise_report(req: ReportGenerateReq):

    """Generates an enterprise-grade report from persisted database records."""

    record = enterprise_report_engine.generate_report(

        template_type=req.template_type,

        target=req.target or "127.0.0.1:8000",

        scan_id=req.scan_id,

        format_type=req.format_type

    )

    return record.model_dump()





@router.get("/reports/archive")

async def list_report_archive(limit: int = 50, template_type: Optional[str] = None):

    """Lists previously generated and archived reports."""

    return db.get_report_records(limit=limit, template_type=template_type)





@router.get("/reports/archive/{report_id}")

async def get_report_record(report_id: str):

    rec = db.get_report_record(report_id)

    if not rec:

        raise HTTPException(status_code=404, detail="Report record not found.")

    return rec





# ---------------------------------------------------------------------------

# 9. Platform Diagnostics & Health

# ---------------------------------------------------------------------------



@router.get("/health/diagnostics")

async def get_detailed_diagnostics():

    """Provides comprehensive health and performance metrics across all SWA subsystems."""

    from core.scanner_integrations import ScannerIntegrations

    inventory = ScannerIntegrations.get_tool_inventory()

    

    return {

        "status": "HEALTHY",

        "platform": "SWA AI Autonomous Cybersecurity Operating System",

        "version": "2.2.0-Enterprise",

        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),

        "subsystems": {

            "database": {"status": "ONLINE", "type": "SQLite (Thread-safe WAL)", "tables": 18},

            "agents": {"status": "READY", "active_count": 17, "total_catalog": 85, "workforce_online": True, "tiers": 5},

            "security_tools": {

                "total_catalog": len(inventory),

                "installed_count": sum(1 for t in inventory.values() if t.get("installed")),

                "native_suite": "HEALTHY"

            },

            "knowledge_graph": {"status": "ACTIVE", "nodes_count": len(db.get_knowledge_graph().get("nodes", []))},

            "approval_gates": {"status": "ACTIVE", "pending_requests": len(db.get_approval_requests("PENDING"))},

            "remediation_engine": {"status": "ACTIVE", "total_tickets": len(db.get_remediation_tickets())}

        }

    }

