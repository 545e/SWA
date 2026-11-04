"""
SWA AI — Autonomous Cybersecurity Intelligence Data Models
Defines Pydantic schemas for Multi-Agent Workforce, Security Knowledge Graph,
Approval Gates, Enterprise Context, EASM Drift, and Explainable Risk Scoring.
"""

from enum import Enum
from typing import List, Dict, Optional, Any, Union
from pydantic import BaseModel, Field
import uuid
import datetime


# ---------------------------------------------------------------------------
# Multi-Agent Workforce Schemas
# ---------------------------------------------------------------------------

class AgentRole(str, Enum):
    SUPERVISOR = "supervisor"
    RECONNAISSANCE = "reconnaissance"
    ASSET_INTELLIGENCE = "asset_intelligence"
    WEB_SECURITY = "web_security"
    API_SECURITY = "api_security"
    NETWORK_SECURITY = "network_security"
    CLOUD_SECURITY = "cloud_security"
    SOURCE_CODE_SECURITY = "source_code_security"
    VULNERABILITY_INTELLIGENCE = "vulnerability_intelligence"
    THREAT_INTELLIGENCE = "threat_intelligence"
    COMPLIANCE = "compliance"
    FINDINGS_CORRELATION = "findings_correlation"
    RISK_PRIORITIZATION = "risk_prioritization"
    REMEDIATION = "remediation"
    REPORT_GENERATION = "report_generation"
    QUALITY_ASSURANCE = "quality_assurance"
    PLATFORM_HEALTH = "platform_health"


class AgentPermissionBoundary(BaseModel):
    allowed_tools: List[str] = Field(default_factory=list)
    can_execute_active_probes: bool = False
    requires_approval_for_exploits: bool = True
    can_access_production_targets: bool = False
    max_execution_time_sec: int = 120
    memory_limit_mb: int = 512
    max_network_requests: int = 500


class AgentManifest(BaseModel):
    role: AgentRole
    name: str
    version: str = "2.2.0"
    description: str
    responsibilities: List[str]
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]
    permission_boundary: AgentPermissionBoundary
    status: str = "active"  # "active", "standby", "executing", "disabled"


class AgentTask(BaseModel):
    id: str = Field(default_factory=lambda: f"task_{uuid.uuid4().hex[:8]}")
    agent_role: Union[AgentRole, str]
    scan_id: str
    title: str
    status: str = "PENDING"  # PENDING, RUNNING, COMPLETED, FAILED, AWAITING_APPROVAL, CANCELLED
    inputs: Dict[str, Any] = Field(default_factory=dict)
    outputs: Optional[Dict[str, Any]] = None
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    error_message: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None


class AgentMessage(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    sender: Union[AgentRole, str]
    recipient: Union[AgentRole, str]
    message_type: str  # "TASK_DISPATCH", "EVIDENCE_SUBMIT", "APPROVAL_REQUEST", "TELEMETRY", "CORRELATION"
    payload: Dict[str, Any]


# ---------------------------------------------------------------------------
# Human-in-the-Loop Approval Gates
# ---------------------------------------------------------------------------

class ApprovalActionType(str, Enum):
    NEW_TARGET_AUTHORIZATION = "new_target_authorization"
    SCOPE_EXPANSION = "scope_expansion"
    AGGRESSIVE_SCANNING = "aggressive_scanning"
    EXPLOIT_VALIDATION = "exploit_validation"
    DESTRUCTIVE_TESTING = "destructive_testing"
    PRODUCTION_CHANGE = "production_change"
    RISK_ACCEPTANCE = "risk_acceptance"
    SENSITIVE_DATA_TRANSFER = "sensitive_data_transfer"
    HIGH_IMPACT_REMEDIATION = "high_impact_remediation"


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ApprovalRequest(BaseModel):
    id: str = Field(default_factory=lambda: f"appr_{uuid.uuid4().hex[:8]}")
    action_type: ApprovalActionType
    target: str
    requested_by: str = "SWA AI Orchestrator"
    agent_role: Optional[AgentRole] = None
    rationale: str
    impact_assessment: str
    scope_details: Dict[str, Any] = Field(default_factory=dict)
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_by: Optional[str] = None
    decision_reason: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    decided_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Enterprise Tenancy, Workspace & Global Security Context
# ---------------------------------------------------------------------------

class UserRole(str, Enum):
    ADMIN = "admin"
    SECURITY_LEAD = "security_lead"
    PENETRATION_TESTER = "penetration_tester"
    SOC_ANALYST = "soc_analyst"
    DEVELOPER = "developer"
    AUDITOR = "auditor"


class Workspace(BaseModel):
    id: str = Field(default_factory=lambda: f"ws_{uuid.uuid4().hex[:6]}")
    name: str
    description: str = ""
    organization: str = "Enterprise Security"
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class Project(BaseModel):
    id: str = Field(default_factory=lambda: f"proj_{uuid.uuid4().hex[:6]}")
    workspace_id: str
    name: str
    description: str = ""
    authorized_domains: List[str] = Field(default_factory=list)
    business_criticality: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW
    owner: str = "Security Team"
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class GlobalSecurityContext(BaseModel):
    workspace_id: str = "ws_default"
    workspace_name: str = "Default Enterprise"
    project_id: str = "proj_default"
    project_name: str = "Core Production Infrastructure"
    target: str = "127.0.0.1:8000"
    target_authorized: bool = True
    active_scan_id: Optional[str] = None
    active_scan_status: str = "READY"
    active_tasks_count: int = 0
    pending_approvals_count: int = 0
    posture_score: float = 88.0
    posture_grade: str = "B"
    latest_findings_count: int = 0
    last_completion_timestamp: Optional[str] = None


# ---------------------------------------------------------------------------
# Security Knowledge Graph Schemas
# ---------------------------------------------------------------------------

class GraphNodeType(str, Enum):
    ORGANIZATION = "Organization"
    PROJECT = "Project"
    DOMAIN = "Domain"
    SUBDOMAIN = "Subdomain"
    IP_ADDRESS = "IpAddress"
    NETWORK_SERVICE = "NetworkService"
    APPLICATION = "Application"
    API_ENDPOINT = "ApiEndpoint"
    TECHNOLOGY = "Technology"
    CERTIFICATE = "Certificate"
    VULNERABILITY = "Vulnerability"
    FINDING = "Finding"
    EVIDENCE = "Evidence"
    REMEDIATION = "Remediation"
    OWNER = "Owner"


class GraphNode(BaseModel):
    id: str
    type: GraphNodeType
    label: str
    properties: Dict[str, Any] = Field(default_factory=dict)
    criticality: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class GraphEdge(BaseModel):
    id: str = Field(default_factory=lambda: f"edge_{uuid.uuid4().hex[:8]}")
    source_id: str
    target_id: str
    relationship: str  # e.g., "OWNS", "RESOLVES_TO", "RUNS_SERVICE", "EXPOSES_ENDPOINT", "AFFECTED_BY", "VERIFIED_BY"
    properties: Dict[str, Any] = Field(default_factory=dict)


class SecurityKnowledgeGraph(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    summary: Dict[str, int] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Continuous Attack Surface Intelligence (EASM Drift)
# ---------------------------------------------------------------------------

class DriftType(str, Enum):
    NEW_ASSET = "NEW_ASSET"
    REMOVED_ASSET = "REMOVED_ASSET"
    DNS_CHANGE = "DNS_CHANGE"
    NEW_PORT_SERVICE = "NEW_PORT_SERVICE"
    CLOSED_PORT_SERVICE = "CLOSED_PORT_SERVICE"
    TECHNOLOGY_CHANGED = "TECHNOLOGY_CHANGED"
    CERTIFICATE_EXPIRING = "CERTIFICATE_EXPIRING"
    NEW_ENDPOINT = "NEW_ENDPOINT"
    VULNERABILITY_EXPOSURE = "VULNERABILITY_EXPOSURE"


class AssetDriftEvent(BaseModel):
    id: str = Field(default_factory=lambda: f"drift_{uuid.uuid4().hex[:8]}")
    project_id: str = "proj_default"
    target: str
    asset_name: str
    drift_type: DriftType
    title: str
    description: str
    previous_state: Optional[Dict[str, Any]] = None
    current_state: Dict[str, Any] = Field(default_factory=dict)
    confidence: str = "CONFIRMED"  # CONFIRMED, HIGH_PROBABILITY, SUSPECTED_TRANSIENT
    is_genuine_change: bool = True
    detected_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# Finding Lifecycle & Explainable Risk Scoring
# ---------------------------------------------------------------------------

class FindingLifecycleStatus(str, Enum):
    # Original lifecycle states
    DISCOVERED = "DISCOVERED"
    TRIAGED = "TRIAGED"
    ASSIGNED = "ASSIGNED"
    IN_PROGRESS = "IN_PROGRESS"
    FIX_SUBMITTED = "FIX_SUBMITTED"
    RETEST = "RETEST"
    VERIFIED = "VERIFIED"
    CLOSED = "CLOSED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    
    # Section 13.6 Extended Verification & Lifecycle States
    NEW = "NEW"
    NEEDS_VALIDATION = "NEEDS_VALIDATION"
    CONFIRMED = "CONFIRMED"
    LIKELY_FALSE_POSITIVE = "LIKELY_FALSE_POSITIVE"
    DUPLICATE = "DUPLICATE"
    FIX_IN_PROGRESS = "FIX_IN_PROGRESS"
    FIXED_PENDING_RETEST = "FIXED_PENDING_RETEST"
    RESOLVED_VERIFIED = "RESOLVED_VERIFIED"
    REOPENED = "REOPENED"
    INCONCLUSIVE = "INCONCLUSIVE" 


class RiskScoreBreakdown(BaseModel):
    final_score: float = Field(..., ge=0.0, le=100.0)
    severity_factor: float
    confidence_factor: float
    exploitability_factor: float
    exposure_factor: float
    asset_criticality_factor: float
    epss_percentile: Optional[float] = None
    known_exploited_cisa_kev: bool = False
    mitigation_discount: float = 0.0
    rationale: str


class RemediationTicket(BaseModel):
    id: str = Field(default_factory=lambda: f"rem_{uuid.uuid4().hex[:8]}")
    finding_id: str
    scan_id: str
    target: str
    title: str
    severity: str
    lifecycle_status: FindingLifecycleStatus = FindingLifecycleStatus.DISCOVERED
    owner: str = "Unassigned"
    due_date: Optional[str] = None
    patch_code: Optional[str] = None
    mitigation_guidance: Optional[str] = None
    retest_status: Optional[str] = None  # PENDING, PASSED_VERIFIED, FAILED_PERSISTS
    retest_evidence: Optional[str] = None
    suppression_reason: Optional[str] = None
    history: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# 12-Template Enterprise Report Engine Models
# ---------------------------------------------------------------------------

class ReportTemplateType(str, Enum):
    EXECUTIVE_ASSESSMENT = "executive_assessment"
    FULL_TECHNICAL_ASSESSMENT = "full_technical_assessment"
    VULNERABILITY_REPORT = "vulnerability_report"
    ASSET_EXPOSURE_REPORT = "asset_exposure_report"
    API_SECURITY_REPORT = "api_security_report"
    INFRASTRUCTURE_SECURITY_REPORT = "infrastructure_security_report"
    COMPLIANCE_REPORT = "compliance_report"
    REMEDIATION_REPORT = "remediation_report"
    RETEST_REPORT = "retest_report"
    CONTINUOUS_MONITORING_REPORT = "continuous_monitoring_report"
    TOOL_EXECUTION_REPORT = "tool_execution_report"
    PLATFORM_HEALTH_REPORT = "platform_health_report"


class ReportRecord(BaseModel):
    id: str = Field(default_factory=lambda: f"rep_{uuid.uuid4().hex[:8]}")
    template_type: ReportTemplateType
    title: str
    target: str
    scan_id: Optional[str] = None
    format: str = "html"  # html, json, sarif, csv, markdown
    summary: str = ""
    findings_count: int = 0
    risk_score: float = 0.0
    generated_by: str = "Report Generation Agent"
    content: str
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
