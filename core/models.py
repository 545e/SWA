"""
SWA AI Autonomous Security Agent - Core Data Models
Pydantic schemas for targets, configs, findings, and scan jobs.
"""

from enum import Enum
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
import uuid
import datetime

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

class ScanProfile(str, Enum):
    PASSIVE_RECON = "passive_recon"    # Pure passive OSINT, DNS, Certs, Header evaluation
    RECON_ONLY = "recon_only"          # Passive + Active OSINT, DNS brute force, ports
    QUICK = "quick"                    # Rapid surface scan & top misconfigs
    STANDARD = "standard"              # Balanced assessment: OWASP Top 10 + surface + fuzz
    FULL_RED_TEAM = "full_red_team"    # Deep recon, crawling, full exploit & validation
    OWASP_TOP10 = "owasp_top10"        # Systematic OWASP Top 10 web vulnerabilities
    API_SECURITY = "api_security"      # REST/GraphQL API parameter fuzzing & auth checks
    LAB_ASSESSMENT = "lab_assessment"  # Authorized local/test lab assessment (127.0.0.1, PortSwigger)
    ALL_TOOLS = "all_tools"            # Unified threat intel across all engines simultaneously

class ScanConfig(BaseModel):
    target_url: str = Field(..., description="Target domain, URL, or IP address")
    profile: ScanProfile = Field(default=ScanProfile.FULL_RED_TEAM)
    max_depth: int = Field(default=2, ge=1, le=5)
    concurrency: int = Field(default=15, ge=1, le=50)
    timeout_sec: int = Field(default=10, ge=2, le=60)
    custom_headers: Dict[str, str] = Field(default_factory=dict)
    auth_bearer_token: Optional[str] = None
    in_scope_regex: Optional[str] = None
    enable_exploit_validation: bool = Field(default=True, description="Active PoC verification")
    enable_subdomain_enum: bool = Field(default=True, description="Perform passive and active subdomain enumeration")
    enable_fuzzing: bool = Field(default=True, description="Perform path and parameter fuzzing")
    fuzzing_wordlist_size: str = Field(default="medium", description="fast, medium, or deep")
    lab_mode: bool = Field(default=False, description="Authorize local lab testing (localhost, DVWA, PortSwigger)")
    enable_sqlmap_lab: bool = Field(default=False, description="Optional safe non-destructive SQLmap detection in lab mode")
    ai_provider: Optional[str] = Field(default="auto", description="openai, anthropic, gemini, openrouter, ollama, or auto")
    ai_model: Optional[str] = None
    ai_api_key: Optional[str] = None
    ai_base_url: Optional[str] = None

class VulnerabilityFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    scan_id: str
    title: str
    severity: Severity
    cvss_score: float = 0.0
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    endpoint: str
    method: str = "GET"
    parameter: Optional[str] = None
    description: str
    poc_curl: str = ""
    poc_explanation: str = ""
    request_evidence: str = ""
    response_evidence: str = ""
    remediation_advice: str = ""
    remediation_patch: Optional[str] = None
    verified: bool = True
    confidence: str = Field(default="HIGH", description="Confidence level: CONFIRMED, HIGH, MEDIUM, LOW")
    detection_method: str = Field(default="AUTOMATED_PROBE", description="Method or source of detection")
    affected_asset: Optional[str] = Field(default=None, description="Affected host, asset, or component")
    reproduction_steps: Optional[str] = Field(default=None, description="Step-by-step reproduction guide")
    impact: Optional[str] = Field(default=None, description="Security and business impact assessment")
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

class DiscoveredEndpoint(BaseModel):
    url: str
    method: str = "GET"
    parameters: List[str] = Field(default_factory=list)
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    title: Optional[str] = None
    is_api: bool = False

class ReconResult(BaseModel):
    target: str
    ip_addresses: List[str] = Field(default_factory=list)
    dns_records: Dict[str, List[str]] = Field(default_factory=dict)
    open_ports: List[Dict[str, Any]] = Field(default_factory=list)
    technologies: List[Dict[str, str]] = Field(default_factory=list)
    security_headers: Dict[str, Any] = Field(default_factory=dict)
    ssl_info: Dict[str, Any] = Field(default_factory=dict)
    subdomains: List[Dict[str, Any]] = Field(default_factory=list)
    subdomain_metrics: Dict[str, Any] = Field(default_factory=lambda: {
        "discovered": 0,
        "resolved": 0,
        "wildcard_filtered": 0,
        "failed_resolution": 0,
        "live_http": 0
    })
    fuzzing_results: List[Dict[str, Any]] = Field(default_factory=list)
    fuzzed_parameters: List[Dict[str, Any]] = Field(default_factory=list)
    sensitive_files: List[Dict[str, Any]] = Field(default_factory=list)

class ScanJob(BaseModel):
    id: str = Field(default_factory=lambda: f"scan_{uuid.uuid4().hex[:10]}")
    target_url: str
    status: ScanStatus = ScanStatus.PENDING
    profile: ScanProfile = ScanProfile.FULL_RED_TEAM
    progress_percent: int = 0
    current_phase: str = "Initialized"
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None
    config: ScanConfig
    recon_data: Optional[ReconResult] = None
    endpoints_count: int = 0

class LogEvent(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S"))
    scan_id: str
    level: str = "INFO" # INFO, WARN, ERROR, SUCCESS, FINDING, AGENT
    agent: str = "Orchestrator"
    message: str
