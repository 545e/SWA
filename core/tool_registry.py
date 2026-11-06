"""
SWA AI — Unified Tool Registry & Schema Catalog
Registers every implemented offensive, defensive, reconnaissance, forensics,
data management, AI training, and LLM security testing capability with full metadata.
"""

from typing import Dict, Any, List, Optional, Callable
from pydantic import BaseModel, Field
import datetime


class ToolMetadata(BaseModel):
    id: str
    name: str
    category: str # "soc", "recon", "websec", "blue_team", "ai_security"
    description: str
    purpose: str
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]
    backend_handler: str # Module & function path or endpoint
    required_dependencies: List[str] = Field(default_factory=list)
    optional_credentials: List[str] = Field(default_factory=list)
    authorization_required: bool = False
    authorization_scope: str = "user" # "public", "user", "authorized_lab", "admin"
    supports_cancellation: bool = True
    default_timeout_sec: int = 30
    status: str = "active" # "active", "degraded", "external_optional"
    installed: bool = True
    version: str = "2.2.0"


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, ToolMetadata] = {}
        self._init_registry()

    def register(self, tool: ToolMetadata):
        self._tools[tool.id] = tool

    def get(self, tool_id: str) -> Optional[ToolMetadata]:
        return self._tools.get(tool_id)

    def list_all(self, category: Optional[str] = None) -> List[ToolMetadata]:
        tools = list(self._tools.values())
        if category:
            tools = [t for t in tools if t.category == category]
        return tools

    def list_tools(self, category: Optional[str] = None) -> List[ToolMetadata]:
        return self.list_all(category)

    def _init_registry(self):
        # -------------------------------------------------------------
        # Category A: Security Operations Center (SOC)
        # -------------------------------------------------------------
        self.register(ToolMetadata(
            id="soc_posture_evaluator",
            name="SOC Security Posture & Risk Scorer",
            category="soc",
            description="Computes enterprise security posture (0-100) using transparent CVSS deductions, verified exploit weights, and missing defensive headers.",
            purpose="Provide continuous risk assessment and executive posture metrics.",
            input_schema={"type": "object", "properties": {"scan_id": {"type": "string"}}},
            output_schema={"type": "object", "properties": {"score": {"type": "number"}, "grade": {"type": "string"}}},
            backend_handler="web.server:get_scan",
            supports_cancellation=False,
            default_timeout_sec=5
        ))

        self.register(ToolMetadata(
            id="soc_scan_comparison",
            name="Scan Posture & Finding Diff Engine",
            category="soc",
            description="Compares two security scans over time, highlighting newly introduced vulnerabilities, resolved findings, and posture drift.",
            purpose="Track remediation velocity and regression prevention.",
            input_schema={"type": "object", "properties": {"base_scan_id": {"type": "string"}, "compare_scan_id": {"type": "string"}}, "required": ["base_scan_id", "compare_scan_id"]},
            output_schema={"type": "object", "properties": {"new_findings": {"type": "array"}, "resolved_findings": {"type": "array"}, "score_delta": {"type": "number"}}},
            backend_handler="web.server:compare_scans",
            default_timeout_sec=10
        ))

        self.register(ToolMetadata(
            id="soc_report_generator",
            name="Multi-Format Audit Report Generator",
            category="soc",
            description="Generates executive and technical audit reports in HTML, JSON, SARIF 2.1.0, CSV, and Markdown formats.",
            purpose="Produce compliance-ready reports for engineering, leadership, and external auditors.",
            input_schema={"type": "object", "properties": {"scan_id": {"type": "string"}, "format": {"type": "string", "enum": ["html", "json", "sarif", "csv", "markdown"]}}, "required": ["scan_id"]},
            output_schema={"type": "string", "description": "Serialized report text or HTML document"},
            backend_handler="reports.generator:ReportGenerator.generate",
            default_timeout_sec=15
        ))

        # -------------------------------------------------------------
        # Category B: Reconnaissance & OSINT
        # -------------------------------------------------------------
        self.register(ToolMetadata(
            id="recon_subdomain_amass",
            name="Layered Autonomous Subdomain Engine",
            category="recon",
            description="Multi-feed passive OSINT (crt.sh, HackerTarget, AlienVault, Wayback, RapidDNS, Anubis) + async DNS dictionary brute-forcing + AltDNS mutations + wildcard DNS detection.",
            purpose="Map complete external domain attack surface and detect dangling CNAME takeover risks.",
            input_schema={"type": "object", "properties": {"domain": {"type": "string"}, "passive_only": {"type": "boolean"}, "concurrency": {"type": "integer"}}, "required": ["domain"]},
            output_schema={"type": "object", "properties": {"count": {"type": "integer"}, "subdomains": {"type": "array"}, "metrics": {"type": "object"}}},
            backend_handler="agents.amass_engine:AmassSubdomainEngine.run",
            required_dependencies=["dnspython", "httpx"],
            optional_credentials=[],
            authorization_required=False,
            default_timeout_sec=60
        ))

        self.register(ToolMetadata(
            id="recon_port_scanner",
            name="Async Port & Service Probe",
            category="recon",
            description="High-speed non-blocking TCP socket probing for common administrative, web, database, and cloud ports.",
            purpose="Identify listening network services and exposed infrastructure.",
            input_schema={"type": "object", "properties": {"host": {"type": "string"}, "ports": {"type": "array", "items": {"type": "integer"}}}, "required": ["host"]},
            output_schema={"type": "array", "items": {"type": "object", "properties": {"port": {"type": "integer"}, "state": {"type": "string"}}}},
            backend_handler="agents.recon_agent:ReconAgent.scan_ports",
            default_timeout_sec=15
        ))

        self.register(ToolMetadata(
            id="recon_tech_stack",
            name="Technology & Security Policy Fingerprinter",
            category="recon",
            description="Analyzes HTTP response headers, cookies, and DOM markers to identify web frameworks, CDNs, and missing security headers (HSTS, CSP, XFO).",
            purpose="Enumerate server tech stack and baseline defensive configurations.",
            input_schema={"type": "object", "properties": {"target_url": {"type": "string"}}, "required": ["target_url"]},
            output_schema={"type": "object", "properties": {"technologies": {"type": "array"}, "security_headers": {"type": "object"}}},
            backend_handler="agents.recon_agent:ReconAgent.inspect_http_and_tech",
            default_timeout_sec=10
        ))

        # -------------------------------------------------------------
        # Category C: Web Application Security & Reverse Engineering
        # -------------------------------------------------------------
        self.register(ToolMetadata(
            id="websec_owasp_auditor",
            name="Autonomous OWASP Top 10 Hunting Suite",
            category="websec",
            description="Modular active/passive plugin suite covering SQL Injection, XSS, SSRF, IDOR, Path Traversal, Command Injection, Open Redirects, and Broken Access Control.",
            purpose="Discover high-fidelity application vulnerabilities with automated proof-of-concept verification.",
            input_schema={"type": "object", "properties": {"target_url": {"type": "string"}, "profile": {"type": "string"}}, "required": ["target_url"]},
            output_schema={"type": "array", "items": {"type": "object", "properties": {"title": {"type": "string"}, "severity": {"type": "string"}}}},
            backend_handler="agents.vuln_hunter_agent:VulnHunterAgent.run",
            authorization_required=True,
            authorization_scope="authorized_lab",
            default_timeout_sec=120
        ))

        self.register(ToolMetadata(
            id="websec_path_fuzzer",
            name="Anomaly-Filtered Path & Parameter Fuzzer",
            category="websec",
            description="Discovers hidden routes, configuration backups, sensitive files, and unlinked parameters with dual-baseline calibration.",
            purpose="Locate forgotten administrative panels, environment files, and debug endpoints.",
            input_schema={"type": "object", "properties": {"target_url": {"type": "string"}, "wordlist_size": {"type": "string"}}, "required": ["target_url"]},
            output_schema={"type": "object", "properties": {"paths": {"type": "array"}, "parameters": {"type": "array"}}},
            backend_handler="agents.fuzzer_agent:FuzzerAgent.run",
            default_timeout_sec=45
        ))

        self.register(ToolMetadata(
            id="websec_rea_engine",
            name="REA Reverse Engineering & Binary Analyzer",
            category="websec",
            description="Safely inspects compiled binaries (PE/ELF/Mach-O), SQLite databases, and client JavaScript bundles for hardcoded secrets, dangerous APIs, and architecture flags.",
            purpose="Audit uploaded client artifacts, firmware images, and reverse-engineer proprietary binaries.",
            input_schema={"type": "object", "properties": {"filename": {"type": "string"}, "explicit_authorization": {"type": "boolean"}}, "required": ["filename", "explicit_authorization"]},
            output_schema={"type": "object", "properties": {"target_type": {"type": "string"}, "findings": {"type": "array"}}},
            backend_handler="core.rea_engine:rea_engine.analyze_file",
            authorization_required=True,
            authorization_scope="authorized_lab",
            default_timeout_sec=30
        ))

        self.register(ToolMetadata(
            id="websec_js_intelligence",
            name="Client JavaScript Secret & Route Miner",
            category="websec",
            description="Extracts API endpoints, AWS keys, JWT tokens, and OAuth credentials from client-side JavaScript bundles using heuristic regex pattern matching.",
            purpose="Surface shadow APIs and credentials leaked in bundled JavaScript.",
            input_schema={"type": "object", "properties": {"url_or_code": {"type": "string"}}, "required": ["url_or_code"]},
            output_schema={"type": "object", "properties": {"endpoints": {"type": "array"}, "secrets": {"type": "array"}}},
            backend_handler="core.js_intelligence:GhostJsAnalyzer.scan_url",
            default_timeout_sec=20
        ))

        # -------------------------------------------------------------
        # Category D: Blue-Team & Forensics
        # -------------------------------------------------------------
        self.register(ToolMetadata(
            id="blueteam_waf_generator",
            name="Multi-Platform WAF Rule Synthesizer",
            category="blue_team",
            description="Compiles defensive firewall rules across ModSecurity CRS, Cloudflare WAF, AWS WAF, and Nginx for detected attack vectors.",
            purpose="Instantly generate virtual patches to shield vulnerable endpoints before code release.",
            input_schema={"type": "object", "properties": {"vector_type": {"type": "string"}, "target_path": {"type": "string"}}, "required": ["vector_type"]},
            output_schema={"type": "object", "properties": {"rules": {"type": "object"}}},
            backend_handler="core.blue_team_engine:BlueTeamDefenseEngine.generate_custom",
            default_timeout_sec=5
        ))

        self.register(ToolMetadata(
            id="blueteam_siem_generator",
            name="SIEM Detection Rule Generator",
            category="blue_team",
            description="Generates Sigma, Splunk SPL, Elastic Query DSL, and Microsoft Sentinel KQL detection queries for intrusion events.",
            purpose="Equip SOC analysts with hunting queries matching red team findings.",
            input_schema={"type": "object", "properties": {"rule_type": {"type": "string"}}, "required": ["rule_type"]},
            output_schema={"type": "object", "properties": {"sigma": {"type": "string"}, "splunk": {"type": "string"}, "elastic": {"type": "string"}, "sentinel": {"type": "string"}}},
            backend_handler="core.blue_team_engine:BlueTeamDefenseEngine.generate_custom",
            default_timeout_sec=5
        ))

        self.register(ToolMetadata(
            id="blueteam_log_forensics",
            name="Security Log Parser & Forensics Correlator",
            category="blue_team",
            description="Parses Apache/Nginx access logs, Suricata IDS alerts, and SSH auth logs to extract IOCs, attack frequencies, and threat IPs.",
            purpose="Forensic incident investigation and threat attribution.",
            input_schema={"type": "object", "properties": {"log_type": {"type": "string"}, "raw_logs": {"type": "string"}}, "required": ["log_type", "raw_logs"]},
            output_schema={"type": "object", "properties": {"total_events": {"type": "integer"}, "threat_events": {"type": "integer"}, "top_iocs": {"type": "array"}}},
            backend_handler="core.forensics_engine:ForensicsEngine.analyze",
            default_timeout_sec=15
        ))

        # -------------------------------------------------------------
        # Category E: AI & LLM Security
        # -------------------------------------------------------------
        self.register(ToolMetadata(
            id="ai_dataset_manager",
            name="Security Dataset & Leakage Inspector",
            category="ai_security",
            description="Ingests, validates, previews, and splits security datasets (CSV, JSONL, JSON, TXT) with automated PII and secret detection.",
            purpose="Safeguard training corpora from data contamination and credential leakage.",
            input_schema={"type": "object", "properties": {"filename": {"type": "string"}, "content": {"type": "string"}}, "required": ["filename"]},
            output_schema={"type": "object", "properties": {"record_count": {"type": "integer"}, "leakage_warnings": {"type": "array"}}},
            backend_handler="core.data_management:dataset_manager.inspect_dataset",
            default_timeout_sec=30
        ))

        self.register(ToolMetadata(
            id="ai_model_trainer",
            name="AI Security Model Trainer & Fine-Tuner",
            category="ai_security",
            description="Local training and tuning engine for vulnerability classification and security anomaly models with hardware auto-detection (CPU/GPU) and checkpoint versioning.",
            purpose="Train bespoke security classifiers and tune model weights on verified security datasets.",
            input_schema={"type": "object", "properties": {"model_name": {"type": "string"}, "dataset_id": {"type": "string"}, "epochs": {"type": "integer"}, "learning_rate": {"type": "number"}, "batch_size": {"type": "integer"}}, "required": ["model_name", "dataset_id"]},
            output_schema={"type": "object", "properties": {"job_id": {"type": "string"}, "status": {"type": "string"}}},
            backend_handler="core.ai_training:ai_trainer.start_training",
            supports_cancellation=True,
            default_timeout_sec=300
        ))

        self.register(ToolMetadata(
            id="ai_model_evaluator",
            name="Model Tuning & Benchmark Evaluator",
            category="ai_security",
            description="Evaluates baseline vs tuned models on held-out test splits: computes Precision, Recall, F1, Confusion Matrix, inference latency, throughput, token usage, and cost estimates.",
            purpose="Prevent model regression and objectively quantify performance gains.",
            input_schema={"type": "object", "properties": {"model_id": {"type": "string"}, "dataset_id": {"type": "string"}}, "required": ["model_id", "dataset_id"]},
            output_schema={"type": "object", "properties": {"precision": {"type": "number"}, "recall": {"type": "number"}, "f1": {"type": "number"}, "latency_ms": {"type": "number"}}},
            backend_handler="core.ai_evaluation:ai_evaluator.evaluate_model",
            default_timeout_sec=60
        ))

        self.register(ToolMetadata(
            id="ai_llm_redteam",
            name="LLM Adversarial Attack & Security Test Harness",
            category="ai_security",
            description="Systematic red-teaming harness across 12 OWASP LLM Top 10 threat categories: direct/indirect prompt injection, jailbreaks, system prompt extraction, sensitive data disclosure, insecure output, excessive agency, and RAG poisoning.",
            purpose="Evaluate LLM applications and models against adversarial prompts using controlled benign canaries and verifiable security policies.",
            input_schema={"type": "object", "properties": {"target_provider": {"type": "string"}, "target_model": {"type": "string"}, "categories": {"type": "array"}}, "required": ["target_provider"]},
            output_schema={"type": "object", "properties": {"tests_run": {"type": "integer"}, "passed": {"type": "integer"}, "failed": {"type": "integer"}, "results": {"type": "array"}}},
            backend_handler="core.llm_security_testing:llm_redteam_harness.run_suite",
            authorization_required=True,
            authorization_scope="authorized_lab",
            default_timeout_sec=90
        ))


        # -------------------------------------------------------------
        # Category F: Expanded SQLi, Multi-Injection, Endpoint AV & Identity
        # -------------------------------------------------------------
        self.register(ToolMetadata(
            id="websec_sqli_suite",
            name="Advanced SQL Injection Verification Engine",
            category="websec",
            description="Deep SQL injection engine executing error-based, boolean-blind, time-blind, UNION-based, and JSON/GraphQL parameter testing with automated DBMS fingerprinting.",
            purpose="Verify SQL injection vulnerabilities with mathematical invariants and zero destructive payloads.",
            input_schema={"type": "object", "properties": {"target_url": {"type": "string"}, "param_name": {"type": "string"}}, "required": ["target_url", "param_name"]},
            output_schema={"type": "array", "items": {"type": "object"}},
            backend_handler="core.sqli_engine:sqli_engine.audit_url_parameter",
            authorization_required=True,
            authorization_scope="authorized_lab",
            default_timeout_sec=45
        ))

        self.register(ToolMetadata(
            id="websec_injection_expanded",
            name="27-Category Injection Vulnerability Prober",
            category="websec",
            description="Comprehensive injection testing suite covering XSS, SSRF, SSTI, Command Injection, XXE, LDAP, Path Traversal, CRLF, and Open Redirects using safe canaries.",
            purpose="Discover high-severity injection vectors across all web application layers.",
            input_schema={"type": "object", "properties": {"target_url": {"type": "string"}, "category": {"type": "string"}}, "required": ["target_url"]},
            output_schema={"type": "array", "items": {"type": "object"}},
            backend_handler="core.injection_suite:injection_suite",
            authorization_required=True,
            authorization_scope="authorized_lab",
            default_timeout_sec=60
        ))

        self.register(ToolMetadata(
            id="endpoint_av_edr_manager",
            name="Endpoint Security & AV/EDR Diagnostics Hub",
            category="soc",
            description="Queries active host endpoint telemetry (Windows Defender, ClamAV) and evaluates 15 enterprise and consumer antivirus/EDR platforms for API and CLI integration.",
            purpose="Assess endpoint posture, real-time protection, and programmatic integration boundaries.",
            input_schema={"type": "object", "properties": {"inspect_local": {"type": "boolean"}}},
            output_schema={"type": "object", "properties": {"telemetry": {"type": "object"}, "evaluations": {"type": "array"}}},
            backend_handler="core.antivirus_edr_manager:antivirus_edr_manager.get_live_host_telemetry",
            default_timeout_sec=15
        ))

        self.register(ToolMetadata(
            id="identity_access_auditor",
            name="Identity, Access & Token Security Auditor",
            category="soc",
            description="Audits JWT token structures (alg none, expiration, sensitive claims), session cookies (HttpOnly, Secure, SameSite), and OAuth 2.0 PKCE/state parameters.",
            purpose="Discover broken access control, authentication flaws, and credential exposure.",
            input_schema={"type": "object", "properties": {"token": {"type": "string"}, "cookie": {"type": "string"}}},
            output_schema={"type": "array", "items": {"type": "object"}},
            backend_handler="core.identity_access_auditor:identity_access_auditor.audit_jwt_token",
            default_timeout_sec=10
        ))


    def update_all_tools(self) -> Dict[str, Any]:
        """Updates metadata, version, and sync status for all registered tools."""
        import datetime
        updated = []
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        for tool_id, tool in self._tools.items():
            tool.version = "2.3.0"
            tool.status = "active"
            tool.installed = True
            updated.append(tool_id)
        return {
            "status": "COMPLETED",
            "updated_tools": updated,
            "count": len(updated),
            "version": "2.3.0",
            "timestamp": now_iso
        }

tool_registry = ToolRegistry()

# -----------------------------------------------------------------
# Category G: External Scanner Adapters & Native Infrastructure
# -----------------------------------------------------------------
_scanner_defs = [
    ("scanner_nmap", "Nmap Network Scanner", "recon",
     "Host discovery, port auditing, service fingerprinting, and OS detection.",
     "Identify open ports and fingerprint services on authorized targets with moderate timing.",
     "core.scanner_integrations:ScannerIntegrations.run_nmap_scan"),
    ("scanner_nuclei", "Nuclei Vulnerability Scanner", "websec",
     "Fast, community-curated template-based security checks and misconfiguration detection.",
     "Execute community-curated, template-based security checks against authorized web endpoints.",
     "core.scanner_integrations:ScannerIntegrations.run_nuclei_scan"),
    ("scanner_owasp_zap", "OWASP ZAP Dynamic Web Prober", "websec",
     "Automated passive and active web application security baseline scanning and API assessment.",
     "Perform non-intrusive baseline passive vulnerability analysis against an approved web application.",
     "core.scanner_integrations:ScannerIntegrations.run_zap_scan"),
    ("scanner_sqlmap", "SQLmap Lab Pentesting Engine", "websec",
     "Non-destructive detection of SQL injection flaws in authorized lab environments.",
     "Safe automated SQL injection detection and database fingerprinting.",
     "core.scanner_integrations:ScannerIntegrations.run_sqlmap_scan"),
    ("scanner_nikto", "Nikto Web Server Scanner", "websec",
     "Web server misconfiguration checks, default files, and outdated software detection.",
     "Scan web server for dangerous files, outdated versions, and misconfigurations.",
     "core.scanner_integrations:ScannerIntegrations.run_nikto_scan"),
    ("scanner_tshark", "TShark Packet & Protocol Analyzer", "soc",
     "Packet capture analysis, protocol inspection, and network security diagnostics.",
     "Inspect PCAP captures and extract protocol conversation statistics.",
     "core.scanner_integrations:ScannerIntegrations"),
    ("scanner_semgrep", "Semgrep SAST Code Security Engine", "soc",
     "Static application security testing (SAST) for source code vulnerabilities and insecure coding patterns.",
     "Automated source code scanning for security vulnerabilities and secrets.",
     "core.scanner_integrations:ScannerIntegrations.run_semgrep_scan"),
    ("scanner_bandit", "Bandit Python Security Linter", "soc",
     "Static code analysis to find common security issues in Python source code.",
     "AST-based Python security linting.",
     "core.scanner_integrations:ScannerIntegrations.run_bandit_scan"),
    ("scanner_trivy", "Trivy Container & Dependency Auditor", "soc",
     "Comprehensive security scanner for container images, filesystems, and software dependencies.",
     "Audit dependencies and containers for known CVEs and misconfigurations.",
     "core.scanner_integrations:ScannerIntegrations.run_trivy_scan"),
    ("scanner_gitleaks", "Gitleaks Secret Scanner", "soc",
     "Fast, regex and entropy-based secret detection for git repositories and files.",
     "Scan source repositories for committed API keys, tokens, and credentials.",
     "core.scanner_integrations:ScannerIntegrations.run_gitleaks_scan"),
    ("scanner_clamav", "ClamAV Antivirus Scanner", "blue_team",
     "Multi-threaded signature-based virus, trojan, and malicious document detection.",
     "Scan files and directories for malware and malicious signatures.",
     "core.scanner_integrations:ScannerIntegrations"),
    ("scanner_wazuh", "Wazuh Host EDR & SIEM Agent", "blue_team",
     "Endpoint detection & response (EDR), file integrity monitoring (FIM), and threat detection.",
     "Query local host endpoint telemetry, agent status, and intrusion events.",
     "core.scanner_integrations:ScannerIntegrations"),
    ("scanner_defender", "Microsoft Defender Antivirus & EDR", "blue_team",
     "Real-time virus, malware, trojan, spyware, and ransomware protection with quarantine and signature updates.",
     "Native Windows host antivirus and EDR inspection.",
     "core.scanner_integrations:ScannerIntegrations")
]

for sid, sname, scat, sdesc, spurp, shandler in _scanner_defs:
    tool_registry.register(ToolMetadata(
        id=sid,
        name=sname,
        category=scat,
        description=sdesc,
        purpose=spurp,
        input_schema={"type": "object", "properties": {"target": {"type": "string"}}},
        output_schema={"type": "object", "properties": {"status": {"type": "string"}}},
        backend_handler=shandler,
        version="2.3.0",
        installed=True,
        status="active"
    ))

