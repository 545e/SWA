# SWA AI — Complete 85-Agent Authoritative Inventory

**Generated:** 2026-11-01T07:23:49.512323+00:00  
**Platform Version:** 2.2.0-Enterprise  
**Total Discovered:** 85  
**Total Registered:** 85  
**Available:** 85  
**Execution Status:** OPERATIONAL  

---

## 1. Executive Summary

This document provides the authoritative, reconciled inventory of all 85 cybersecurity agents, specialist engines, OWASP security plugins, and scanner adapters operating within the SWA AI platform across 5 operational tiers.

| Operational Tier | Tier Name | Agent Count | Primary Architectural Responsibility | Verification Status |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1** | Specialist Workforce Agents | 17 | Core multi-agent autonomous security workforce | **PASS** (17/17) |
| **Tier 2** | Offensive & Reconnaissance Domain Agents | 9 | Subdomain discovery, attack surface, fuzzing & validation | **PASS** (9/9) |
| **Tier 3** | OWASP Top 10 Security Plugin Agents | 10 | Deep vulnerability probing for OWASP A01-A10 | **PASS** (10/10) |
| **Tier 4** | Core Autonomous Security & Governance Engines | 32 | AST analysis, DFIR, WAF evasion, SQLi, AV/EDR, LLM Red Team | **PASS** (32/32) |
| **Tier 5** | External Tool & Scanner Integration Adapters | 17 | CLI & API adapters for Nmap, Nuclei, ZAP, Bandit, Trivy, etc. | **PASS** (17/17) |
| **TOTAL** | **All Managed Cybersecurity Agents** | **85** | **Full Spectrum Enterprise Cybersecurity Automation** | **PASS (85/85)** |

---

## 2. Complete Reconciled Agent Inventory Table

| # | Agent ID | Agent Name | Tier | Category | Module Path | Class Name | Max Timeout | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `supervisor` | Supervisor Agent | `specialist_workforce` | Workforce Specialists | `agents.agent_workforce` | `SupervisorAgent` | 60s | **AVAILABLE** |
| 2 | `reconnaissance` | Reconnaissance Agent | `specialist_workforce` | Workforce Specialists | `agents.agent_workforce` | `ReconnaissanceAgent` | 180s | **AVAILABLE** |
| 3 | `asset_intelligence` | Asset Intelligence Agent | `specialist_workforce` | Workforce Specialists | `agents.agent_workforce` | `AssetIntelligenceAgent` | 60s | **AVAILABLE** |
| 4 | `web_security` | Web Security Agent | `specialist_workforce` | Workforce Specialists | `agents.agent_workforce` | `WebSecurityAgent` | 180s | **AVAILABLE** |
| 5 | `api_security` | API Security Agent | `specialist_workforce` | Workforce Specialists | `agents.agent_workforce` | `APISecurityAgent` | 120s | **AVAILABLE** |
| 6 | `network_security` | Network Security Agent | `specialist_workforce` | Workforce Specialists | `agents.agent_workforce` | `NetworkSecurityAgent` | 120s | **AVAILABLE** |
| 7 | `cloud_security` | Cloud Security Agent | `specialist_workforce` | Workforce Specialists | `agents.agent_workforce` | `CloudSecurityAgent` | 90s | **AVAILABLE** |
| 8 | `source_code_security` | Source Code Security Agent | `specialist_workforce` | Workforce Specialists | `agents.agent_workforce` | `SourceCodeSecurityAgent` | 120s | **AVAILABLE** |
| 9 | `vulnerability_intelligence` | Vulnerability Intelligence Agent | `specialist_workforce` | Workforce Specialists | `agents.agent_workforce` | `VulnerabilityIntelligenceAgent` | 60s | **AVAILABLE** |
| 10 | `threat_intelligence` | Threat Intelligence Agent | `specialist_workforce` | Workforce Specialists | `agents.agent_workforce` | `ThreatIntelligenceAgent` | 60s | **AVAILABLE** |
| 11 | `compliance` | Compliance Agent | `specialist_workforce` | Workforce Specialists | `agents.agent_workforce` | `ComplianceAgent` | 60s | **AVAILABLE** |
| 12 | `findings_correlation` | Findings Correlation Agent | `specialist_workforce` | Workforce Specialists | `agents.agent_workforce` | `FindingsCorrelationAgent` | 60s | **AVAILABLE** |
| 13 | `risk_prioritization` | Risk Prioritization Agent | `specialist_workforce` | Workforce Specialists | `agents.agent_workforce` | `RiskPrioritizationAgent` | 45s | **AVAILABLE** |
| 14 | `remediation` | Remediation Agent | `specialist_workforce` | Workforce Specialists | `agents.agent_workforce` | `RemediationAgent` | 60s | **AVAILABLE** |
| 15 | `report_generation` | Report Generation Agent | `specialist_workforce` | Workforce Specialists | `agents.agent_workforce` | `ReportGenerationAgent` | 90s | **AVAILABLE** |
| 16 | `quality_assurance` | Quality Assurance Agent | `specialist_workforce` | Workforce Specialists | `agents.agent_workforce` | `QualityAssuranceAgent` | 45s | **AVAILABLE** |
| 17 | `platform_health` | Platform Health Agent | `specialist_workforce` | Workforce Specialists | `agents.agent_workforce` | `PlatformHealthAgent` | 30s | **AVAILABLE** |
| 18 | `amass_engine` | OWASP Amass Subdomain Engine | `offensive_recon` | Offensive & Reconnaissance | `agents.amass_engine` | `AmassSubdomainEngine` | 180s | **AVAILABLE** |
| 19 | `attack_surface_agent` | Attack Surface Intelligence Agent | `offensive_recon` | Offensive & Reconnaissance | `agents.attack_surface_agent` | `AttackSurfaceAgent` | 120s | **AVAILABLE** |
| 20 | `dependency_confusion_agent` | Dependency Confusion Audit Agent | `offensive_recon` | Offensive & Reconnaissance | `agents.dependency_confusion_agent` | `DependencyConfusionAgent` | 90s | **AVAILABLE** |
| 21 | `exploit_validator_agent` | Safe Exploit Validator Agent | `offensive_recon` | Offensive & Reconnaissance | `agents.exploit_validator_agent` | `ExploitValidatorAgent` | 90s | **AVAILABLE** |
| 22 | `fuzzer_agent` | Autonomous Path & Parameter Fuzzer Agent | `offensive_recon` | Offensive & Reconnaissance | `agents.fuzzer_agent` | `FuzzerAgent` | 180s | **AVAILABLE** |
| 23 | `recon_agent` | Active Network Reconnaissance Agent | `offensive_recon` | Offensive & Reconnaissance | `agents.recon_agent` | `ReconAgent` | 120s | **AVAILABLE** |
| 24 | `vuln_hunter_agent` | Autonomous Vulnerability Hunter Agent | `offensive_recon` | Offensive & Reconnaissance | `agents.vuln_hunter_agent` | `VulnHunterAgent` | 240s | **AVAILABLE** |
| 25 | `remediation_lifecycle_agent` | Remediation Lifecycle Verifier | `offensive_recon` | Offensive & Reconnaissance | `agents.remediation_agent` | `RemediationAgent` | 60s | **AVAILABLE** |
| 26 | `swa_orchestrator` | SWA Master Orchestration Engine | `offensive_recon` | Offensive & Reconnaissance | `agents.orchestrator` | `SWAOrchestrator` | 300s | **AVAILABLE** |
| 27 | `owasp_a01_broken_access` | A01: Broken Access Control Agent | `owasp_plugins` | OWASP Security Plugins | `plugins.owasp_plugins` | `PluginA01_BrokenAccessControl` | 60s | **AVAILABLE** |
| 28 | `owasp_a02_crypto_failures` | A02: Cryptographic Failures Agent | `owasp_plugins` | OWASP Security Plugins | `plugins.owasp_plugins` | `PluginA02_CryptographicFailures` | 60s | **AVAILABLE** |
| 29 | `owasp_a03_injection` | A03: Injection Prober Agent | `owasp_plugins` | OWASP Security Plugins | `plugins.owasp_plugins` | `PluginA03_Injection` | 90s | **AVAILABLE** |
| 30 | `owasp_a04_insecure_design` | A04: Insecure Design Agent | `owasp_plugins` | OWASP Security Plugins | `plugins.owasp_plugins` | `PluginA04_InsecureDesign` | 60s | **AVAILABLE** |
| 31 | `owasp_a05_misconfiguration` | A05: Security Misconfiguration Agent | `owasp_plugins` | OWASP Security Plugins | `plugins.owasp_plugins` | `PluginA05_SecurityMisconfiguration` | 45s | **AVAILABLE** |
| 32 | `owasp_a06_vulnerable_components` | A06: Vulnerable Components Agent | `owasp_plugins` | OWASP Security Plugins | `plugins.owasp_plugins` | `PluginA06_VulnerableComponents` | 60s | **AVAILABLE** |
| 33 | `owasp_a07_auth_failures` | A07: Auth & Session Failures Agent | `owasp_plugins` | OWASP Security Plugins | `plugins.owasp_plugins` | `PluginA07_AuthFailures` | 60s | **AVAILABLE** |
| 34 | `owasp_a08_integrity_failures` | A08: Software & Data Integrity Agent | `owasp_plugins` | OWASP Security Plugins | `plugins.owasp_plugins` | `PluginA08_IntegrityFailures` | 45s | **AVAILABLE** |
| 35 | `owasp_a09_logging_monitoring` | A09: Logging & Monitoring Agent | `owasp_plugins` | OWASP Security Plugins | `plugins.owasp_plugins` | `PluginA09_LoggingMonitoring` | 45s | **AVAILABLE** |
| 36 | `owasp_a10_ssrf` | A10: Server-Side Request Forgery Agent | `owasp_plugins` | OWASP Security Plugins | `plugins.owasp_plugins` | `PluginA10_SSRF` | 90s | **AVAILABLE** |
| 37 | `ghostjs_ast_engine` | GhostJS AST Code Intelligence Engine | `core_engines` | Autonomous Security Engines | `core.js_intelligence` | `GhostJsAnalyzer` | 90s | **AVAILABLE** |
| 38 | `dfir_forensics_engine` | DFIR Forensics & Log Analyzer | `core_engines` | Autonomous Security Engines | `core.forensics_engine` | `ForensicsEngine` | 60s | **AVAILABLE** |
| 39 | `blue_team_engine` | Blue Team WAF/SIEM Rule Generator | `core_engines` | Autonomous Security Engines | `core.blue_team_engine` | `BlueTeamDefenseEngine` | 45s | **AVAILABLE** |
| 40 | `waf_bypass_engine` | WAF Fingerprinting & Evasion Engine | `core_engines` | Autonomous Security Engines | `core.waf_bypass_engine` | `WAFBypassEngine` | 60s | **AVAILABLE** |
| 41 | `rea_disassembler_engine` | REA Binary Reverse Engineering Engine | `core_engines` | Autonomous Security Engines | `core.rea_engine` | `REAEngine` | 120s | **AVAILABLE** |
| 42 | `bug_bounty_hub` | Bug Bounty Scope & Policy Hub | `core_engines` | Autonomous Security Engines | `core.bug_bounty_hub` | `BugBountyHub` | 30s | **AVAILABLE** |
| 43 | `sqli_testing_engine` | SQL Injection Probing & Testing Engine | `core_engines` | Autonomous Security Engines | `core.sqli_engine` | `SQLiEngine` | 120s | **AVAILABLE** |
| 44 | `multi_injection_suite` | 27-Class Injection Probing Suite | `core_engines` | Autonomous Security Engines | `core.injection_suite` | `InjectionSuite` | 180s | **AVAILABLE** |
| 45 | `antivirus_edr_manager` | Antivirus & EDR Telemetry Manager | `core_engines` | Autonomous Security Engines | `core.antivirus_edr_manager` | `AntivirusEdrManager` | 45s | **AVAILABLE** |
| 46 | `identity_access_auditor` | Identity & Access Security Auditor | `core_engines` | Autonomous Security Engines | `core.identity_access_auditor` | `IdentityAccessAuditor` | 45s | **AVAILABLE** |
| 47 | `llm_security_testing_engine` | LLM Red Teaming & Security Auditor | `core_engines` | Autonomous Security Engines | `core.llm_security_testing` | `LLMSecurityTestingHarness` | 90s | **AVAILABLE** |
| 48 | `ai_model_trainer` | Machine Learning Model Training Engine | `core_engines` | Autonomous Security Engines | `core.ai_training` | `AITrainingEngine` | 300s | **AVAILABLE** |
| 49 | `ai_evaluation_engine` | AI Model Evaluation & Benchmark Engine | `core_engines` | Autonomous Security Engines | `core.ai_evaluation` | `AIEvaluationEngine` | 60s | **AVAILABLE** |
| 50 | `data_management_engine` | Security Dataset Management Engine | `core_engines` | Autonomous Security Engines | `core.data_management` | `DataManagementEngine` | 60s | **AVAILABLE** |
| 51 | `cyber_export_engine` | Multi-Format Cyber Export Engine | `core_engines` | Autonomous Security Engines | `core.cyber_export` | `CyberExportEngine` | 60s | **AVAILABLE** |
| 52 | `cyber_test_engine` | Autonomous Cyber Test Runner | `core_engines` | Autonomous Security Engines | `core.cyber_test` | `CyberTestEngine` | 120s | **AVAILABLE** |
| 53 | `cyber_deploy_engine` | 15-Stage Release Deployment Orchestrator | `core_engines` | Autonomous Security Engines | `core.cyber_deploy` | `CyberDeployEngine` | 120s | **AVAILABLE** |
| 54 | `post_deployment_acceptance_engine` | Post-Deployment Acceptance Engine | `core_engines` | Autonomous Security Engines | `core.post_deployment_checklist` | `PostDeploymentChecklistEngine` | 30s | **AVAILABLE** |
| 55 | `attack_surface_intel_engine` | Attack Surface Intelligence Engine | `core_engines` | Autonomous Security Engines | `core.attack_surface_intel` | `AttackSurfaceIntelligence` | 60s | **AVAILABLE** |
| 56 | `knowledge_graph_engine` | Security Knowledge Graph Engine | `core_engines` | Autonomous Security Engines | `core.knowledge_graph` | `SecurityKnowledgeGraph` | 45s | **AVAILABLE** |
| 57 | `remediation_ticket_engine` | Remediation Ticket Lifecycle Engine | `core_engines` | Autonomous Security Engines | `core.remediation_engine` | `RemediationEngine` | 45s | **AVAILABLE** |
| 58 | `risk_scoring_engine` | Defensible Risk Scoring Engine | `core_engines` | Autonomous Security Engines | `core.risk_engine` | `DefensibleRiskEngine` | 30s | **AVAILABLE** |
| 59 | `approval_gate_engine` | Human-in-the-Loop Approval Gate | `core_engines` | Autonomous Security Engines | `core.approval_engine` | `ApprovalGateEngine` | 30s | **AVAILABLE** |
| 60 | `app_security_hardener` | Application Security Hardening Engine | `core_engines` | Autonomous Security Engines | `core.app_security` | `ApplicationSecurityHardener` | 30s | **AVAILABLE** |
| 61 | `scope_enforcement_policy` | Target Scope Enforcement Policy | `core_engines` | Autonomous Security Engines | `core.scope_policy` | `ScopePolicy` | 15s | **AVAILABLE** |
| 62 | `autonomous_background_daemon` | Continuous Autonomous Monitoring Daemon | `core_engines` | Autonomous Security Engines | `core.autonomous_daemon` | `AutonomousDaemon` | 120s | **AVAILABLE** |
| 63 | `scoped_recon_assistant` | Scoped Target Reconnaissance Assistant | `core_engines` | Autonomous Security Engines | `core.scoped_recon_assistant` | `ScopedReconAssistant` | 90s | **AVAILABLE** |
| 64 | `enterprise_report_engine` | Enterprise Security Report Engine | `core_engines` | Autonomous Security Engines | `reports.enterprise_reports` | `EnterpriseReportEngine` | 60s | **AVAILABLE** |
| 65 | `vulnerability_report_generator` | Vulnerability Finding Report Generator | `core_engines` | Autonomous Security Engines | `reports.generator` | `ReportGenerator` | 45s | **AVAILABLE** |
| 66 | `queue_event_bus` | Asynchronous Event & Task Queue Bus | `core_engines` | Autonomous Security Engines | `core.queue_manager` | `queue_manager` | 30s | **AVAILABLE** |
| 67 | `llm_inference_client` | Multi-Provider LLM Gateway Client | `core_engines` | Autonomous Security Engines | `core.llm_client` | `SWALLMClient` | 60s | **AVAILABLE** |
| 68 | `security_notifier_engine` | Multi-Channel Security Alert Notifier | `core_engines` | Autonomous Security Engines | `core.notifier` | `NotificationDispatcher` | 30s | **AVAILABLE** |
| 69 | `tool_adapter_nmap` | Nmap Network Port Scanner Adapter | `tool_adapters` | Scanner & Tool Adapters | `core.scanner_integrations` | `ScannerIntegrations` | 180s | **AVAILABLE** |
| 70 | `tool_adapter_nuclei` | Nuclei Vulnerability Scanner Adapter | `tool_adapters` | Scanner & Tool Adapters | `core.scanner_integrations` | `ScannerIntegrations` | 180s | **AVAILABLE** |
| 71 | `tool_adapter_owasp_zap` | OWASP ZAP Dynamic Application Security Adapter | `tool_adapters` | Scanner & Tool Adapters | `core.scanner_integrations` | `ScannerIntegrations` | 300s | **AVAILABLE** |
| 72 | `tool_adapter_bandit` | Bandit Python SAST Security Scanner Adapter | `tool_adapters` | Scanner & Tool Adapters | `core.scanner_integrations` | `ScannerIntegrations` | 90s | **AVAILABLE** |
| 73 | `tool_adapter_trivy` | Trivy Container & Dependency Scanner Adapter | `tool_adapters` | Scanner & Tool Adapters | `core.scanner_integrations` | `ScannerIntegrations` | 120s | **AVAILABLE** |
| 74 | `tool_adapter_semgrep` | Semgrep Semantic Code Analysis Adapter | `tool_adapters` | Scanner & Tool Adapters | `core.scanner_integrations` | `ScannerIntegrations` | 120s | **AVAILABLE** |
| 75 | `tool_adapter_clamav` | ClamAV Antivirus Malware Scanner Adapter | `tool_adapters` | Scanner & Tool Adapters | `core.scanner_integrations` | `ScannerIntegrations` | 120s | **AVAILABLE** |
| 76 | `tool_adapter_wazuh` | Wazuh Host EDR & SIEM Agent Adapter | `tool_adapters` | Scanner & Tool Adapters | `core.scanner_integrations` | `ScannerIntegrations` | 90s | **AVAILABLE** |
| 77 | `tool_adapter_microsoft_defender` | Microsoft Defender Host Endpoint Adapter | `tool_adapters` | Scanner & Tool Adapters | `core.scanner_integrations` | `ScannerIntegrations` | 60s | **AVAILABLE** |
| 78 | `tool_adapter_amass` | Amass OSINT Network Mapping Adapter | `tool_adapters` | Scanner & Tool Adapters | `core.scanner_integrations` | `ScannerIntegrations` | 180s | **AVAILABLE** |
| 79 | `tool_adapter_ghostjs` | GhostJS AST Secret Scanner Adapter | `tool_adapters` | Scanner & Tool Adapters | `core.scanner_integrations` | `ScannerIntegrations` | 90s | **AVAILABLE** |
| 80 | `tool_adapter_owasp_prober` | OWASP Security Prober Adapter | `tool_adapters` | Scanner & Tool Adapters | `core.scanner_integrations` | `ScannerIntegrations` | 120s | **AVAILABLE** |
| 81 | `tool_adapter_waf_analyzer` | WAF & Perimeter Analyzer Adapter | `tool_adapters` | Scanner & Tool Adapters | `core.scanner_integrations` | `ScannerIntegrations` | 60s | **AVAILABLE** |
| 82 | `tool_adapter_param_fuzzer` | Parameter & Path Fuzzer Adapter | `tool_adapters` | Scanner & Tool Adapters | `core.scanner_integrations` | `ScannerIntegrations` | 120s | **AVAILABLE** |
| 83 | `tool_adapter_rea_disasm` | REA Binary Disassembler Adapter | `tool_adapters` | Scanner & Tool Adapters | `core.scanner_integrations` | `ScannerIntegrations` | 120s | **AVAILABLE** |
| 84 | `tool_adapter_sqlmap` | sqlmap Automatic SQLi Tool Adapter | `tool_adapters` | Scanner & Tool Adapters | `core.scanner_integrations` | `ScannerIntegrations` | 180s | **AVAILABLE** |
| 85 | `tool_adapter_swa_native` | SWA AI Autonomous Core Security Suite | `tool_adapters` | Scanner & Tool Adapters | `core.scanner_integrations` | `ScannerIntegrations` | 300s | **AVAILABLE** |

---

## 3. Five-Layer Inventory Reconciliation

The platform strictly verifies that agent counts match 100% across all five architectural layers:

1. **Source Code Inventory:** 85 implementations and manifests verified.
2. **Central Registry:** 85 agents registered in `AgentRegistry`.
3. **Database Persistence:** 85 records committed to SQLite `agents_inventory` table (`db.count_agents_inventory() == 85`).
4. **Backend REST API:** `GET /api/agents` returns 85 items; `GET /api/agents/summary` returns `{"total_discovered": 85}`.
5. **Frontend Web UI:** `loadAgents()` renders all 85 agents with pagination and tier filters.
