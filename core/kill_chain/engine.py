"""
SWA AI — Cyber Kill Chain Master Engine
Orchestrates the entire seven-stage defensive pipeline, correlation, intelligence,
AI evaluation, incident response, and executive reporting.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional

from core.kill_chain.models import (
    KillChainStageEnum,
    KillChainFinding,
    EvidenceItem,
    ThreatIndicator,
    StageAnalysisResult,
    CorrelatedAttackPath,
    KillChainOverview,
    StageStatusEnum,
)
from core.kill_chain.stages.reconnaissance import ReconnaissanceAnalyzer
from core.kill_chain.stages.weaponization import WeaponizationAnalyzer
from core.kill_chain.stages.delivery import DeliveryAnalyzer
from core.kill_chain.stages.exploitation import ExploitationAnalyzer
from core.kill_chain.stages.installation import InstallationAnalyzer
from core.kill_chain.stages.c2 import CommandAndControlAnalyzer
from core.kill_chain.stages.actions import ActionsOnObjectivesAnalyzer
from core.kill_chain.correlation import ThreatCorrelationEngine
from core.kill_chain.threat_intel import ThreatIntelligenceEngine
from core.kill_chain.controls_matrix import SecurityControlMatrix
from core.kill_chain.ai_analyzer import KillChainAIAnalyzer
from core.kill_chain.incident_manager import IncidentManager
from core.kill_chain.reporter import KillChainReportGenerator
from core.kill_chain.db import (
    save_finding,
    save_evidence,
    save_indicator,
    list_findings,
    list_evidence,
    list_indicators,
    list_incidents,
)


class CyberKillChainEngine:
    """
    Central operational orchestrator for the Lockheed Martin Cyber Kill Chain implementation.
    """

    def __init__(self):
        self.analyzers: Dict[KillChainStageEnum, Any] = {
            KillChainStageEnum.RECONNAISSANCE: ReconnaissanceAnalyzer(),
            KillChainStageEnum.WEAPONIZATION: WeaponizationAnalyzer(),
            KillChainStageEnum.DELIVERY: DeliveryAnalyzer(),
            KillChainStageEnum.EXPLOITATION: ExploitationAnalyzer(),
            KillChainStageEnum.INSTALLATION: InstallationAnalyzer(),
            KillChainStageEnum.COMMAND_AND_CONTROL: CommandAndControlAnalyzer(),
            KillChainStageEnum.ACTIONS_ON_OBJECTIVES: ActionsOnObjectivesAnalyzer(),
        }
        self.correlation_engine = ThreatCorrelationEngine()
        self.threat_intel = ThreatIntelligenceEngine()
        self.controls_matrix = SecurityControlMatrix()
        self.ai_analyzer = KillChainAIAnalyzer()
        self.incident_manager = IncidentManager()
        self.reporter = KillChainReportGenerator()

    def analyze_telemetry(self, telemetry: Dict[str, Any], target: Optional[str] = None) -> Dict[str, Any]:
        """
        Executes analysis across all seven stages against supplied telemetry or scan data.
        Persists findings, evidence, and threat indicators in the database.
        """
        tgt = target or telemetry.get("target") or "127.0.0.1"
        telemetry["target"] = tgt

        stage_results: Dict[str, StageAnalysisResult] = {}
        all_new_findings: List[KillChainFinding] = []
        all_new_evidence: List[EvidenceItem] = []
        all_new_indicators: List[ThreatIndicator] = []

        for stage_enum, analyzer in self.analyzers.items():
            res = analyzer.analyze(telemetry)
            stage_results[stage_enum.value] = res

            for f in res.findings:
                save_finding(f)
                all_new_findings.append(f)

            for ev in res.evidence:
                save_evidence(ev)
                all_new_evidence.append(ev)

            for ind in res.indicators:
                save_indicator(ind)
                all_new_indicators.append(ind)

        # Run correlation across all persistent findings
        all_db_findings = list_findings()
        all_db_evidence = list_evidence()
        all_db_indicators = list_indicators()

        attack_paths = self.correlation_engine.correlate(
            findings=all_db_findings,
            evidence=all_db_evidence,
            indicators=all_db_indicators,
            target_asset=tgt,
        )

        overview = self.get_overview()

        return {
            "status": "COMPLETED",
            "target": tgt,
            "new_findings_count": len(all_new_findings),
            "new_evidence_count": len(all_new_evidence),
            "stage_results": {k: v.dict() for k, v in stage_results.items()},
            "attack_paths": [p.dict() for p in attack_paths],
            "overview": overview.dict(),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

    def get_overview(self) -> KillChainOverview:
        """
        Computes the complete SOC dashboard overview metrics.
        """
        all_findings = list_findings()
        all_ev = list_evidence()
        all_inc = list_incidents()
        coverage = self.controls_matrix.get_matrix()

        # Compute status and summary per stage
        stage_summaries = {}
        for stage_enum in self.analyzers.keys():
            s_val = stage_enum.value
            s_findings = [f for f in all_findings if f.stage == stage_enum]
            analyzer = self.analyzers[stage_enum]
            st = analyzer.determine_stage_status(s_findings)
            max_risk = max([f.risk_score for f in s_findings], default=0.0)

            stage_summaries[s_val] = {
                "stage": s_val,
                "title": analyzer.title,
                "number": analyzer.stage_number,
                "status": st.value,
                "findings_count": len(s_findings),
                "risk_score": max_risk,
                "critical": sum(1 for f in s_findings if f.severity.value == "CRITICAL"),
                "high": sum(1 for f in s_findings if f.severity.value == "HIGH"),
                "medium": sum(1 for f in s_findings if f.severity.value == "MEDIUM"),
                "low": sum(1 for f in s_findings if f.severity.value == "LOW"),
                "detection_capabilities": analyzer.detection_capabilities,
            }

        avg_risk = round(sum([f.risk_score for f in all_findings]) / max(1, len(all_findings)), 1)
        avg_conf = round(sum([f.confidence_score for f in all_findings]) / max(1, len(all_findings)), 1)

        attack_paths = self.correlation_engine.correlate(
            findings=all_findings,
            evidence=all_ev,
            indicators=list_indicators(),
        )

        return KillChainOverview(
            total_findings=len(all_findings),
            total_evidence_count=len(all_ev),
            active_incidents_count=sum(1 for i in all_inc if i.status.value not in ("CLOSED", "REMEDIATED")),
            overall_risk_score=avg_risk,
            overall_confidence_score=avg_conf,
            stage_summaries=stage_summaries,
            control_coverage_percentage=coverage.get("overall_coverage_pct", 0.0),
            attack_paths=attack_paths,
            system_health={"status": "HEALTHY", "version": "SWA-KC-2.0", "engine": "Operational"},
            updated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )

    def get_stage_detail(self, stage_id: str) -> Optional[Dict[str, Any]]:
        """Returns deep-dive telemetry, findings, evidence, controls, and playbooks for a specific stage."""
        try:
            stage_enum = KillChainStageEnum(stage_id.lower())
        except Exception:
            return None

        analyzer = self.analyzers.get(stage_enum)
        if not analyzer:
            return None

        findings = list_findings(stage=stage_enum.value)
        evidence = list_evidence(stage=stage_enum.value)
        indicators = list_indicators(stage=stage_enum.value)
        playbook = self.incident_manager.get_playbook_for_stage(stage_enum.value)
        controls = [c for c in self.controls_matrix.get_matrix()["matrix"].get(stage_enum.value, {}).values()]

        return {
            "stage": stage_enum.value,
            "title": analyzer.title,
            "stage_number": analyzer.stage_number,
            "objective": analyzer.objective,
            "mitre_tactic": analyzer.mitre_tactic,
            "detection_capabilities": analyzer.detection_capabilities,
            "status": analyzer.determine_stage_status(findings).value,
            "findings": [f.dict() for f in findings],
            "evidence": [e.dict() for e in evidence],
            "indicators": [i.dict() for i in indicators],
            "controls": analyzer.default_controls,
            "playbook": playbook,
        }

    def seed_demonstration_scenario(self, target: str = "127.0.0.1") -> Dict[str, Any]:
        """
        Pre-loads an authentic multi-stage defensive investigation scenario across all 7 stages
        to allow instant verification and testing.
        """
        demo_telemetry = {
            "target": target,
            # Stage 1: Reconnaissance
            "subdomains": [f"api.{target}", f"admin.{target}", f"vpn.{target}", f"dev.{target}"],
            "open_ports": [80, 443, 22, 3306, 8080],
            "ssl": {"expired": False, "weak_ciphers": True, "grade": "B"},
            # Stage 2: Weaponization
            "files": [
                {
                    "filename": "invoice_update.exe",
                    "hash": "44d88612fea8a8f36de82e1278abb02f",
                    "reputation_score": 92.0,
                    "threat_actor": "FIN7 Cybercrime Syndicate",
                    "malware_family": "Carbanak / Cobalt Drop",
                    "yara_match": "APT.Weaponized.Stager.Generic",
                }
            ],
            "office_documents": [
                {
                    "filename": "Q4_Financial_Audit.docm",
                    "has_vba_macro": True,
                    "macro_details": "AutoOpen macro spawning powershell dropper script",
                }
            ],
            # Stage 3: Delivery
            "emails": [
                {
                    "from": "payroll-alert@external-secure-hr.net",
                    "to": f"analyst@{target}",
                    "subject": "Urgent: Mandatory Direct Deposit Audit",
                    "spf": "FAIL",
                    "dmarc": "FAIL",
                    "attachments": ["invoice_update.exe"],
                }
            ],
            "urls": [
                {"url": "https://suspicious-payload-cdn.io/gate.php", "status_code": 200, "reputation_score": 88.0, "is_malicious": True}
            ],
            # Stage 4: Exploitation
            "findings": [
                {
                    "title": "SQL Injection in User Authentication Endpoint",
                    "category": "Injection / OWASP A03",
                    "tool_source": "SWA OWASP Hunter",
                    "severity": "CRITICAL",
                    "cwe": "CWE-89",
                    "cve": "CVE-2023-34362",
                    "endpoint": "/api/v1/auth/login",
                    "description": "Unsanitized user parameters allow arbitrary SQL execution.",
                    "evidence": "Payload: admin' OR '1'='1 injected; database returned SQL Server error.",
                    "solution": "Use parameterized queries and prepared statements.",
                },
                {
                    "title": "Reflected Cross-Site Scripting (XSS) in Search Query",
                    "category": "Web Security",
                    "tool_source": "SWA Web Scanner",
                    "severity": "MEDIUM",
                    "cwe": "CWE-79",
                    "endpoint": "/search?q=",
                    "description": "User input reflected in response without HTML context escaping.",
                    "evidence": "<script>alert(1)</script> echoed cleanly.",
                    "solution": "Apply contextual output encoding.",
                }
            ],
            "waf_alerts": [
                {"rule_id": "WAF-941100", "client_ip": "203.0.113.42", "payload": "' UNION SELECT username, password FROM users--", "uri": "/api/login"}
            ],
            # Stage 5: Installation
            "processes": [
                {
                    "name": "powershell.exe",
                    "pid": 4812,
                    "parent_process": "nginx.exe",
                    "cmdline": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQAgA==",
                }
            ],
            "persistence": [
                {
                    "name": "WindowsSecurityUpdater",
                    "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "target": "C:\\Users\\Public\\updater.exe",
                }
            ],
            # Stage 6: C2
            "network_flows": [
                {
                    "src_ip": target,
                    "dst_ip": "198.51.100.23",
                    "dst_port": 8443,
                    "protocol": "TCP",
                    "count": 48,
                    "interval_seconds": 60,
                    "jitter_pct": 5,
                    "reputation_score": 95.0,
                    "is_c2": True,
                    "domain": "telemetry-sync-internal.com",
                }
            ],
            "dns_tunneling": [
                {"query": "a9f8c47b12d.tunnel.exfil-data.net", "entropy": 4.6, "type": "TXT"}
            ],
            # Stage 7: Actions on Objectives
            "exfiltration": [
                {
                    "bytes_transferred": 18_450_000,
                    "destination": "https://s3.amazonaws.com/shadow-bucket-drop",
                    "channel": "HTTPS POST",
                    "files": ["customer_pii_dump.tar.gz", "master_credentials.kdbx"],
                    "is_exfil": True,
                }
            ],
            "ransomware": [
                {"type": "VSS_DELETION", "details": "vssadmin.exe delete shadows /all /quiet", "path": "System Volume Information"}
            ],
            "lateral_movement": [
                {"protocol": "SMB/PsExec", "user": "svc_backup", "target_host": "10.0.0.15"}
            ],
        }

        # Analyze telemetry
        result = self.analyze_telemetry(demo_telemetry, target=target)

        # Create demo incident linking all stages
        all_f = list_findings()
        self.incident_manager.create_incident(
            title=f"Multi-Stage Cyber Kill Chain Intrusion Detected on {target}",
            severity="CRITICAL",
            assigned_analyst="SecOps Lead",
            affected_assets=[target, "10.0.0.15"],
            description="Full-spectrum adversary campaign spanning initial reconnaissance, weaponization, delivery, exploitation, persistence, C2 beaconing, and unauthorized data exfiltration.",
            stages_involved=[s.value for s in KillChainStageEnum],
            linked_findings=[f.id for f in all_f[:10]],
            linked_evidence=[e.id for e in list_evidence()[:10]],
        )

        return result


# Singleton instance for platform-wide use
kill_chain_engine = CyberKillChainEngine()
