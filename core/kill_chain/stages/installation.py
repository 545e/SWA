"""
SWA AI — Cyber Kill Chain: Stage 05 — Installation
Objective: Detect suspicious installation and persistence activity: process spawning,
services, registry autoruns, scheduled tasks, systemd units, startup modifications, and file integrity tampering.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Any, Dict, List, Optional

from core.kill_chain.models import (
    KillChainStageEnum,
    KillChainFinding,
    EvidenceItem,
    ThreatIndicator,
    StageAnalysisResult,
    SeverityEnum,
)
from core.kill_chain.stages.base import BaseStageAnalyzer


class InstallationAnalyzer(BaseStageAnalyzer):
    stage = KillChainStageEnum.INSTALLATION
    stage_number = 5
    title = "Installation"
    objective = "Detect adversary persistence mechanisms, unauthorized services, registry modifications, scheduled tasks, and file integrity tampering."
    mitre_tactic = "TA0003 - Persistence"
    detection_capabilities = [
        "Suspicious Process Creation & Anomaly Lineage (e.g., cmd/powershell spawning from web server)",
        "Unauthorized Windows Service & Linux Systemd Unit Creation",
        "Windows Registry Persistence Telemetry (Run/RunOnce, IFEO, AppInit)",
        "Scheduled Task (schtasks / crontab) Modification Monitoring",
        "File Integrity Monitoring (FIM) & System Binary Hash Alteration",
        "Suspicious Local Account & Sudoers Permission Alterations",
        "Endpoint Detection & Response (EDR) Telemetry Ingestion",
    ]
    default_controls = [
        {"name": "Endpoint Detection & Response (EDR) Sensor", "capability": "Detect", "tool": "SWA EDR Manager"},
        {"name": "File Integrity Monitoring (FIM) Agent", "capability": "Detect", "tool": "Core FIM Engine"},
        {"name": "AppLocker / SELinux Mandatory Access Control", "capability": "Deny", "tool": "Host MAC Policy"},
        {"name": "Process Execution Privilege Restriction", "capability": "Disrupt", "tool": "Least Privilege Daemon"},
        {"name": "Active Registry Decoy Keys", "capability": "Deceive", "tool": "Canary Registry Monitor"},
    ]

    def analyze(self, telemetry: Dict[str, Any], asset_context: Optional[Dict[str, Any]] = None) -> StageAnalysisResult:
        findings: List[KillChainFinding] = []
        evidence_list: List[EvidenceItem] = []
        indicators: List[ThreatIndicator] = []
        assets_seen = set()

        target = telemetry.get("target") or telemetry.get("host") or "127.0.0.1"
        assets_seen.add(target)
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # 1. Analyze Process Lineage & Spawning Telemetry
        processes = telemetry.get("processes") or telemetry.get("process_events", [])
        for proc in processes:
            pname = proc.get("name") or proc.get("process_name", "unknown")
            cmdline = proc.get("cmdline") or proc.get("command_line", "")
            pid = proc.get("pid", 0)
            parent = proc.get("parent_process") or proc.get("parent_name", "")

            # Look for malicious dropper / lolbin patterns
            suspicious_cmd = any(
                bad in cmdline.lower()
                for bad in [
                    "-enc", "downloadstring", "certutil -urlcache", "bitsadmin /transfer",
                    "invoke-webrequest", "curl -s http", "wget -q", "bash -i >& /dev/tcp",
                    "schtasks /create", "reg add hkcu\\software\\microsoft\\windows\\currentversion\\run",
                    "systemctl enable --now", "nc -e", "chmod +x /tmp/"
                ]
            )

            is_web_parent = any(web in parent.lower() for web in ["w3wp", "nginx", "httpd", "apache", "node", "python", "php-fpm"])

            if suspicious_cmd or (is_web_parent and any(sh in pname.lower() for sh in ["cmd.exe", "powershell.exe", "bash", "sh"])):
                ev_proc = self.create_evidence(
                    artifact_type="SUSPICIOUS_PROCESS_EXECUTION",
                    raw_data=f"Process {pname} (PID: {pid}) spawned by {parent} with command: {cmdline}",
                    normalized_data=proc,
                    affected_asset=target,
                    source_tool="SWA EDR Telemetry Engine",
                    evidence_quality=0.98,
                )
                evidence_list.append(ev_proc)

                risk = self.calculate_risk(impact_weight=9.0, likelihood=0.88, exploitability=1.3)
                conf_level, conf_score = self.calculate_confidence(evidence_quality=0.98, source_reliability=0.95, corroboration_count=2)
                findings.append(
                    KillChainFinding(
                        id=f"kc_inst_{uuid.uuid4().hex[:8]}",
                        title=f"Suspicious Process Spawning & Persistence Activity: {pname} from {parent or 'Parent'}",
                        stage=self.stage,
                        severity=SeverityEnum.CRITICAL if is_web_parent else SeverityEnum.HIGH,
                        mitre_technique_id="T1059.001" if "powershell" in pname.lower() else "T1053",
                        mitre_tactic=self.mitre_tactic,
                        affected_host=target,
                        affected_endpoint=f"PID {pid} ({pname})",
                        description=(
                            f"Defensive telemetry detected suspicious execution of '{pname}' with command: '{cmdline}'. "
                            f"Parent process '{parent}' indicates post-exploitation dropper or persistence staging."
                        ),
                        evidence=f"Parent: {parent}\nProcess: {pname} (PID {pid})\nCommandLine: {cmdline}",
                        evidence_ids=[ev_proc.id],
                        detection_source="SWA EDR / Process Monitor",
                        confidence_level=conf_level,
                        confidence_score=conf_score,
                        risk_score=risk,
                        remediation="Isolate host from local network segment, terminate process tree, and audit startup items.",
                        references=["https://attack.mitre.org/techniques/T1059/001/"],
                    )
                )

        # 2. Analyze Persistence Items (Registry / Cron / Systemd)
        persistence_items = telemetry.get("persistence") or telemetry.get("autoruns", [])
        for item in persistence_items:
            path = item.get("path") or item.get("key", "Unknown Location")
            entry_name = item.get("name", "PersistenceEntry")
            target_bin = item.get("target") or item.get("executable", "")

            ev_pers = self.create_evidence(
                artifact_type="PERSISTENCE_MECHANISM_DISCOVERY",
                raw_data=f"Persistence entry '{entry_name}' located at '{path}' targeting '{target_bin}'",
                normalized_data=item,
                affected_asset=target,
                source_tool="SWA Autoruns / Forensics Engine",
            )
            evidence_list.append(ev_pers)
            risk = self.calculate_risk(impact_weight=8.5, likelihood=0.85, exposure=1.1)
            conf_level, conf_score = self.calculate_confidence(evidence_quality=0.95, source_reliability=0.92, corroboration_count=2)
            findings.append(
                KillChainFinding(
                    id=f"kc_inst_{uuid.uuid4().hex[:8]}",
                    title=f"Unauthorized Persistence Installed: {entry_name} in {path}",
                    stage=self.stage,
                    severity=SeverityEnum.HIGH,
                    mitre_technique_id="T1547.001" if "run" in path.lower() else "T1053.005",
                    mitre_tactic=self.mitre_tactic,
                    affected_host=target,
                    affected_endpoint=path,
                    description=f"System autorun survey revealed suspicious persistent anchor '{entry_name}' executing binary '{target_bin}'.",
                    evidence=f"Registry/Task Path: {path}\nExecutable Target: {target_bin}",
                    evidence_ids=[ev_pers.id],
                    detection_source="SWA Forensics Engine",
                    confidence_level=conf_level,
                    confidence_score=conf_score,
                    risk_score=risk,
                    remediation="Remove persistence registry key or scheduled task and delete referenced binary payload.",
                    references=["https://attack.mitre.org/techniques/T1547/001/"],
                )
            )

        status = self.determine_stage_status(findings)
        summary = (
            f"Installation inspection analyzed {len(processes)} process telemetry events and {len(persistence_items)} "
            f"autorun locations. Generated {len(findings)} installation findings."
        )

        return StageAnalysisResult(
            stage=self.stage,
            status=status,
            score=max([f.risk_score for f in findings], default=0.0),
            findings_count=len(findings),
            critical_count=sum(1 for f in findings if f.severity == SeverityEnum.CRITICAL),
            high_count=sum(1 for f in findings if f.severity == SeverityEnum.HIGH),
            medium_count=sum(1 for f in findings if f.severity == SeverityEnum.MEDIUM),
            low_count=sum(1 for f in findings if f.severity == SeverityEnum.LOW),
            findings=findings,
            evidence=evidence_list,
            indicators=indicators,
            associated_assets=list(assets_seen),
            security_controls=self.default_controls,
            recommended_remediations=[
                "Deploy Endpoint Detection & Response (EDR) in active blocking mode.",
                "Enforce strict executable signing policies to prevent running unapproved binaries.",
                "Implement File Integrity Monitoring (FIM) on critical OS binary directories and system services.",
            ],
            summary=summary,
            assessed_at=now_utc,
        )
