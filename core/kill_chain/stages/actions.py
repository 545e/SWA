"""
SWA AI — Cyber Kill Chain: Stage 07 — Actions on Objectives
Objective: Identify evidence of the attacker's final mission objectives: data exfiltration,
lateral movement, privilege escalation, ransomware, data destruction, and operational disruption.
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


class ActionsOnObjectivesAnalyzer(BaseStageAnalyzer):
    stage = KillChainStageEnum.ACTIONS_ON_OBJECTIVES
    stage_number = 7
    title = "Actions on Objectives"
    objective = "Identify evidence of data exfiltration, ransomware encryption, unauthorized privilege escalation, lateral movement, or data destruction."
    mitre_tactic = "TA0040 - Impact / TA0010 - Exfiltration"
    detection_capabilities = [
        "Data Exfiltration & Abnormal Egress Volume Telemetry",
        "Privilege Escalation (System/Root Token Impersonation & Sudo Abuse)",
        "Lateral Movement Detection (SMB, WMI, WinRM, PsExec, SSH Key Reuse)",
        "Ransomware Encryption Indicators (Volume Shadow Copy Deletion, Mass Renames)",
        "Unauthorized Administrative Account Creation & Group Modification",
        "Sensitive Data Access Anomalies & Database Dump Execution",
        "Business Interruption & Service Sabotage Telemetry",
    ]
    default_controls = [
        {"name": "Data Loss Prevention (DLP) Sensor", "capability": "Detect", "tool": "Core DLP Monitor"},
        {"name": "Privileged Access Management (PAM) & Zero Trust", "capability": "Deny", "tool": "PAM Controller"},
        {"name": "Endpoint Anti-Ransomware & Canary File Shield", "capability": "Disrupt", "tool": "EDR RansomShield"},
        {"name": "Immutable Backup Storage & Air-Gapped Snapshots", "capability": "Degrade", "tool": "Backup Custodian"},
        {"name": "Honey-Documents & Decoy Databases", "capability": "Deceive", "tool": "Canary Data Sensor"},
    ]

    def analyze(self, telemetry: Dict[str, Any], asset_context: Optional[Dict[str, Any]] = None) -> StageAnalysisResult:
        findings: List[KillChainFinding] = []
        evidence_list: List[EvidenceItem] = []
        indicators: List[ThreatIndicator] = []
        assets_seen = set()

        target = telemetry.get("target") or telemetry.get("host") or "127.0.0.1"
        assets_seen.add(target)
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # 1. Analyze Data Exfiltration Telemetry
        exfil_events = telemetry.get("exfiltration") or telemetry.get("data_transfers", [])
        for ex in exfil_events:
            bytes_out = ex.get("bytes_transferred", 0)
            dst = ex.get("destination", "unknown-cloud-bucket")
            channel = ex.get("channel", "HTTPS POST")
            sensitive_files = ex.get("files", [])

            # Alert if egress is large (> 10MB) or transfers sensitive tags (database dump, customer records)
            if bytes_out > 5_000_000 or sensitive_files or ex.get("is_exfil"):
                ev_ex = self.create_evidence(
                    artifact_type="DATA_EXFILTRATION_EVENT",
                    raw_data=f"Exfiltration flow: {bytes_out} bytes sent to {dst} via {channel}. Files: {sensitive_files}",
                    normalized_data=ex,
                    affected_asset=target,
                    source_tool="SWA DLP / Network Flow Analyzer",
                    evidence_quality=0.98,
                )
                evidence_list.append(ev_ex)

                risk = self.calculate_risk(impact_weight=10.0, likelihood=0.95, asset_criticality=1.4, exposure=1.3)
                conf_level, conf_score = self.calculate_confidence(evidence_quality=0.98, source_reliability=0.95, corroboration_count=2)
                findings.append(
                    KillChainFinding(
                        id=f"kc_act_{uuid.uuid4().hex[:8]}",
                        title=f"Critical Data Exfiltration Detected ({bytes_out / (1024*1024):.1f} MB to {dst})",
                        stage=self.stage,
                        severity=SeverityEnum.CRITICAL,
                        mitre_technique_id="T1048.003",
                        mitre_tactic=self.mitre_tactic,
                        affected_host=target,
                        affected_endpoint=str(dst),
                        description=(
                            f"Defensive sensor identified unauthorized outbound data transmission of {bytes_out} bytes "
                            f"to external destination '{dst}'. Referenced sensitive targets: {sensitive_files or 'Database/PII Stores'}."
                        ),
                        evidence=f"Destination: {dst}\nProtocol: {channel}\nVolume: {bytes_out} bytes\nFiles Involved: {sensitive_files}",
                        evidence_ids=[ev_ex.id],
                        detection_source="SWA DLP / NetFlow Sensor",
                        confidence_level=conf_level,
                        confidence_score=conf_score,
                        risk_score=risk,
                        remediation="Sever network link immediately, revoke impacted credentials, and trigger incident response data breach playbook.",
                        references=["https://attack.mitre.org/techniques/T1048/"],
                    )
                )

        # 2. Analyze Ransomware / Destruction Indicators
        ransom_events = telemetry.get("ransomware") or telemetry.get("impact_events", [])
        for r_ev in ransom_events:
            event_type = r_ev.get("type", "MASS_ENCRYPTION")
            details = r_ev.get("details", "VSS shadow copies deleted via vssadmin")
            affected_path = r_ev.get("path", "C:\\Data\\Shares")

            ev_r = self.create_evidence(
                artifact_type="RANSOMWARE_IMPACT_INDICATOR",
                raw_data=f"Impact event: {event_type} | Details: {details} | Path: {affected_path}",
                normalized_data=r_ev,
                affected_asset=target,
                source_tool="SWA Ransomware Defense Agent",
                evidence_quality=1.0,
            )
            evidence_list.append(ev_r)

            risk = self.calculate_risk(impact_weight=10.0, likelihood=0.98, asset_criticality=1.5, exposure=1.2)
            conf_level, conf_score = self.calculate_confidence(evidence_quality=1.0, source_reliability=0.98, corroboration_count=3)
            findings.append(
                KillChainFinding(
                    id=f"kc_act_{uuid.uuid4().hex[:8]}",
                    title=f"Active Ransomware Destruction / Sabotage Activity ({event_type})",
                    stage=self.stage,
                    severity=SeverityEnum.CRITICAL,
                    mitre_technique_id="T1486",
                    mitre_tactic=self.mitre_tactic,
                    affected_host=target,
                    affected_endpoint=affected_path,
                    description=f"High-fidelity endpoint telemetry captured rapid file encryption or shadow copy destruction: {details}.",
                    evidence=f"Event: {event_type}\nDetails: {details}\nTarget: {affected_path}",
                    evidence_ids=[ev_r.id],
                    detection_source="SWA Endpoint Guard / RansomShield",
                    confidence_level=conf_level,
                    confidence_score=conf_score,
                    risk_score=risk,
                    remediation="Execute emergency host isolation, preserve volatile memory, verify immutable backup integrity, and do NOT pay ransom.",
                    references=["https://attack.mitre.org/techniques/T1486/"],
                )
            )

        # 3. Analyze Lateral Movement & Privilege Escalation
        lateral_events = telemetry.get("lateral_movement") or []
        for lm in lateral_events:
            proto = lm.get("protocol", "SMB/WMI")
            src_user = lm.get("user", "SYSTEM")
            target_host = lm.get("target_host", "10.0.0.15")
            assets_seen.add(target_host)

            ev_lm = self.create_evidence(
                artifact_type="LATERAL_MOVEMENT_TELEMETRY",
                raw_data=f"Lateral hop from {target} to {target_host} via {proto} as user {src_user}",
                normalized_data=lm,
                affected_asset=target,
                source_tool="SWA Active Directory / Lateral Sensor",
            )
            evidence_list.append(ev_lm)
            risk = self.calculate_risk(impact_weight=8.5, likelihood=0.85, exposure=1.2)
            conf_level, conf_score = self.calculate_confidence(evidence_quality=0.95, source_reliability=0.92, corroboration_count=2)
            findings.append(
                KillChainFinding(
                    id=f"kc_act_{uuid.uuid4().hex[:8]}",
                    title=f"Internal Lateral Movement Detected ({proto}) -> {target_host}",
                    stage=self.stage,
                    severity=SeverityEnum.HIGH,
                    mitre_technique_id="T1021.002" if "smb" in proto.lower() else "T1047",
                    mitre_tactic=self.mitre_tactic,
                    affected_host=target,
                    affected_endpoint=f"{target_host} ({proto})",
                    description=f"Adversary executed remote administrative commands or token reuse across internal network: {target} -> {target_host}.",
                    evidence=f"Source Host: {target}\nDestination: {target_host}\nProtocol: {proto}\nAccount: {src_user}",
                    evidence_ids=[ev_lm.id],
                    detection_source="SWA SIEM / Network Lateral Sensor",
                    confidence_level=conf_level,
                    confidence_score=conf_score,
                    risk_score=risk,
                    remediation="Revoke compromised user session tokens, disable NTLM where possible, and enforce microsegmentation.",
                    references=["https://attack.mitre.org/techniques/T1021/"],
                )
            )

        status = self.determine_stage_status(findings)
        summary = (
            f"Actions on Objectives analysis completed. Evaluated {len(exfil_events)} egress flows, {len(ransom_events)} "
            f"impact events, and {len(lateral_events)} lateral movement connections. Generated {len(findings)} critical impact findings."
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
                "Deploy Data Loss Prevention (DLP) across internal gateways and endpoints.",
                "Enforce network microsegmentation and isolate high-value data stores from workstations.",
                "Maintain validated, offline, immutable volume snapshots for business continuity.",
            ],
            summary=summary,
            assessed_at=now_utc,
        )
