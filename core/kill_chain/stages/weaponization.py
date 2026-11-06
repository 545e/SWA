"""
SWA AI — Cyber Kill Chain: Stage 02 — Weaponization
Objective: Identify intelligence associated with malicious payload preparation and weaponized artifacts.
Note: Weaponization typically takes place within adversary infrastructure.
Defensive analysis correlates file hashes, CVEs, YARA signatures, and malware metadata.
"""

from __future__ import annotations

import datetime
import hashlib
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


class WeaponizationAnalyzer(BaseStageAnalyzer):
    stage = KillChainStageEnum.WEAPONIZATION
    stage_number = 2
    title = "Weaponization"
    objective = "Identify intelligence associated with malicious payload preparation, exploit craft, and weaponized artifacts."
    mitre_tactic = "TA0042 - Resource Development"
    detection_capabilities = [
        "Cryptographic File Hash Identification (MD5, SHA-1, SHA-256)",
        "Malware Reputation & Threat Intelligence Correlation",
        "YARA Rule Signature & Heuristic Pattern Matching",
        "CVE Exploit Payload & PoC Fingerprinting",
        "PE Header & Obfuscation Static Telemetry Analysis",
        "Malicious Document / Office Macro Telemetry Inspection",
        "Threat Actor & Known Malware Family Attribution",
    ]
    default_controls = [
        {"name": "Endpoint Static File Inspection & YARA", "capability": "Detect", "tool": "SWA REA / Antivirus Engine"},
        {"name": "Pre-Execution Binary Emulation Sandbox", "capability": "Detect", "tool": "Sandbox Isolation"},
        {"name": "Application Whitelisting / AppLocker Policy", "capability": "Deny", "tool": "Host Policy Engine"},
        {"name": "Secure Coding & Input Sanitization Gates", "capability": "Deny", "tool": "CI/CD Security Gate"},
        {"name": "Threat Intelligence IOC Pre-Emptive Blocklist", "capability": "Disrupt", "tool": "Firewall Threat Feed"},
    ]

    def analyze(self, telemetry: Dict[str, Any], asset_context: Optional[Dict[str, Any]] = None) -> StageAnalysisResult:
        findings: List[KillChainFinding] = []
        evidence_list: List[EvidenceItem] = []
        indicators: List[ThreatIndicator] = []
        assets_seen = set()

        target = telemetry.get("target") or telemetry.get("host") or "127.0.0.1"
        assets_seen.add(target)
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # 1. Analyze Artifacts / File Hashes
        files = telemetry.get("files") or telemetry.get("artifacts", [])
        for f_item in files:
            fname = f_item.get("filename") or f_item.get("name") or "unknown_artifact"
            fhash = f_item.get("sha256") or f_item.get("hash") or f_item.get("md5")
            if not fhash and f_item.get("content"):
                fhash = hashlib.sha256(f_item["content"].encode("utf-8", errors="ignore")).hexdigest()

            if fhash:
                ev_hash = self.create_evidence(
                    artifact_type="PAYLOAD_HASH_IDENTIFICATION",
                    raw_data=f"Identified file: {fname} with digest: {fhash}",
                    normalized_data={"filename": fname, "hash": fhash, "metadata": f_item.get("metadata", {})},
                    affected_asset=target,
                    source_tool="SWA Forensics / REA Engine",
                    evidence_quality=0.98,
                )
                evidence_list.append(ev_hash)

                # Check known threat indicators / reputation
                rep = f_item.get("reputation_score", 0.0)
                is_known_malware = rep >= 70.0 or f_item.get("is_malicious", False)
                actor = f_item.get("threat_actor") or "Unattributed Threat Actor"
                family = f_item.get("malware_family") or "Trojan/Staged-Payload"

                if is_known_malware or f_item.get("yara_match"):
                    risk = self.calculate_risk(impact_weight=9.0, likelihood=0.85, exploitability=1.3)
                    conf_level, conf_score = self.calculate_confidence(evidence_quality=0.98, source_reliability=0.92, corroboration_count=2)
                    yara_rule = f_item.get("yara_match") or "Heuristic.WeaponizedPayload.Generic"
                    finding = KillChainFinding(
                        id=f"kc_weap_{uuid.uuid4().hex[:8]}",
                        title=f"Weaponized Malicious Artifact Detected: {fname} ({family})",
                        stage=self.stage,
                        severity=SeverityEnum.CRITICAL if rep >= 85.0 else SeverityEnum.HIGH,
                        mitre_technique_id="T1587.001",
                        mitre_tactic=self.mitre_tactic,
                        affected_host=target,
                        affected_endpoint=fname,
                        description=(
                            f"Static defensive inspection correlated file '{fname}' (SHA256: {fhash}) "
                            f"with known weaponized toolchain '{family}' attributed to {actor}. "
                            f"Matched YARA rule: {yara_rule}."
                        ),
                        evidence=f"File hash: {fhash}\nYARA Signature: {yara_rule}\nReputation Score: {rep}/100",
                        evidence_ids=[ev_hash.id],
                        detection_source="SWA REA / Threat Intel Engine",
                        confidence_level=conf_level,
                        confidence_score=conf_score,
                        risk_score=risk,
                        remediation="Quarantine file immediately, calculate full entropy, and block hash at network perimeter.",
                        references=["https://attack.mitre.org/techniques/T1587/001/"],
                    )
                    findings.append(finding)

                    indicators.append(
                        ThreatIndicator(
                            id=f"ind_weap_{uuid.uuid4().hex[:8]}",
                            indicator_type="SHA256" if len(fhash) == 64 else "HASH",
                            value=fhash,
                            stage=self.stage,
                            threat_actor=actor,
                            malware_family=family,
                            reputation_score=rep if rep > 0 else 85.0,
                            provider=f_item.get("provider", "SWA YARA/Static Engine"),
                            source_attribution="Artifact Static Triage",
                            verified=True,
                            details={"filename": fname, "yara": yara_rule},
                        )
                    )

        # 2. Analyze Document / Macro Telemetry
        docs = telemetry.get("office_documents", [])
        for doc in docs:
            if doc.get("has_vba_macro") or doc.get("has_powershell_embed"):
                ev_doc = self.create_evidence(
                    artifact_type="WEAPONIZED_DOCUMENT_METADATA",
                    raw_data=f"Document {doc.get('filename')} contains embedded macro/script payload.",
                    normalized_data=doc,
                    affected_asset=target,
                    source_tool="SWA Static Document Inspector",
                )
                evidence_list.append(ev_doc)
                risk = self.calculate_risk(impact_weight=8.0, likelihood=0.75, exposure=1.2)
                conf_level, conf_score = self.calculate_confidence(evidence_quality=0.92, source_reliability=0.88, corroboration_count=1)
                findings.append(
                    KillChainFinding(
                        id=f"kc_weap_{uuid.uuid4().hex[:8]}",
                        title=f"Weaponized Document with Automated Macro/Script Payload: {doc.get('filename')}",
                        stage=self.stage,
                        severity=SeverityEnum.HIGH,
                        mitre_technique_id="T1587.004",
                        mitre_tactic=self.mitre_tactic,
                        affected_host=target,
                        affected_endpoint=doc.get("filename"),
                        description=f"Static analysis discovered embedded VBA macro or PowerShell dropper payload inside {doc.get('filename')}.",
                        evidence=str(doc.get("macro_details", "Embedded AutoOpen macro detected")),
                        evidence_ids=[ev_doc.id],
                        detection_source="SWA Static Document Inspector",
                        confidence_level=conf_level,
                        confidence_score=conf_score,
                        risk_score=risk,
                        remediation="Enforce group policy disabling all unsigned Office macros and block macro-enabled formats at email gateway.",
                        references=["https://attack.mitre.org/techniques/T1587/004/"],
                    )
                )

        status = self.determine_stage_status(findings)
        summary = (
            f"Weaponization analysis performed. Inspected {len(files)} binary artifacts and {len(docs)} documents. "
            f"Correlated {len(findings)} weaponized artifacts."
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
                "Deploy Endpoint Detection & Response (EDR) with real-time heuristic inspection.",
                "Enforce host application control and strict binary signature verification.",
                "Integrate continuous threat intelligence IOC feeds into boundary defenses.",
            ],
            summary=summary,
            assessed_at=now_utc,
        )
