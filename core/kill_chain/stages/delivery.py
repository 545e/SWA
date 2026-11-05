"""
SWA AI — Cyber Kill Chain: Stage 03 — Delivery
Objective: Analyze potential malicious content delivery mechanisms, including phishing,
malicious URLs, email attachments, web gateway events, and proxy telemetry.
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


class DeliveryAnalyzer(BaseStageAnalyzer):
    stage = KillChainStageEnum.DELIVERY
    stage_number = 3
    title = "Delivery"
    objective = "Analyze malicious payload transmission mechanisms: email, phishing, web drive-by, USB, and suspicious HTTP ingress."
    mitre_tactic = "TA0001 - Initial Access"
    detection_capabilities = [
        "Phishing Email & Spoofed Sender Analysis",
        "Email Header (SPF, DKIM, DMARC) Forensic Verification",
        "Malicious & Typosquatted URL Detection",
        "Suspicious Email Attachment & Container Inspection (.iso, .lnk, .zip)",
        "Secure Web Gateway (SWG) & Reverse Proxy Log Ingestion",
        "Malicious Inbound HTTP Request & User-Agent Anomaly Identification",
        "Sender IP / Host Reputation Telemetry Correlation",
    ]
    default_controls = [
        {"name": "Secure Email Gateway (SEG) SPF/DKIM/DMARC", "capability": "Deny", "tool": "Email Security Gateway"},
        {"name": "DNS Sinkholing & URL Filtering (RPZ)", "capability": "Deny", "tool": "Protective DNS Filter"},
        {"name": "Web Proxy Sandboxing & Attachment Stripping", "capability": "Disrupt", "tool": "Web Gateway Proxy"},
        {"name": "Browser Isolation & Safe Browsing Inspection", "capability": "Degrade", "tool": "Browser Isolation Engine"},
        {"name": "Security Awareness Phishing Simulation", "capability": "Detect", "tool": "Security Training Agent"},
    ]

    def analyze(self, telemetry: Dict[str, Any], asset_context: Optional[Dict[str, Any]] = None) -> StageAnalysisResult:
        findings: List[KillChainFinding] = []
        evidence_list: List[EvidenceItem] = []
        indicators: List[ThreatIndicator] = []
        assets_seen = set()

        target = telemetry.get("target") or telemetry.get("host") or "127.0.0.1"
        assets_seen.add(target)
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # 1. Analyze Email / Phishing Telemetry
        emails = telemetry.get("emails") or telemetry.get("email_logs", [])
        for em in emails:
            sender = em.get("from") or em.get("sender", "unknown@external.net")
            recipient = em.get("to") or em.get("recipient", target)
            subject = em.get("subject", "No Subject")
            spf = em.get("spf", "PASS").upper()
            dmarc = em.get("dmarc", "PASS").upper()
            attachments = em.get("attachments", [])
            urls = em.get("urls", [])

            is_spoofed = (spf in ("FAIL", "SOFTFAIL")) or (dmarc in ("FAIL", "REJECT"))
            has_dangerous_ext = any(a.lower().endswith((".iso", ".lnk", ".vbs", ".hta", ".exe", ".js", ".docm")) for a in attachments)

            ev_email = self.create_evidence(
                artifact_type="EMAIL_DELIVERY_TELEMETRY",
                raw_data=f"From: {sender} | To: {recipient} | Subject: {subject} | SPF: {spf} | Attachments: {attachments}",
                normalized_data=em,
                affected_asset=recipient,
                source_tool="SWA Mail Gateway Analyzer",
                evidence_quality=0.95,
            )
            evidence_list.append(ev_email)
            assets_seen.add(recipient)

            if is_spoofed or has_dangerous_ext or em.get("phishing_indicators"):
                risk = self.calculate_risk(impact_weight=8.5, likelihood=0.8, exposure=1.3)
                conf_level, conf_score = self.calculate_confidence(evidence_quality=0.95, source_reliability=0.9, corroboration_count=2)
                findings.append(
                    KillChainFinding(
                        id=f"kc_deliv_{uuid.uuid4().hex[:8]}",
                        title=f"Spearphishing Delivery Attempt with Spoofed Domain: {subject}",
                        stage=self.stage,
                        severity=SeverityEnum.HIGH,
                        mitre_technique_id="T1566.001" if attachments else "T1566.002",
                        mitre_tactic=self.mitre_tactic,
                        affected_host=recipient,
                        affected_endpoint=f"Mailbox: {recipient}",
                        description=(
                            f"Inbound email from '{sender}' failed email authentication checks (SPF: {spf}, DMARC: {dmarc}) "
                            f"and delivered suspicious payloads: {attachments or urls}."
                        ),
                        evidence=f"Sender: {sender}\nAuthentication: SPF={spf}, DMARC={dmarc}\nPayloads: {attachments or urls}",
                        evidence_ids=[ev_email.id],
                        detection_source="SWA Mail Gateway Analyzer",
                        confidence_level=conf_level,
                        confidence_score=conf_score,
                        risk_score=risk,
                        remediation="Quarantine email from all recipient inboxes, block sender domain, and submit attachments to sandbox.",
                        references=["https://attack.mitre.org/techniques/T1566/"],
                    )
                )

                if sender:
                    indicators.append(
                        ThreatIndicator(
                            id=f"ind_deliv_{uuid.uuid4().hex[:8]}",
                            indicator_type="DOMAIN" if "@" in sender else "SENDER",
                            value=sender.split("@")[-1] if "@" in sender else sender,
                            stage=self.stage,
                            reputation_score=85.0,
                            provider="SWA Phishing Engine",
                            source_attribution="Inbound SMTP Inspection",
                            verified=True,
                            details={"subject": subject, "sender": sender},
                        )
                    )

        # 2. Analyze Malicious URLs & Ingress Web Gateway Logs
        urls_telemetry = telemetry.get("urls") or telemetry.get("web_events", [])
        for u in urls_telemetry:
            url_str = u if isinstance(u, str) else u.get("url", "")
            status_code = u.get("status_code", 200) if isinstance(u, dict) else 200
            rep = u.get("reputation_score", 0.0) if isinstance(u, dict) else 0.0
            is_malicious = rep >= 75.0 or (isinstance(u, dict) and u.get("is_malicious"))

            if is_malicious or any(bad in url_str.lower() for bad in ["malware", "phish", "exploit", "c2", "token_steal"]):
                ev_url = self.create_evidence(
                    artifact_type="WEB_GATEWAY_DELIVERY",
                    raw_data=f"Target accessed malicious URL: {url_str} (HTTP Status {status_code})",
                    normalized_data={"url": url_str, "status_code": status_code, "rep": rep},
                    affected_asset=target,
                    source_tool="SWA Proxy Analyzer",
                )
                evidence_list.append(ev_url)
                risk = self.calculate_risk(impact_weight=8.0, likelihood=0.8, exposure=1.4)
                conf_level, conf_score = self.calculate_confidence(evidence_quality=0.95, source_reliability=0.9, corroboration_count=2)
                findings.append(
                    KillChainFinding(
                        id=f"kc_deliv_{uuid.uuid4().hex[:8]}",
                        title=f"Malicious Web URL / Drive-By Download Delivery Vector: {url_str[:50]}",
                        stage=self.stage,
                        severity=SeverityEnum.HIGH,
                        mitre_technique_id="T1189",
                        mitre_tactic=self.mitre_tactic,
                        affected_host=target,
                        affected_endpoint=url_str,
                        http_status_code=status_code,
                        description=f"Outbound proxy or gateway logged user/system access to high-reputation malicious URL: {url_str}.",
                        evidence=f"URL: {url_str}\nGateway Status: HTTP {status_code}\nThreat Score: {rep}/100",
                        evidence_ids=[ev_url.id],
                        detection_source="SWA Proxy / Threat Intel Analyzer",
                        confidence_level=conf_level,
                        confidence_score=conf_score,
                        risk_score=risk,
                        remediation="Block URL and parent domain at web proxy/DNS sinkhole. Check client endpoint for dropper execution.",
                        references=["https://attack.mitre.org/techniques/T1189/"],
                    )
                )

                indicators.append(
                    ThreatIndicator(
                        id=f"ind_deliv_{uuid.uuid4().hex[:8]}",
                        indicator_type="URL",
                        value=url_str,
                        stage=self.stage,
                        reputation_score=rep if rep > 0 else 90.0,
                        provider="SWA URL Intel Provider",
                        source_attribution="Proxy Access Log",
                        verified=True,
                    )
                )

        status = self.determine_stage_status(findings)
        summary = (
            f"Delivery analysis evaluated {len(emails)} email transmissions and {len(urls_telemetry)} web gateway requests. "
            f"Identified {len(findings)} potential delivery events."
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
                "Enforce DMARC with strict 'reject' policy on all mail domains.",
                "Implement DNS-layer threat filtering and automatic sandbox analysis for untrusted attachments.",
                "Enforce multi-factor authentication (MFA) to mitigate credential harvesting delivery attacks.",
            ],
            summary=summary,
            assessed_at=now_utc,
        )
