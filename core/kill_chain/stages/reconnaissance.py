"""
SWA AI — Cyber Kill Chain: Stage 01 — Reconnaissance
Objective: Identify information gathering, adversary footprinting, and external attack surface exposure.
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


class ReconnaissanceAnalyzer(BaseStageAnalyzer):
    stage = KillChainStageEnum.RECONNAISSANCE
    stage_number = 1
    title = "Reconnaissance"
    objective = "Identify information gathering, scanning, and external attack surface exposure."
    mitre_tactic = "TA0043 - Reconnaissance"
    detection_capabilities = [
        "Domain & Subdomain Discovery",
        "DNS Record & Zone Transfer Analysis",
        "WHOIS & ASN Exposure Inspection",
        "Public IP & Open Port Inventory",
        "Service Identification & Banner Grabbing",
        "Technology Stack Fingerprinting",
        "SSL/TLS Certificate & Cipher Inspection",
        "Public Exposure & Cloud Storage Assessment",
        "Adversary Port/Vulnerability Scanning Indicators",
    ]
    default_controls = [
        {"name": "External Attack Surface Monitoring (EASM)", "capability": "Detect", "tool": "SWA Scoped Recon"},
        {"name": "DNS Rate Limiting & Stealth Zone Transfers", "capability": "Deny", "tool": "Core DNS Policy"},
        {"name": "Web Application Firewall (WAF) Pre-Scan Filtering", "capability": "Deny", "tool": "WAF Shield"},
        {"name": "Network Perimeter Firewall / Port Blocker", "capability": "Deny", "tool": "Perimeter IDS/IPS"},
        {"name": "Honeypot Decoy Service", "capability": "Deceive", "tool": "HoneyPort Agent"},
    ]

    def analyze(self, telemetry: Dict[str, Any], asset_context: Optional[Dict[str, Any]] = None) -> StageAnalysisResult:
        findings: List[KillChainFinding] = []
        evidence_list: List[EvidenceItem] = []
        indicators: List[ThreatIndicator] = []
        assets_seen = set()

        target = telemetry.get("target") or telemetry.get("host") or "127.0.0.1"
        assets_seen.add(target)
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # 1. Analyze Subdomains & DNS Telemetry
        subdomains = telemetry.get("subdomains", [])
        dns_records = telemetry.get("dns_records", {})
        if subdomains:
            ev = self.create_evidence(
                artifact_type="SUBDOMAIN_INVENTORY",
                raw_data=f"Discovered {len(subdomains)} subdomains for {target}: {', '.join(subdomains[:10])}",
                normalized_data={"subdomains": subdomains, "count": len(subdomains)},
                affected_asset=target,
                source_tool="SWA Amass / Subdomain Engine",
            )
            evidence_list.append(ev)

            # Check for high-risk exposed subdomains (e.g. dev, test, staging, admin)
            risky_subs = [s for s in subdomains if any(k in s.lower() for k in ["admin", "dev", "test", "stage", "vpn", "internal"])]
            if risky_subs:
                risk = self.calculate_risk(impact_weight=6.5, likelihood=0.8, exposure=1.4)
                conf_level, conf_score = self.calculate_confidence(evidence_quality=0.95, source_reliability=0.9, corroboration_count=2)
                f = KillChainFinding(
                    id=f"kc_recon_{uuid.uuid4().hex[:8]}",
                    title=f"Exposed Pre-Production & Administrative Subdomains ({len(risky_subs)} detected)",
                    stage=self.stage,
                    severity=SeverityEnum.MEDIUM,
                    cwe="CWE-200",
                    mitre_technique_id="T1596.001",
                    mitre_tactic=self.mitre_tactic,
                    affected_host=target,
                    affected_endpoint=", ".join(risky_subs[:5]),
                    description=f"Publicly queryable DNS records reveal sensitive non-production domains: {', '.join(risky_subs)}",
                    evidence=f"DNS enumeration identified: {risky_subs}",
                    evidence_ids=[ev.id],
                    detection_source="SWA Subdomain Engine",
                    confidence_level=conf_level,
                    confidence_score=conf_score,
                    risk_score=risk,
                    remediation="Restrict internal subdomains from public authoritative DNS or enforce zero-trust gateway.",
                    references=["https://attack.mitre.org/techniques/T1596/001/"],
                )
                findings.append(f)

        # 2. Analyze Open Ports & Exposed Services
        open_ports = telemetry.get("open_ports") or telemetry.get("ports", [])
        if open_ports:
            port_ints = []
            for p in open_ports:
                try:
                    port_ints.append(int(p if isinstance(p, (int, str)) else p.get("port", 0)))
                except Exception:
                    pass

            ev_ports = self.create_evidence(
                artifact_type="OPEN_PORT_SCAN",
                raw_data=f"Port scan findings for {target}: {port_ints}",
                normalized_data={"open_ports": port_ints},
                affected_asset=target,
                source_tool="SWA Port Scanner",
            )
            evidence_list.append(ev_ports)

            # Check for critical administrative or database ports exposed
            critical_ports = {22: "SSH", 3389: "RDP", 23: "Telnet", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch"}
            exposed_crit = [f"{p} ({critical_ports[p]})" for p in port_ints if p in critical_ports]

            if exposed_crit:
                risk = self.calculate_risk(impact_weight=8.5, likelihood=0.85, exposure=1.5)
                conf_level, conf_score = self.calculate_confidence(evidence_quality=1.0, source_reliability=0.95, corroboration_count=2)
                f_ports = KillChainFinding(
                    id=f"kc_recon_{uuid.uuid4().hex[:8]}",
                    title=f"Direct Exposure of Sensitive Administrative / Database Ports: {', '.join(exposed_crit)}",
                    stage=self.stage,
                    severity=SeverityEnum.HIGH,
                    cwe="CWE-284",
                    mitre_technique_id="T1046",
                    mitre_tactic=self.mitre_tactic,
                    affected_host=target,
                    description=f"Host exposes direct management/datastore interfaces to the network: {exposed_crit}",
                    evidence=f"TCP handshake response on ports: {exposed_crit}",
                    evidence_ids=[ev_ports.id],
                    detection_source="SWA Port Scanner",
                    confidence_level=conf_level,
                    confidence_score=conf_score,
                    risk_score=risk,
                    remediation="Bind database and management ports strictly to 127.0.0.1 or enforce bastion host and VPN ACLs.",
                    references=["https://attack.mitre.org/techniques/T1046/"],
                )
                findings.append(f_ports)

        # 3. Analyze SSL/TLS & Technology Fingerprints
        ssl_info = telemetry.get("ssl", {})
        if ssl_info:
            ev_ssl = self.create_evidence(
                artifact_type="SSL_CERT_ANALYSIS",
                raw_data=str(ssl_info),
                normalized_data=ssl_info,
                affected_asset=target,
                source_tool="SWA SSL Analyzer",
            )
            evidence_list.append(ev_ssl)
            if ssl_info.get("expired") or ssl_info.get("weak_ciphers"):
                risk = self.calculate_risk(impact_weight=5.0, likelihood=0.6, exposure=1.2)
                conf_level, conf_score = self.calculate_confidence(evidence_quality=0.95, source_reliability=0.9, corroboration_count=1)
                findings.append(
                    KillChainFinding(
                        id=f"kc_recon_{uuid.uuid4().hex[:8]}",
                        title="Insecure or Expired SSL/TLS Cryptographic Profile",
                        stage=self.stage,
                        severity=SeverityEnum.MEDIUM,
                        cwe="CWE-326",
                        mitre_technique_id="T1596.003",
                        mitre_tactic=self.mitre_tactic,
                        affected_host=target,
                        description="TLS inspection detected deprecated cipher suites or an expired certificate allowing potential MITM exposure.",
                        evidence=str(ssl_info),
                        evidence_ids=[ev_ssl.id],
                        detection_source="SWA SSL Analyzer",
                        confidence_level=conf_level,
                        confidence_score=conf_score,
                        risk_score=risk,
                        remediation="Upgrade TLS configuration to TLS 1.3/1.2 only and renew certificates with strong RSA/ECDSA keys.",
                        references=["https://attack.mitre.org/techniques/T1596/003/"],
                    )
                )

        # 4. Ingest Existing SWA Scan Findings for Recon
        existing_findings = telemetry.get("findings", [])
        for ef in existing_findings:
            cat = (ef.get("category") or ef.get("tool_source") or "").lower()
            if any(k in cat for k in ["recon", "dns", "port", "whois", "network", "amass"]):
                ev_f = self.create_evidence(
                    artifact_type="RECON_FINDING_INGEST",
                    raw_data=ef.get("description", "") or ef.get("title", ""),
                    normalized_data=ef,
                    affected_asset=ef.get("endpoint", target),
                    source_tool=ef.get("tool_source", "SWA Core"),
                )
                evidence_list.append(ev_f)
                sev_str = (ef.get("severity") or "MEDIUM").upper()
                sev = SeverityEnum[sev_str] if sev_str in SeverityEnum.__members__ else SeverityEnum.MEDIUM
                risk = self.calculate_risk(impact_weight=7.0 if sev == SeverityEnum.HIGH else 4.5, likelihood=0.7)
                conf_level, conf_score = self.calculate_confidence(evidence_quality=0.9, source_reliability=0.85, corroboration_count=1)
                findings.append(
                    KillChainFinding(
                        id=f"kc_recon_{uuid.uuid4().hex[:8]}",
                        title=ef.get("title", "Reconnaissance Exposure Finding"),
                        stage=self.stage,
                        severity=sev,
                        cwe=ef.get("cwe"),
                        mitre_technique_id="T1595",
                        mitre_tactic=self.mitre_tactic,
                        affected_host=target,
                        affected_endpoint=ef.get("endpoint"),
                        description=ef.get("description", ""),
                        evidence=ef.get("evidence", ""),
                        evidence_ids=[ev_f.id],
                        detection_source=ef.get("tool_source", "SWA Core Scanner"),
                        confidence_level=conf_level,
                        confidence_score=conf_score,
                        risk_score=risk,
                        remediation=ef.get("solution", "Harden perimeter exposure."),
                        references=["https://attack.mitre.org/techniques/T1595/"],
                    )
                )

        # Indicators
        if target:
            indicators.append(
                ThreatIndicator(
                    id=f"ind_recon_{uuid.uuid4().hex[:8]}",
                    indicator_type="DOMAIN" if not target.replace(".", "").isdigit() else "IP",
                    value=target,
                    stage=self.stage,
                    reputation_score=15.0,
                    provider="SWA Attack Surface Analyzer",
                    source_attribution="Direct Target Scope",
                    verified=True,
                )
            )

        status = self.determine_stage_status(findings)
        summary = (
            f"Reconnaissance evaluation completed. Discovered {len(subdomains)} subdomains, "
            f"{len(open_ports)} open network ports, and generated {len(findings)} exposure findings."
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
                "Implement strict egress/ingress firewalling on non-public ports.",
                "Enforce split-horizon internal DNS resolution.",
                "Deploy proactive Attack Surface Management (EASM).",
            ],
            summary=summary,
            assessed_at=now_utc,
        )
