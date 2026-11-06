"""
SWA AI — Cyber Kill Chain: Stage 06 — Command & Control (C2)
Objective: Detect suspicious external communication patterns, beaconing, DNS tunneling,
abnormal outbound network traffic, and connections to known adversary infrastructure.
Note: Strictly defensive analysis. No C2 servers or implants are implemented.
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


class CommandAndControlAnalyzer(BaseStageAnalyzer):
    stage = KillChainStageEnum.COMMAND_AND_CONTROL
    stage_number = 6
    title = "Command & Control (C2)"
    objective = "Detect adversary command and control channels, beaconing periodicity, DNS tunneling, and suspicious egress network flows."
    mitre_tactic = "TA0011 - Command and Control"
    detection_capabilities = [
        "Network Beaconing Frequency & Jitter Analysis",
        "DNS Tunneling & High-Entropy Query Inspection",
        "Suspicious Outbound Connections to High-Risk ASN/IPs",
        "Non-Standard Port Protocol Tunneling (e.g., HTTPS over 8443/4444)",
        "Periodic Heartbeat Anomaly Detection",
        "Malicious C2 Domain & Fast-Flux DNS Correlation",
        "Firewall Egress & NetFlow Telemetry Inspection",
    ]
    default_controls = [
        {"name": "Network Intrusion Detection System (NIDS)", "capability": "Detect", "tool": "Core NIDS Engine"},
        {"name": "Protective DNS Firewall & Sinkhole", "capability": "Deny", "tool": "DNS Threat Guard"},
        {"name": "Strict Egress Port Filtering & TLS Decryption", "capability": "Deny", "tool": "Next-Gen Firewall"},
        {"name": "Network Flow Jitter & Beacon Anomaly Profiler", "capability": "Disrupt", "tool": "NetFlow Analyzer"},
        {"name": "Deception Canary C2 Listener Response", "capability": "Deceive", "tool": "Honeynet Listener"},
    ]

    def analyze(self, telemetry: Dict[str, Any], asset_context: Optional[Dict[str, Any]] = None) -> StageAnalysisResult:
        findings: List[KillChainFinding] = []
        evidence_list: List[EvidenceItem] = []
        indicators: List[ThreatIndicator] = []
        assets_seen = set()

        target = telemetry.get("target") or telemetry.get("host") or "127.0.0.1"
        assets_seen.add(target)
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # 1. Analyze Outbound Network Flows & Beaconing
        net_flows = telemetry.get("network_flows") or telemetry.get("connections", [])
        for flow in net_flows:
            src_ip = flow.get("src_ip", target)
            dst_ip = flow.get("dst_ip", "198.51.100.23")
            dst_port = flow.get("dst_port", 443)
            domain = flow.get("domain", "")
            proto = flow.get("protocol", "TCP")
            count = flow.get("count", 1)
            interval_sec = flow.get("interval_seconds", 0)
            jitter_pct = flow.get("jitter_pct", 0)
            rep = flow.get("reputation_score", 0.0)

            # Check for suspicious C2 indicators: high reputation threat IP, regular beacon intervals, or unusual ports
            is_unusual_port = dst_port in (4444, 1337, 8443, 6667, 9001, 8088, 31337)
            is_beaconing = interval_sec > 0 and count >= 5 and jitter_pct < 20
            is_known_c2 = rep >= 75.0 or flow.get("is_c2", False)

            if is_unusual_port or is_beaconing or is_known_c2:
                ev_flow = self.create_evidence(
                    artifact_type="C2_NETWORK_FLOW_TELEMETRY",
                    raw_data=(
                        f"Connection: {src_ip} -> {dst_ip}:{dst_port} ({proto}) | "
                        f"Domain: {domain} | Interval: {interval_sec}s | Count: {count} | Jitter: {jitter_pct}%"
                    ),
                    normalized_data=flow,
                    affected_asset=src_ip,
                    source_tool="SWA Network Telemetry Analyzer",
                    evidence_quality=0.96,
                )
                evidence_list.append(ev_flow)
                assets_seen.add(src_ip)

                risk = self.calculate_risk(impact_weight=9.5, likelihood=0.9, exposure=1.4)
                conf_level, conf_score = self.calculate_confidence(evidence_quality=0.96, source_reliability=0.92, corroboration_count=2)
                f_title = (
                    f"Active C2 Beaconing Detected: {src_ip} -> {domain or dst_ip}:{dst_port} (Interval: {interval_sec}s)"
                    if is_beaconing
                    else f"Suspicious Outbound C2 Channel on Non-Standard Port {dst_port} ({dst_ip})"
                )
                findings.append(
                    KillChainFinding(
                        id=f"kc_c2_{uuid.uuid4().hex[:8]}",
                        title=f_title,
                        stage=self.stage,
                        severity=SeverityEnum.CRITICAL if (is_known_c2 or is_beaconing) else SeverityEnum.HIGH,
                        mitre_technique_id="T1071.001" if dst_port in (80, 443, 8080) else "T1571",
                        mitre_tactic=self.mitre_tactic,
                        affected_host=src_ip,
                        affected_endpoint=f"{dst_ip}:{dst_port}",
                        description=(
                            f"Network sensor recorded periodic egress traffic pattern from internal host {src_ip} "
                            f"to external destination {domain or dst_ip}:{dst_port}. Flow exhibited hallmark C2 characteristics "
                            f"with {count} heartbeats and low jitter ({jitter_pct}%)."
                        ),
                        evidence=(
                            f"Source IP: {src_ip}\nDestination IP: {dst_ip}\nDomain: {domain or 'N/A'}\n"
                            f"Port: {dst_port}\nProtocol: {proto}\nBeacon Count: {count}\nInterval: {interval_sec}s"
                        ),
                        evidence_ids=[ev_flow.id],
                        detection_source="SWA Network / NetFlow Monitor",
                        confidence_level=conf_level,
                        confidence_score=conf_score,
                        risk_score=risk,
                        remediation="Sever external connection at firewall immediately, isolate host {src_ip}, and preserve memory dump.",
                        references=["https://attack.mitre.org/techniques/T1071/"],
                    )
                )

                if dst_ip:
                    indicators.append(
                        ThreatIndicator(
                            id=f"ind_c2_{uuid.uuid4().hex[:8]}",
                            indicator_type="IP",
                            value=dst_ip,
                            stage=self.stage,
                            reputation_score=rep if rep > 0 else 92.0,
                            provider="SWA C2 Threat Correlation Engine",
                            source_attribution="Network NetFlow Ingestion",
                            verified=True,
                            details={"port": dst_port, "domain": domain},
                        )
                    )

        # 2. Analyze DNS Tunneling Telemetry
        dns_tunnel_events = telemetry.get("dns_tunneling") or []
        for dt in dns_tunnel_events:
            d_query = dt.get("query", "exfil.badactor.com")
            entropy = dt.get("entropy", 4.2)
            qtype = dt.get("type", "TXT")
            ev_dt = self.create_evidence(
                artifact_type="DNS_TUNNELING_INDICATOR",
                raw_data=f"High entropy DNS query: {d_query} (Entropy: {entropy}, Type: {qtype})",
                normalized_data=dt,
                affected_asset=target,
                source_tool="SWA DNS Threat Analyzer",
            )
            evidence_list.append(ev_dt)
            risk = self.calculate_risk(impact_weight=9.0, likelihood=0.85, exposure=1.3)
            conf_level, conf_score = self.calculate_confidence(evidence_quality=0.94, source_reliability=0.9, corroboration_count=2)
            findings.append(
                KillChainFinding(
                    id=f"kc_c2_{uuid.uuid4().hex[:8]}",
                    title=f"Potential DNS Tunneling / Covert Channel Activity: {d_query[:40]}",
                    stage=self.stage,
                    severity=SeverityEnum.HIGH,
                    mitre_technique_id="T1071.004",
                    mitre_tactic=self.mitre_tactic,
                    affected_host=target,
                    affected_endpoint=f"DNS Server / Resolver ({d_query})",
                    description=f"DNS query log inspection detected excessive payload length or Shannon entropy ({entropy}) indicative of DNS tunneling.",
                    evidence=f"Query: {d_query}\nRecord Type: {qtype}\nEntropy: {entropy}",
                    evidence_ids=[ev_dt.id],
                    detection_source="SWA DNS Threat Analyzer",
                    confidence_level=conf_level,
                    confidence_score=conf_score,
                    risk_score=risk,
                    remediation="Block root domain at recursive DNS resolver and inspect client machine for covert tunneling tools (e.g. iodine).",
                    references=["https://attack.mitre.org/techniques/T1071/004/"],
                )
            )

        status = self.determine_stage_status(findings)
        summary = (
            f"Command & Control analysis inspected {len(net_flows)} network flows and {len(dns_tunnel_events)} DNS telemetry events. "
            f"Detected {len(findings)} potential C2 communication channels."
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
                "Deploy strict egress firewall policies permitting outbound traffic only on verified ports via authenticated proxies.",
                "Enforce DNS Response Policy Zones (RPZ) to sinkhole known C2 domains dynamically.",
                "Implement behavioral beaconing detection algorithms across edge firewall flow logs.",
            ],
            summary=summary,
            assessed_at=now_utc,
        )
