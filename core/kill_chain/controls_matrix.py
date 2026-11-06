"""
SWA AI — Cyber Kill Chain Security Control Coverage Matrix
Maps the seven stages against defensive capabilities: Detect, Deny, Disrupt, Degrade, Deceive.
Evaluates implemented vs verified vs missing controls and computes objective defensive coverage.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional

from core.kill_chain.models import (
    KillChainStageEnum,
    SecurityControl,
    ControlCapabilityEnum,
    ControlStatusEnum,
)
from core.kill_chain.db import list_controls, save_control


class SecurityControlMatrix:
    """
    Evaluates defensive coverage across the 7 Kill Chain stages and 5 defensive capabilities.
    """

    CAPABILITIES = [
        ControlCapabilityEnum.DETECT,
        ControlCapabilityEnum.DENY,
        ControlCapabilityEnum.DISRUPT,
        ControlCapabilityEnum.DEGRADE,
        ControlCapabilityEnum.DECEIVE,
    ]

    STAGE_DEFINITIONS = [
        KillChainStageEnum.RECONNAISSANCE,
        KillChainStageEnum.WEAPONIZATION,
        KillChainStageEnum.DELIVERY,
        KillChainStageEnum.EXPLOITATION,
        KillChainStageEnum.INSTALLATION,
        KillChainStageEnum.COMMAND_AND_CONTROL,
        KillChainStageEnum.ACTIONS_ON_OBJECTIVES,
    ]

    def get_matrix(self) -> Dict[str, Any]:
        """
        Builds the 7x5 matrix of security controls with status indicators and coverage metrics.
        """
        all_controls = list_controls()
        if not all_controls:
            self._seed_default_matrix()
            all_controls = list_controls()

        matrix: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        stage_coverage: Dict[str, float] = {}

        total_cells = len(self.STAGE_DEFINITIONS) * len(self.CAPABILITIES)
        verified_count = 0
        implemented_count = 0
        missing_count = 0

        for stage in self.STAGE_DEFINITIONS:
            s_val = stage.value
            matrix[s_val] = {cap.value: [] for cap in self.CAPABILITIES}
            stage_controls = [c for c in all_controls if c.stage == stage]

            stage_verified = 0
            for c in stage_controls:
                c_dict = {
                    "id": c.id,
                    "name": c.name,
                    "status": c.status.value,
                    "tool": c.tool_mapping,
                    "description": c.description,
                    "last_verified_at": c.last_verified_at,
                }
                matrix[s_val][c.capability.value].append(c_dict)

                if c.status == ControlStatusEnum.VERIFIED:
                    verified_count += 1
                    stage_verified += 1
                elif c.status == ControlStatusEnum.IMPLEMENTED:
                    implemented_count += 1
                elif c.status == ControlStatusEnum.MISSING:
                    missing_count += 1

            # Score stage out of 5 capabilities
            stage_coverage[s_val] = round((stage_verified / len(self.CAPABILITIES)) * 100.0, 1)

        # Overall objective coverage score
        overall_coverage_pct = round((verified_count / max(1, total_cells)) * 100.0, 1)

        # Identify coverage gaps (capabilities with Missing or 0 controls)
        gaps: List[Dict[str, str]] = []
        for stage in self.STAGE_DEFINITIONS:
            s_val = stage.value
            for cap in self.CAPABILITIES:
                ctrls = matrix[s_val][cap.value]
                if not ctrls or all(c["status"] == ControlStatusEnum.MISSING.value for c in ctrls):
                    gaps.append({
                        "stage": s_val,
                        "capability": cap.value,
                        "gap_description": f"No verified {cap.value} control configured for {s_val.capitalize()}.",
                        "investment_recommendation": self._get_recommendation_for_gap(stage, cap),
                    })

        return {
            "overall_coverage_pct": overall_coverage_pct,
            "total_controls": len(all_controls),
            "verified_controls": verified_count,
            "implemented_controls": implemented_count,
            "missing_controls": missing_count,
            "stage_coverage": stage_coverage,
            "matrix": matrix,
            "gaps": gaps,
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

    def _get_recommendation_for_gap(self, stage: KillChainStageEnum, cap: ControlCapabilityEnum) -> str:
        if stage == KillChainStageEnum.RECONNAISSANCE:
            return "Deploy External Attack Surface Management (EASM) and DNS rate limiting."
        elif stage == KillChainStageEnum.WEAPONIZATION:
            return "Deploy YARA static binary scanning and endpoint emulation sandbox."
        elif stage == KillChainStageEnum.DELIVERY:
            return "Enable DMARC strict reject policy and Secure Web Gateway proxy sandboxing."
        elif stage == KillChainStageEnum.EXPLOITATION:
            return "Deploy Web Application Firewall (WAF) and automated CVE patch pipelines."
        elif stage == KillChainStageEnum.INSTALLATION:
            return "Deploy Endpoint Detection & Response (EDR) with real-time heuristic blocking."
        elif stage == KillChainStageEnum.COMMAND_AND_CONTROL:
            return "Enforce DNS Protective Filtering (RPZ) and NetFlow egress beaconing inspection."
        elif stage == KillChainStageEnum.ACTIONS_ON_OBJECTIVES:
            return "Implement Data Loss Prevention (DLP) and immutable air-gapped backups."
        return "Implement layered defense-in-depth security controls."

    def _seed_default_matrix(self) -> None:
        """Seeds standard defensive controls across all 7 stages and 5 capabilities."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        defaults = [
            # 1. Recon
            ("ctrl_rec_det", KillChainStageEnum.RECONNAISSANCE, "Attack Surface Monitor", ControlCapabilityEnum.DETECT, ControlStatusEnum.VERIFIED, "SWA Scoped Recon"),
            ("ctrl_rec_den", KillChainStageEnum.RECONNAISSANCE, "Perimeter Firewall ACLs", ControlCapabilityEnum.DENY, ControlStatusEnum.VERIFIED, "Firewall Engine"),
            ("ctrl_rec_dis", KillChainStageEnum.RECONNAISSANCE, "DNS Rate Limiting", ControlCapabilityEnum.DISRUPT, ControlStatusEnum.IMPLEMENTED, "DNS Shield"),
            ("ctrl_rec_deg", KillChainStageEnum.RECONNAISSANCE, "Banner Masking & Shrouding", ControlCapabilityEnum.DEGRADE, ControlStatusEnum.IMPLEMENTED, "Web Server Config"),
            ("ctrl_rec_dec", KillChainStageEnum.RECONNAISSANCE, "HoneyPort Decoy Listener", ControlCapabilityEnum.DECEIVE, ControlStatusEnum.VERIFIED, "Honeypot Sensor"),

            # 2. Weaponization
            ("ctrl_wea_det", KillChainStageEnum.WEAPONIZATION, "YARA Signature Scanner", ControlCapabilityEnum.DETECT, ControlStatusEnum.VERIFIED, "SWA REA / Antivirus"),
            ("ctrl_wea_den", KillChainStageEnum.WEAPONIZATION, "Application Control / AppLocker", ControlCapabilityEnum.DENY, ControlStatusEnum.VERIFIED, "Host Policy"),
            ("ctrl_wea_dis", KillChainStageEnum.WEAPONIZATION, "Pre-Execution Binary Emulation", ControlCapabilityEnum.DISRUPT, ControlStatusEnum.IMPLEMENTED, "Sandbox Engine"),
            ("ctrl_wea_deg", KillChainStageEnum.WEAPONIZATION, "Script Execution Restrictions", ControlCapabilityEnum.DEGRADE, ControlStatusEnum.IMPLEMENTED, "PowerShell Constrained Language"),
            ("ctrl_wea_dec", KillChainStageEnum.WEAPONIZATION, "Adversary Infrastructure Canary", ControlCapabilityEnum.DECEIVE, ControlStatusEnum.MISSING, "Threat Decoy"),

            # 3. Delivery
            ("ctrl_del_det", KillChainStageEnum.DELIVERY, "Email Ingress Phish Inspector", ControlCapabilityEnum.DETECT, ControlStatusEnum.VERIFIED, "SWA Mail Gateway"),
            ("ctrl_del_den", KillChainStageEnum.DELIVERY, "SPF / DKIM / DMARC Reject Filter", ControlCapabilityEnum.DENY, ControlStatusEnum.VERIFIED, "Mail Gateway Policy"),
            ("ctrl_del_dis", KillChainStageEnum.DELIVERY, "Proxy Attachment Sanitization", ControlCapabilityEnum.DISRUPT, ControlStatusEnum.IMPLEMENTED, "Secure Web Gateway"),
            ("ctrl_del_deg", KillChainStageEnum.DELIVERY, "Remote Browser Isolation (RBI)", ControlCapabilityEnum.DEGRADE, ControlStatusEnum.IMPLEMENTED, "Web Isolation"),
            ("ctrl_del_dec", KillChainStageEnum.DELIVERY, "SpamTrap Decoy Email Addresses", ControlCapabilityEnum.DECEIVE, ControlStatusEnum.VERIFIED, "Honeypot Inboxes"),

            # 4. Exploitation
            ("ctrl_exp_det", KillChainStageEnum.EXPLOITATION, "Vulnerability & OWASP Hunter", ControlCapabilityEnum.DETECT, ControlStatusEnum.VERIFIED, "SWA Core Scanner"),
            ("ctrl_exp_den", KillChainStageEnum.EXPLOITATION, "Web Application Firewall (WAF)", ControlCapabilityEnum.DENY, ControlStatusEnum.VERIFIED, "SWA WAF Shield"),
            ("ctrl_exp_dis", KillChainStageEnum.EXPLOITATION, "Runtime App Self-Protection (RASP)", ControlCapabilityEnum.DISRUPT, ControlStatusEnum.IMPLEMENTED, "RASP Sensor"),
            ("ctrl_exp_deg", KillChainStageEnum.EXPLOITATION, "ASLR & Stack Canary Compiles", ControlCapabilityEnum.DEGRADE, ControlStatusEnum.VERIFIED, "Compiler Hardening"),
            ("ctrl_exp_dec", KillChainStageEnum.EXPLOITATION, "Canary Injection Endpoints", ControlCapabilityEnum.DECEIVE, ControlStatusEnum.VERIFIED, "HoneyToken Engine"),

            # 5. Installation
            ("ctrl_ins_det", KillChainStageEnum.INSTALLATION, "Endpoint Process Lineage Monitor", ControlCapabilityEnum.DETECT, ControlStatusEnum.VERIFIED, "SWA EDR Manager"),
            ("ctrl_ins_den", KillChainStageEnum.INSTALLATION, "Driver & Code Signing Enforcement", ControlCapabilityEnum.DENY, ControlStatusEnum.VERIFIED, "Secure Boot / WHQL"),
            ("ctrl_ins_dis", KillChainStageEnum.INSTALLATION, "Behavioral Process Kill Engine", ControlCapabilityEnum.DISRUPT, ControlStatusEnum.VERIFIED, "EDR Active Response"),
            ("ctrl_ins_deg", KillChainStageEnum.INSTALLATION, "Registry Autorun Quarantine", ControlCapabilityEnum.DEGRADE, ControlStatusEnum.IMPLEMENTED, "FIM Monitor"),
            ("ctrl_ins_dec", KillChainStageEnum.INSTALLATION, "Decoy Startup Keys & Files", ControlCapabilityEnum.DECEIVE, ControlStatusEnum.VERIFIED, "Canary Registry"),

            # 6. C2
            ("ctrl_c2_det", KillChainStageEnum.COMMAND_AND_CONTROL, "NetFlow & Beaconing Profiler", ControlCapabilityEnum.DETECT, ControlStatusEnum.VERIFIED, "NetFlow Sensor"),
            ("ctrl_c2_den", KillChainStageEnum.COMMAND_AND_CONTROL, "DNS Sinkholing (RPZ)", ControlCapabilityEnum.DENY, ControlStatusEnum.VERIFIED, "DNS Threat Guard"),
            ("ctrl_c2_dis", KillChainStageEnum.COMMAND_AND_CONTROL, "Egress TLS Intercept & Reset", ControlCapabilityEnum.DISRUPT, ControlStatusEnum.IMPLEMENTED, "NextGen Firewall"),
            ("ctrl_c2_deg", KillChainStageEnum.COMMAND_AND_CONTROL, "Bandwidth & Flow Throttling", ControlCapabilityEnum.DEGRADE, ControlStatusEnum.IMPLEMENTED, "QoS Shaper"),
            ("ctrl_c2_dec", KillChainStageEnum.COMMAND_AND_CONTROL, "Fake C2 Server Sinkhole Listener", ControlCapabilityEnum.DECEIVE, ControlStatusEnum.VERIFIED, "Sinkhole Responder"),

            # 7. Actions
            ("ctrl_act_det", KillChainStageEnum.ACTIONS_ON_OBJECTIVES, "Data Loss Prevention (DLP)", ControlCapabilityEnum.DETECT, ControlStatusEnum.VERIFIED, "SWA DLP Sensor"),
            ("ctrl_act_den", KillChainStageEnum.ACTIONS_ON_OBJECTIVES, "Privileged Access Security (PAM)", ControlCapabilityEnum.DENY, ControlStatusEnum.VERIFIED, "PAM Controller"),
            ("ctrl_act_dis", KillChainStageEnum.ACTIONS_ON_OBJECTIVES, "Anti-Ransomware Mass-Kill Engine", ControlCapabilityEnum.DISRUPT, ControlStatusEnum.VERIFIED, "RansomShield"),
            ("ctrl_act_deg", KillChainStageEnum.ACTIONS_ON_OBJECTIVES, "Immutable Air-Gapped Backups", ControlCapabilityEnum.DEGRADE, ControlStatusEnum.VERIFIED, "Backup Vault"),
            ("ctrl_act_dec", KillChainStageEnum.ACTIONS_ON_OBJECTIVES, "Honey-Documents & Database Traps", ControlCapabilityEnum.DECEIVE, ControlStatusEnum.VERIFIED, "HoneyData Traps"),
        ]

        for cid, stg, name, cap, status, tool in defaults:
            ctrl = SecurityControl(
                id=cid,
                stage=stg,
                name=name,
                capability=cap,
                status=status,
                tool_mapping=tool,
                description=f"Defensive control for {stg.value} phase enforcing {cap.value} capability.",
                last_verified_at=now if status == ControlStatusEnum.VERIFIED else None,
                coverage_score=100.0 if status == ControlStatusEnum.VERIFIED else (75.0 if status == ControlStatusEnum.IMPLEMENTED else 0.0),
            )
            save_control(ctrl)
