"""
SWA AI — Cyber Kill Chain Central Correlation Engine
Correlates findings, evidence, indicators, and telemetry across all seven stages
to reconstruct attack progression paths, compute composite risk/confidence scores,
and link MITRE ATT&CK techniques.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Any, Dict, List, Optional, Set

from core.kill_chain.models import (
    KillChainStageEnum,
    KillChainFinding,
    EvidenceItem,
    ThreatIndicator,
    CorrelatedAttackPath,
    SeverityEnum,
)


class ThreatCorrelationEngine:
    """
    Central correlation engine connecting findings and evidence across all 7 stages.
    Maintains provenance, deduplicates, associates with assets, and maps attack progression.
    """

    def __init__(self):
        self._stage_order = [
            KillChainStageEnum.RECONNAISSANCE,
            KillChainStageEnum.WEAPONIZATION,
            KillChainStageEnum.DELIVERY,
            KillChainStageEnum.EXPLOITATION,
            KillChainStageEnum.INSTALLATION,
            KillChainStageEnum.COMMAND_AND_CONTROL,
            KillChainStageEnum.ACTIONS_ON_OBJECTIVES,
        ]

    def correlate(
        self,
        findings: List[KillChainFinding],
        evidence: List[EvidenceItem],
        indicators: List[ThreatIndicator],
        target_asset: Optional[str] = None,
    ) -> List[CorrelatedAttackPath]:
        """
        Groups multi-stage events by affected asset and common indicators to identify
        coherent attack progressions across the 7 stages.
        """
        # Deduplicate findings by title and endpoint
        deduped_findings = self._deduplicate_findings(findings)

        # Group findings by asset
        asset_findings: Dict[str, List[KillChainFinding]] = {}
        for f in deduped_findings:
            asset = f.affected_host or "127.0.0.1"
            if target_asset and asset != target_asset:
                continue
            asset_findings.setdefault(asset, []).append(f)

        attack_paths: List[CorrelatedAttackPath] = []

        for asset, f_list in asset_findings.items():
            stages_detected_set: Set[KillChainStageEnum] = {f.stage for f in f_list}
            stages_detected = [s for s in self._stage_order if s in stages_detected_set]

            if not stages_detected:
                continue

            progression_pct = round((len(stages_detected) / 7.0) * 100.0, 1)

            # Determine root cause stage (earliest detected in chain)
            root_stage = stages_detected[0]

            # Highest severity
            severities = [f.severity for f in f_list]
            if SeverityEnum.CRITICAL in severities:
                highest_sev = SeverityEnum.CRITICAL
            elif SeverityEnum.HIGH in severities:
                highest_sev = SeverityEnum.HIGH
            elif SeverityEnum.MEDIUM in severities:
                highest_sev = SeverityEnum.MEDIUM
            else:
                highest_sev = SeverityEnum.LOW

            # Calculate composite risk score:
            # max stage risk + weighted progression bonus
            max_risk = max([f.risk_score for f in f_list], default=50.0)
            progression_bonus = (len(stages_detected) - 1) * 3.5
            composite_risk = round(min(100.0, max_risk + progression_bonus), 1)

            # Composite confidence score:
            # Average confidence weighted by corroboration
            avg_conf = sum([f.confidence_score for f in f_list]) / len(f_list)
            corroboration_boost = min(15.0, len(f_list) * 2.0)
            composite_conf = round(min(100.0, avg_conf * 0.85 + corroboration_boost), 1)

            # Build MITRE chain
            mitre_chain = []
            for f in f_list:
                if f.mitre_technique_id:
                    mitre_chain.append({
                        "stage": f.stage.value if hasattr(f.stage, "value") else str(f.stage),
                        "technique_id": f.mitre_technique_id,
                        "tactic": f.mitre_tactic or "Enterprise ATT&CK",
                        "title": f.title,
                    })

            # Time range
            times = [f.first_observed for f in f_list if f.first_observed]
            first_event = min(times) if times else datetime.datetime.now(datetime.timezone.utc).isoformat()
            latest_event = max(times) if times else datetime.datetime.now(datetime.timezone.utc).isoformat()

            # Vector summary
            stage_names = [s.value.capitalize() for s in stages_detected]
            vector_summary = (
                f"Multi-stage intrusion chain against asset '{asset}' spanning {len(stages_detected)}/7 stages "
                f"({', '.join(stage_names)}). Root cause initiated at {root_stage.value.capitalize()}."
            )

            path = CorrelatedAttackPath(
                path_id=f"path_{uuid.uuid4().hex[:8]}",
                target_asset=asset,
                stages_detected=stages_detected,
                progression_percentage=progression_pct,
                correlated_findings=[f.id for f in f_list],
                root_cause_stage=root_stage,
                highest_severity=highest_sev,
                composite_risk_score=composite_risk,
                confidence_score=composite_conf,
                attack_vector_summary=vector_summary,
                mitre_chain=mitre_chain,
                first_event_at=first_event,
                latest_event_at=latest_event,
            )
            attack_paths.append(path)

        # Sort attack paths by composite risk score descending
        attack_paths.sort(key=lambda p: p.composite_risk_score, reverse=True)
        return attack_paths

    def _deduplicate_findings(self, findings: List[KillChainFinding]) -> List[KillChainFinding]:
        seen = set()
        deduped = []
        for f in findings:
            key = (f.stage, f.title.strip().lower(), (f.affected_endpoint or "").strip().lower(), f.affected_host)
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped
