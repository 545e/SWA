"""
SWA AI — Base Stage Analyzer Framework
Abstract base class defining contracts, risk & confidence calculations,
and MITRE ATT&CK mapping for all seven stages of the Lockheed Martin Cyber Kill Chain.
"""

from __future__ import annotations

import abc
import datetime
import hashlib
import uuid
from typing import Any, Dict, List, Optional, Tuple

from core.kill_chain.models import (
    KillChainStageEnum,
    KillChainFinding,
    EvidenceItem,
    ThreatIndicator,
    StageAnalysisResult,
    StageStatusEnum,
    SeverityEnum,
    ConfidenceLevelEnum,
)


class BaseStageAnalyzer(abc.ABC):
    """Abstract interface and common utilities for Kill Chain stage analyzers."""

    stage: KillChainStageEnum
    stage_number: int
    title: str
    objective: str
    mitre_tactic: str
    detection_capabilities: List[str]
    default_controls: List[Dict[str, str]]

    @abc.abstractmethod
    def analyze(self, telemetry: Dict[str, Any], asset_context: Optional[Dict[str, Any]] = None) -> StageAnalysisResult:
        """Executes defensive inspection for this stage against ingested telemetry or scans."""
        pass

    def calculate_risk(
        self,
        impact_weight: float,       # 1.0 (Low) to 10.0 (Critical)
        likelihood: float,          # 0.1 to 1.0
        asset_criticality: float = 1.0,  # 0.5 (Dev) to 1.5 (Production/Crown Jewels)
        exploitability: float = 1.0,     # 0.5 (Theoretical) to 1.5 (Active in wild / CISA KEV)
        exposure: float = 1.0,           # 0.5 (Internal isolated) to 1.5 (Public internet facing)
    ) -> float:
        """
        Documented risk scoring methodology:
        Risk = min(100.0, impact_weight * 10 * likelihood * asset_criticality * exploitability * exposure / 1.5)
        Separates risk from confidence.
        """
        base_score = (impact_weight * 10.0) * likelihood
        multiplier = (asset_criticality * exploitability * exposure) / 1.5
        score = base_score * multiplier
        return round(max(5.0, min(100.0, score)), 1)

    def calculate_confidence(
        self,
        evidence_quality: float,    # 0.5 (Inferred/Heuristic) to 1.0 (Direct cryptographic/binary proof)
        source_reliability: float,  # 0.6 (Third party/crowdsourced) to 1.0 (Direct local kernel/scanner)
        corroboration_count: int,   # 1 to N sources agreeing
        completeness: float = 1.0   # 0.5 (Partial headers) to 1.0 (Full payload/PCAP/AST)
    ) -> Tuple[ConfidenceLevelEnum, float]:
        """
        Documented confidence scoring methodology:
        Confidence = min(100.0, (evidence_quality * 0.4 + source_reliability * 0.3 + min(corroboration_count, 3) * 0.1 + completeness * 0.2) * 100)
        Never uses AI confidence as a substitute for verified evidence.
        """
        corroboration_factor = min(corroboration_count, 3) / 3.0
        raw = (evidence_quality * 0.40) + (source_reliability * 0.30) + (corroboration_factor * 0.15) + (completeness * 0.15)
        score = round(max(10.0, min(100.0, raw * 100.0)), 1)

        if score >= 85.0:
            level = ConfidenceLevelEnum.CONFIRMED
        elif score >= 65.0:
            level = ConfidenceLevelEnum.SUSPECTED
        elif score >= 40.0:
            level = ConfidenceLevelEnum.INFERRED
        else:
            level = ConfidenceLevelEnum.UNKNOWN

        return level, score

    def create_evidence(
        self,
        artifact_type: str,
        raw_data: str,
        normalized_data: Dict[str, Any],
        affected_asset: str,
        source_tool: str = "SWA Core",
        evidence_quality: float = 0.9,
    ) -> EvidenceItem:
        ev_id = f"ev_{self.stage.value[:4]}_{uuid.uuid4().hex[:8]}"
        ev_hash = hashlib.sha256(raw_data.encode("utf-8", errors="ignore")).hexdigest()
        conf_level, conf_score = self.calculate_confidence(
            evidence_quality=evidence_quality,
            source_reliability=0.9,
            corroboration_count=1,
            completeness=1.0,
        )
        return EvidenceItem(
            id=ev_id,
            stage=self.stage,
            artifact_type=artifact_type,
            raw_data=raw_data,
            normalized_data=normalized_data,
            source_tool=source_tool,
            affected_asset=affected_asset,
            evidence_hash=ev_hash,
            confidence_level=conf_level,
            confidence_score=conf_score,
            observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )

    def determine_stage_status(self, findings: List[KillChainFinding]) -> StageStatusEnum:
        """Computes stage color-coded status based on findings severity."""
        if not findings:
            return StageStatusEnum.PROTECTED

        severities = [f.severity for f in findings]
        if SeverityEnum.CRITICAL in severities:
            return StageStatusEnum.CRITICAL
        elif SeverityEnum.HIGH in severities:
            return StageStatusEnum.HIGH
        elif SeverityEnum.MEDIUM in severities:
            return StageStatusEnum.MEDIUM
        elif SeverityEnum.LOW in severities:
            return StageStatusEnum.LOW
        return StageStatusEnum.PROTECTED
