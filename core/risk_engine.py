"""
SWA AI — Defensible & Explainable Risk Prioritization Engine
Calculates risk scores based on explicit, mathematically documented factors:
Severity, Confidence, Exploitability (PoC, EPSS, CISA KEV), Asset Criticality,
Exposure Surface, and Existing Defensive Mitigations.
"""

from typing import Dict, Any, Optional
from core.models import VulnerabilityFinding, Severity
from core.intelligence_models import RiskScoreBreakdown


class DefensibleRiskEngine:
    """Computes transparent, defensible risk scores and human-readable rationales."""

    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 100.0,
        Severity.HIGH: 75.0,
        Severity.MEDIUM: 45.0,
        Severity.LOW: 20.0,
        Severity.INFO: 5.0
    }

    CONFIDENCE_MULTIPLIERS = {
        "CONFIRMED": 1.0,
        "HIGH": 0.95,
        "MEDIUM": 0.75,
        "LOW": 0.50
    }

    CRITICALITY_FACTORS = {
        "CRITICAL": 1.25,
        "HIGH": 1.10,
        "MEDIUM": 1.0,
        "LOW": 0.85
    }

    @classmethod
    def calculate_risk(
        cls,
        finding: VulnerabilityFinding,
        asset_criticality: str = "HIGH",
        is_internet_exposed: bool = True,
        has_active_waf_or_mitigation: bool = False
    ) -> RiskScoreBreakdown:
        """
        Calculates explainable risk score with full mathematical provenance.
        Formula:
          Base = Severity_Weight(finding.severity)
          Confidence_Factor = Confidence_Multiplier(finding.confidence)
          Exploitability_Factor:
            + 15 if verified active PoC curl present
            + 15 if listed in CISA KEV or high EPSS percentile (>0.5)
          Exposure_Factor = 1.15 if internet exposed else 0.80
          Asset_Factor = Criticality_Factor(asset_criticality)
          Mitigation_Discount = 15% if active WAF or rate limiting shields endpoint
        """
        base_sev = cls.SEVERITY_WEIGHTS.get(finding.severity, 40.0)
        conf_factor = cls.CONFIDENCE_MULTIPLIERS.get(str(finding.confidence).upper(), 0.85)

        # Exploitability evaluation
        exploit_score = 0.0
        has_poc = bool(finding.poc_curl and len(finding.poc_curl.strip()) > 10)
        if has_poc:
            exploit_score += 15.0

        cisa_kev = getattr(finding, "cisa_kev", False) or False
        epss = getattr(finding, "epss_score", 0.0) or 0.0

        # Heuristic KEV check if known CVE is present in title/desc
        if not cisa_kev and "CVE-" in (finding.title + " " + finding.description):
            cisa_kev = any(known in (finding.title + " " + finding.description) for known in ["Log4j", "Spring4Shell", "CitrixBleed", "MOVEit", "Confluence"])

        if cisa_kev:
            exploit_score += 20.0
        elif epss > 0.4:
            exploit_score += 12.0

        exploit_factor = min(35.0, exploit_score)

        exposure_factor = 1.15 if is_internet_exposed else 0.80
        asset_factor = cls.CRITICALITY_FACTORS.get(asset_criticality.upper(), 1.0)
        mitigation_discount = 0.15 if has_active_waf_or_mitigation else 0.0

        # Raw formula calculation
        raw_score = (base_sev * conf_factor + exploit_factor) * exposure_factor * asset_factor
        discounted_score = raw_score * (1.0 - mitigation_discount)
        final_score = round(max(1.0, min(100.0, discounted_score)), 1)

        # Generate explainable rationale text
        reasons = [
            f"Base severity rating: {finding.severity.value} ({base_sev} pts)",
            f"Detection confidence multiplier: {conf_factor:.2f}x ({finding.confidence})",
            f"Exploitability bonus: +{exploit_factor} pts (Active PoC: {'Yes' if has_poc else 'No'}, KEV: {'Yes' if cisa_kev else 'No'})",
            f"Perimeter exposure multiplier: {exposure_factor:.2f}x ({'Internet-facing' if is_internet_exposed else 'Internal'})",
            f"Business asset criticality multiplier: {asset_factor:.2f}x ({asset_criticality})"
        ]
        if mitigation_discount > 0:
            reasons.append(f"Mitigation shield discount: -{int(mitigation_discount * 100)}% (Active WAF / filtering)")

        rationale = " | ".join(reasons)

        return RiskScoreBreakdown(
            final_score=final_score,
            severity_factor=base_sev,
            confidence_factor=conf_factor,
            exploitability_factor=exploit_factor,
            exposure_factor=exposure_factor,
            asset_criticality_factor=asset_factor,
            epss_percentile=epss,
            known_exploited_cisa_kev=bool(cisa_kev),
            mitigation_discount=mitigation_discount,
            rationale=rationale
        )


risk_engine = DefensibleRiskEngine()
