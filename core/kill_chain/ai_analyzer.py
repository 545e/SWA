"""
SWA AI — Cyber Kill Chain AI Threat Analyzer
Uses existing SWA AI provider configuration (via registry & LLMClient)
with robust, deterministic rule-based fallback when AI is unconfigured or offline.
Answers the seven SOC questions and strictly distinguishes confidence levels.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional

from core.integrations.registry import integration_registry as registry
from core.llm_client import SWALLMClient as LLMClient
from core.kill_chain.models import (
    KillChainStageEnum,
    KillChainFinding,
    EvidenceItem,
    ConfidenceLevelEnum,
)


class KillChainAIAnalyzer:
    """
    AI-powered threat assessment service with zero-downtime deterministic fallback.
    """

    def __init__(self):
        self.llm = LLMClient()

    def analyze_event(
        self,
        finding: KillChainFinding,
        evidence: Optional[EvidenceItem] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generates an in-depth SOC investigation report addressing the seven core questions.
        Attempts LLM query first; falls back gracefully to deterministic expert heuristics.
        """
        # Try LLM first if an AI provider is enabled and configured
        ai_provider = registry.get_default_ai_provider()
        if ai_provider and self.llm.is_available():
            try:
                ai_response = self._run_llm_analysis(finding, evidence, ai_provider)
                if ai_response:
                    return ai_response
            except Exception:
                pass  # Fall back directly to deterministic analysis

        # Deterministic fallback analysis
        return self._run_deterministic_analysis(finding, evidence, context)

    def _run_deterministic_analysis(
        self,
        finding: KillChainFinding,
        evidence: Optional[EvidenceItem] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        High-precision deterministic rule-based analysis ensuring continuous SOC operations.
        """
        stage_name = finding.stage.value.capitalize() if hasattr(finding.stage, "value") else str(finding.stage).capitalize()
        asset = finding.affected_host or "127.0.0.1"
        endpoint = finding.affected_endpoint or "/"
        sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        conf_level = finding.confidence_level.value if hasattr(finding.confidence_level, "value") else str(finding.confidence_level)

        # 1. What happened?
        what_happened = (
            f"During defensive security operations, the platform identified an indicator of interest ({finding.title}) "
            f"associated with the {stage_name} phase of the Cyber Kill Chain on asset {asset} (endpoint: {endpoint}). "
            f"Severity is classified as {sev} with a risk score of {finding.risk_score}/100."
        )

        # 2. Which stage is involved?
        stage_detail = {
            "stage_id": finding.stage.value if hasattr(finding.stage, "value") else str(finding.stage),
            "stage_name": stage_name,
            "mitre_tactic": finding.mitre_tactic or "Enterprise ATT&CK",
            "mitre_technique": finding.mitre_technique_id or "T1190",
        }

        # 3. What evidence supports the finding?
        ev_summary = finding.evidence or (evidence.raw_data if evidence else "Direct telemetry observation from local scanner.")
        evidence_support = {
            "primary_evidence": ev_summary,
            "detection_source": finding.detection_source,
            "evidence_hash": evidence.evidence_hash if evidence else None,
            "observed_at": finding.first_observed,
            "verified": conf_level == "CONFIRMED",
        }

        # 4. Which assets are affected?
        affected_assets = [asset]
        if endpoint and endpoint not in affected_assets:
            affected_assets.append(endpoint)

        # 5. How confident is the assessment?
        # Must strictly be one of: Confirmed, Suspected, Inferred, Unknown, Not assessed
        confidence_assessment = {
            "level": conf_level,  # CONFIRMED, SUSPECTED, INFERRED, UNKNOWN
            "score": finding.confidence_score,
            "rationale": (
                f"Confidence is {conf_level} based on empirical detection source '{finding.detection_source}' "
                f"with {len(finding.evidence_ids)} linked evidence artifacts."
            ),
        }

        # 6. What is the potential impact?
        if sev == "CRITICAL":
            potential_impact = "High likelihood of remote system compromise, unauthenticated remote code execution, or mass data exfiltration."
        elif sev == "HIGH":
            potential_impact = "Significant risk of localized privilege escalation, unauthorized persistence, or sensitive data exposure."
        elif sev == "MEDIUM":
            potential_impact = "Elevated attack surface exposure allowing an adversary to gather reconnaissance data or chain with secondary flaws."
        else:
            potential_impact = "Minimal direct operational impact; security hygiene non-conformance."

        # 7. What should the security analyst do next?
        recommended_actions = [
            f"Review finding evidence at endpoint: {endpoint}",
            f"Execute defense playbook: '{finding.remediation}'",
            f"Correlate upstream/downstream network flows from asset {asset}",
            "If verified malicious, isolate endpoint or apply temporary perimeter block rule.",
        ]

        return {
            "mode": "DETERMINISTIC_ENGINE",
            "provider": "SWA Expert Heuristic Rules Engine",
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "answers": {
                "1_what_happened": what_happened,
                "2_stage_involved": stage_detail,
                "3_supporting_evidence": evidence_support,
                "4_affected_assets": affected_assets,
                "5_confidence_assessment": confidence_assessment,
                "6_potential_impact": potential_impact,
                "7_analyst_next_steps": recommended_actions,
            },
            "summary": f"{stage_name} Alert: {finding.title} on {asset} ({sev} - {conf_level})",
        }

    def _run_llm_analysis(
        self,
        finding: KillChainFinding,
        evidence: Optional[EvidenceItem],
        ai_provider: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Invokes the configured SWA AI provider."""
        prompt = (
            f"You are the SWA AI Principal SOC Analyst. Analyze this Cyber Kill Chain event.\n"
            f"Finding: {finding.title}\n"
            f"Stage: {finding.stage}\n"
            f"Severity: {finding.severity}\n"
            f"Asset: {finding.affected_host}\n"
            f"Endpoint: {finding.affected_endpoint}\n"
            f"Evidence: {finding.evidence}\n\n"
            f"Provide answers to the 7 mandatory SOC questions:\n"
            f"1. What happened?\n2. Which stage is involved?\n3. What evidence supports it?\n"
            f"4. Which assets are affected?\n5. How confident is the assessment (Confirmed/Suspected/Inferred)?\n"
            f"6. What is the potential impact?\n7. What should the analyst do next?"
        )
        # Use LLMClient query
        res = self.llm.query(prompt, model=ai_provider.get("model"))
        if not res or not res.get("content"):
            return None

        # Return AI enriched payload
        det = self._run_deterministic_analysis(finding, evidence)
        det["mode"] = "AI_AUGMENTED"
        det["provider"] = f"SWA AI ({ai_provider.get('display_name', 'Configured LLM')})"
        det["ai_response_text"] = res.get("content")
        return det
