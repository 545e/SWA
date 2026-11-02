"""
SWA AI - Canonical Security Posture Scoring & Finding Normalization

This module is the single source of truth for severity penalties and letter
grades. The REST API, report generator and dashboard all consume the same
formula so a scan can never show two different grades in two places.

Scoring model (transparent and additive):
    CRITICAL -30, HIGH -18, MEDIUM -8, LOW -3, INFO -1
    score = clamp(100 - sum(penalties), 0, 100)

Grade bands:
    A >= 90, B >= 75, C >= 60, D >= 40, F < 40
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

SEVERITY_WEIGHTS: Dict[str, int] = {
    "CRITICAL": 30,
    "HIGH": 18,
    "MEDIUM": 8,
    "LOW": 3,
    "INFO": 1,
}

GRADE_BANDS: List[Tuple[int, str, str, str]] = [
    (90, "A", "#10b981", "LOW RISK - Strong Security Posture"),
    (75, "B", "#3b82f6", "MODERATE RISK - Standard Defenses Active"),
    (60, "C", "#eab308", "ELEVATED RISK - Remediation Recommended"),
    (40, "D", "#f97316", "HIGH RISK - Multiple Exposures Detected"),
    (0, "F", "#ef4444", "CRITICAL RISK - Immediate Triage Required"),
]

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _severity_of(finding: Any) -> str:
    sev = getattr(finding, "severity", finding)
    return str(getattr(sev, "value", sev) or "").strip().upper()


def severity_counts(findings: Iterable[Any]) -> Dict[str, int]:
    """Count findings by canonical severity name."""
    counts = {sev: 0 for sev in _SEVERITIES}
    for finding in findings:
        sev = _severity_of(finding)
        if sev in counts:
            counts[sev] += 1
    counts["TOTAL"] = sum(counts[sev] for sev in _SEVERITIES)
    return counts


def compute_posture(findings: Optional[Iterable[Any]] = None,
                    counts: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    """Compute the canonical score/grade for a collection of findings or counts."""
    if counts is None:
        counts = severity_counts(findings or [])

    penalty = sum(int(counts.get(sev, 0) or 0) * weight for sev, weight in SEVERITY_WEIGHTS.items())
    score = max(0, min(100, 100 - penalty))

    band = GRADE_BANDS[-1]
    for threshold, grade, color, risk in GRADE_BANDS:
        if score >= threshold:
            band = (threshold, grade, color, risk)
            break
    _, grade, color, risk = band

    return {
        "score": score,
        "grade": grade,
        "grade_color": color,
        "risk": risk,
        "penalties": {sev: int(counts.get(sev, 0) or 0) * weight for sev, weight in SEVERITY_WEIGHTS.items()},
        "counts": {sev: int(counts.get(sev, 0) or 0) for sev in _SEVERITIES},
        "total": int(counts.get("TOTAL", sum(int(counts.get(s, 0) or 0) for s in _SEVERITIES))),
    }


def normalize_endpoint(endpoint: Optional[str]) -> str:
    """Host + path, lower-cased, query/fragment stripped, for stable dedup keys."""
    raw = (endpoint or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlparse(raw if "://" in raw else "//" + raw.lstrip("/"))
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "/").rstrip("/") or "/"
        return f"{host}{path}".lower()
    except Exception:
        return raw.lower()


def canonical_finding_key(finding: Any) -> Tuple[str, str, str]:
    """Cross-source deduplication key: normalized title + endpoint + parameter."""
    title = re.sub(r"[^a-z0-9]+", " ", str(getattr(finding, "title", "") or "").lower()).strip()
    parameter = str(getattr(finding, "parameter", "") or "").lower().strip()
    return title, normalize_endpoint(getattr(finding, "endpoint", "")), parameter


def finding_evidence_hash(finding: Any) -> str:
    material = "|".join([
        str(getattr(finding, "scan_id", "") or ""),
        str(getattr(finding, "title", "") or ""),
        str(getattr(finding, "endpoint", "") or ""),
        str(getattr(finding, "parameter", "") or ""),
        str(getattr(finding, "request_evidence", "") or "")[:500],
    ])
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:16]


def deduplicate_findings(findings: Iterable[Any]) -> List[Any]:
    """Keep the highest-confidence/first occurrence of each logical finding."""
    seen: Dict[Tuple[str, str, str], Any] = {}
    for finding in findings:
        if getattr(finding, "verified", True) is False:
            continue
        key = canonical_finding_key(finding)
        if key not in seen:
            seen[key] = finding
    return list(seen.values())


def severity_from_score(cvss: float) -> str:
    """Map a CVSS base score to a severity label (defensive fallback only)."""
    try:
        cvss = float(cvss)
    except (TypeError, ValueError):
        return "INFO"
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    if cvss > 0.0:
        return "LOW"
    return "INFO"
