"""
SWA AI — Live threat-intelligence fetchers with short-term caching.

Real, keyless public feeds:
- CISA Known Exploited Vulnerabilities (KEV) catalog (JSON)
- FIRST.org EPSS (Exploit Prediction Scoring System) API

Both raise ThreatIntelUnavailable when the feed cannot be reached or
returns unexpected data. Callers MUST surface that as an error/status,
never as fabricated data.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger("swa.threat_intel_live")

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

_CACHE_TTL_SEC = 3600
_cache: Dict[str, Dict[str, Any]] = {}


class ThreatIntelUnavailable(Exception):
    """Raised when a live threat-intel feed cannot be fetched."""


def _cache_get(key: str) -> Optional[Any]:
    entry = _cache.get(key)
    if entry and (time.time() - entry["ts"]) < _CACHE_TTL_SEC:
        return entry["data"]
    return None


def _cache_put(key: str, data: Any) -> None:
    _cache[key] = {"ts": time.time(), "data": data}


async def get_cisa_kev(cve: Optional[str] = None) -> Dict[str, Any]:
    raw = _cache_get("kev")
    if raw is None:
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                resp = await client.get(KEV_FEED_URL)
                resp.raise_for_status()
                raw = resp.json()
        except Exception as exc:
            raise ThreatIntelUnavailable(f"CISA KEV feed unreachable: {exc}") from exc
        if not isinstance(raw, dict) or "vulnerabilities" not in raw:
            raise ThreatIntelUnavailable("CISA KEV feed returned an unexpected payload shape.")
        _cache_put("kev", raw)

    vulns = raw.get("vulnerabilities", [])
    catalog_meta = {
        "catalog": "CISA KEV",
        "feed_url": KEV_FEED_URL,
        "catalog_version": raw.get("catalogVersion"),
        "date_released": raw.get("dateReleased"),
        "count": len(vulns),
    }
    if not cve:
        return {**catalog_meta, "vulnerabilities": vulns[:25], "truncated_to": 25}
    cve_norm = cve.strip().upper()
    match = [v for v in vulns if str(v.get("cveID", "")).upper() == cve_norm]
    if match:
        v = match[0]
        return {
            **catalog_meta,
            "cve": cve_norm,
            "known_exploited": True,
            "vendor_project": v.get("vendorProject"),
            "product": v.get("product"),
            "vulnerability_name": v.get("vulnerabilityName"),
            "date_added": v.get("dateAdded"),
            "short_description": v.get("shortDescription"),
            "required_action": v.get("requiredAction"),
            "due_date": v.get("dueDate"),
            "known_ransomware_campaign_use": v.get("knownRansomwareCampaignUse"),
            "notes": v.get("notes"),
        }
    return {**catalog_meta, "cve": cve_norm, "known_exploited": False,
            "note": "CVE not present in the CISA KEV catalog as of the cached feed release."}


async def get_first_epss(cve: str) -> Dict[str, Any]:
    cve_norm = (cve or "").strip().upper()
    if not cve_norm.startswith("CVE-"):
        raise ThreatIntelUnavailable("EPSS requires a CVE identifier like CVE-2021-44228.")
    cache_key = f"epss:{cve_norm}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(EPSS_API_URL, params={"cve": cve_norm})
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        raise ThreatIntelUnavailable(f"FIRST EPSS API unreachable: {exc}") from exc

    rows = data.get("data") or []
    if not rows:
        result = {"cve": cve_norm, "found": False,
                  "note": "FIRST EPSS returned no data for this CVE.",
                  "model_version": data.get("model_version")}
    else:
        row = rows[0]
        try:
            epss_score = float(row.get("epss"))
            percentile = float(row.get("percentile"))
        except (TypeError, ValueError):
            raise ThreatIntelUnavailable("FIRST EPSS returned non-numeric scores.")
        result = {
            "cve": cve_norm,
            "found": True,
            "epss_score": epss_score,
            "percentile": percentile,
            "date": row.get("date"),
            "model_version": data.get("model_version"),
            "feed_url": EPSS_API_URL,
        }
    _cache_put(cache_key, result)
    return result
