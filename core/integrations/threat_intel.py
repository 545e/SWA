"""
SWA AI — Threat Intelligence Provider Adapters
Implements concrete adapters for VirusTotal, AbuseIPDB, Shodan, Censys, AlienVault OTX, and URLhaus.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
import httpx
from core.integrations.base import BaseIntegrationAdapter


class VirusTotalAdapter(BaseIntegrationAdapter):
    provider_id = "virustotal"
    display_name = "VirusTotal"
    category = "threat_intel"
    description = "Analyze suspicious files, domains, IPs and URLs to detect malware and breaches."
    documentation_url = "https://developers.virustotal.com/reference/overview"
    required_permissions = ["Standard API v3 User Access"]
    setup_instructions = (
        "1. Create a VirusTotal account at virustotal.com.\n"
        "2. Navigate to your user profile -> API Key.\n"
        "3. Copy your 64-character API key and paste it below."
    )

    def get_credential_fields(self) -> List[Dict[str, Any]]:
        return [
            {"key": "api_key", "label": "API Key", "type": "password", "required": True, "placeholder": "Enter VirusTotal v3 API Key"}
        ]

    async def test_connection(self, credentials: Dict[str, str], endpoint_url: Optional[str] = None) -> Dict[str, Any]:
        api_key = credentials.get("api_key", "").strip()
        if not api_key:
            return {"success": False, "status": "NOT_CONFIGURED", "message": "VirusTotal API key is missing.", "latency_ms": 0}
        
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get(
                    "https://www.virustotal.com/api/v3/users/current",
                    headers={"x-apikey": api_key}
                )
                latency = int((time.perf_counter() - start) * 1000)
                if res.status_code == 200:
                    user_data = res.json().get("data", {}).get("attributes", {})
                    return {
                        "success": True,
                        "status": "CONNECTED",
                        "message": f"Successfully connected as {user_data.get('user_id', 'authenticated user')}.",
                        "latency_ms": latency,
                        "details": {"quota": user_data.get("quotas", {})}
                    }
                elif res.status_code in (401, 403):
                    return {"success": False, "status": "AUTHENTICATION_FAILED", "message": "Invalid API key or unauthorized access.", "latency_ms": latency}
                else:
                    return {"success": False, "status": "ERROR", "message": f"VirusTotal responded with HTTP {res.status_code}.", "latency_ms": latency}
        except httpx.RequestError as exc:
            latency = int((time.perf_counter() - start) * 1000)
            return {"success": False, "status": "UNREACHABLE", "message": f"Connection to VirusTotal timed out or failed: {exc}", "latency_ms": latency}


class AbuseIPDBAdapter(BaseIntegrationAdapter):
    provider_id = "abuseipdb"
    display_name = "AbuseIPDB"
    category = "threat_intel"
    description = "Check IP address abuse confidence scores and reported malicious activity."
    documentation_url = "https://docs.abuseipdb.com/"
    required_permissions = ["Check IP Endpoint Access"]
    setup_instructions = (
        "1. Register at abuseipdb.com and create a Webmaster account.\n"
        "2. Go to the API tab in Account settings.\n"
        "3. Generate a key and paste it below."
    )

    def get_credential_fields(self) -> List[Dict[str, Any]]:
        return [
            {"key": "api_key", "label": "API Key", "type": "password", "required": True, "placeholder": "Enter AbuseIPDB Key"}
        ]

    async def test_connection(self, credentials: Dict[str, str], endpoint_url: Optional[str] = None) -> Dict[str, Any]:
        api_key = credentials.get("api_key", "").strip()
        if not api_key:
            return {"success": False, "status": "NOT_CONFIGURED", "message": "AbuseIPDB API key missing.", "latency_ms": 0}
        
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": api_key, "Accept": "application/json"},
                    params={"ipAddress": "1.1.1.1", "maxAgeInDays": 90}
                )
                latency = int((time.perf_counter() - start) * 1000)
                if res.status_code == 200:
                    return {"success": True, "status": "CONNECTED", "message": "AbuseIPDB query succeeded.", "latency_ms": latency}
                elif res.status_code in (401, 403):
                    return {"success": False, "status": "AUTHENTICATION_FAILED", "message": "Invalid AbuseIPDB key.", "latency_ms": latency}
                else:
                    return {"success": False, "status": "ERROR", "message": f"AbuseIPDB returned HTTP {res.status_code}.", "latency_ms": latency}
        except Exception as exc:
            latency = int((time.perf_counter() - start) * 1000)
            return {"success": False, "status": "UNREACHABLE", "message": str(exc), "latency_ms": latency}


class ShodanAdapter(BaseIntegrationAdapter):
    provider_id = "shodan"
    display_name = "Shodan"
    category = "threat_intel"
    description = "Search engine for Internet-connected devices, exposed services, and banner grab intelligence."
    documentation_url = "https://developer.shodan.io/api"
    required_permissions = ["API Query Access"]
    setup_instructions = (
        "1. Login to your Shodan account.\n"
        "2. Copy the API Key shown at account.shodan.io.\n"
        "3. Paste into the API Key field."
    )

    def get_credential_fields(self) -> List[Dict[str, Any]]:
        return [
            {"key": "api_key", "label": "API Key", "type": "password", "required": True, "placeholder": "Enter Shodan API Key"}
        ]

    async def test_connection(self, credentials: Dict[str, str], endpoint_url: Optional[str] = None) -> Dict[str, Any]:
        api_key = credentials.get("api_key", "").strip()
        if not api_key:
            return {"success": False, "status": "NOT_CONFIGURED", "message": "Shodan API key missing.", "latency_ms": 0}
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get(f"https://api.shodan.io/api-info?key={api_key}")
                latency = int((time.perf_counter() - start) * 1000)
                if res.status_code == 200:
                    data = res.json()
                    return {"success": True, "status": "CONNECTED", "message": f"Shodan connected. Query credits: {data.get('query_credits', 0)}", "latency_ms": latency}
                elif res.status_code in (401, 403):
                    return {"success": False, "status": "AUTHENTICATION_FAILED", "message": "Invalid Shodan key.", "latency_ms": latency}
                return {"success": False, "status": "ERROR", "message": f"Shodan HTTP {res.status_code}", "latency_ms": latency}
        except Exception as exc:
            return {"success": False, "status": "UNREACHABLE", "message": str(exc), "latency_ms": int((time.perf_counter() - start) * 1000)}


class CensysAdapter(BaseIntegrationAdapter):
    provider_id = "censys"
    display_name = "Censys Search"
    category = "threat_intel"
    description = "Attack surface management and internet asset discovery intelligence."
    documentation_url = "https://search.censys.io/api"
    required_permissions = ["Search API Access"]
    setup_instructions = (
        "1. Register at search.censys.io.\n"
        "2. Go to Account -> API.\n"
        "3. Copy your API ID and API Secret."
    )

    def get_credential_fields(self) -> List[Dict[str, Any]]:
        return [
            {"key": "api_id", "label": "API ID", "type": "text", "required": True, "placeholder": "Censys API ID"},
            {"key": "api_secret", "label": "API Secret", "type": "password", "required": True, "placeholder": "Censys API Secret"}
        ]

    async def test_connection(self, credentials: Dict[str, str], endpoint_url: Optional[str] = None) -> Dict[str, Any]:
        api_id = credentials.get("api_id", "").strip()
        api_secret = credentials.get("api_secret", "").strip()
        if not api_id or not api_secret:
            return {"success": False, "status": "NOT_CONFIGURED", "message": "Censys ID and Secret required.", "latency_ms": 0}
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get("https://search.censys.io/api/v1/account", auth=(api_id, api_secret))
                latency = int((time.perf_counter() - start) * 1000)
                if res.status_code == 200:
                    return {"success": True, "status": "CONNECTED", "message": "Censys API authenticated.", "latency_ms": latency}
                return {"success": False, "status": "AUTHENTICATION_FAILED", "message": "Invalid Censys credentials.", "latency_ms": latency}
        except Exception as exc:
            return {"success": False, "status": "UNREACHABLE", "message": str(exc), "latency_ms": int((time.perf_counter() - start) * 1000)}


class AlienVaultOTXAdapter(BaseIntegrationAdapter):
    provider_id = "alienvault_otx"
    display_name = "AlienVault OTX"
    category = "threat_intel"
    description = "Open Threat Exchange community indicators of compromise (IOCs) and pulses."
    documentation_url = "https://otx.alienvault.com/api"
    required_permissions = ["OTX User Access"]
    setup_instructions = "1. Sign up at otx.alienvault.com.\n2. Obtain API Key from your profile page."

    def get_credential_fields(self) -> List[Dict[str, Any]]:
        return [
            {"key": "api_key", "label": "OTX Key", "type": "password", "required": True, "placeholder": "Enter OTX Key"}
        ]

    async def test_connection(self, credentials: Dict[str, str], endpoint_url: Optional[str] = None) -> Dict[str, Any]:
        api_key = credentials.get("api_key", "").strip()
        if not api_key:
            return {"success": False, "status": "NOT_CONFIGURED", "message": "OTX API key missing.", "latency_ms": 0}
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get("https://otx.alienvault.com/api/v1/user/me", headers={"X-OTX-API-KEY": api_key})
                latency = int((time.perf_counter() - start) * 1000)
                if res.status_code == 200:
                    return {"success": True, "status": "CONNECTED", "message": f"OTX user verified: {res.json().get('username')}", "latency_ms": latency}
                return {"success": False, "status": "AUTHENTICATION_FAILED", "message": "OTX Key rejected.", "latency_ms": latency}
        except Exception as exc:
            return {"success": False, "status": "UNREACHABLE", "message": str(exc), "latency_ms": int((time.perf_counter() - start) * 1000)}


class URLhausAdapter(BaseIntegrationAdapter):
    provider_id = "urlhaus"
    display_name = "URLhaus (abuse.ch)"
    category = "threat_intel"
    description = "Malicious URL feed and payload tracking maintained by abuse.ch."
    documentation_url = "https://urlhaus.abuse.ch/api/"
    required_permissions = ["Public API Access (Optional Auth Key for elevated limits)"]
    setup_instructions = "1. URLhaus provides public access; enter an Auth-Key if available to raise rate limits."

    def get_credential_fields(self) -> List[Dict[str, Any]]:
        return [
            {"key": "auth_key", "label": "Auth-Key (Optional)", "type": "password", "required": False, "placeholder": "Optional abuse.ch API Key"}
        ]

    async def test_connection(self, credentials: Dict[str, str], endpoint_url: Optional[str] = None) -> Dict[str, Any]:
        auth_key = credentials.get("auth_key", "").strip()
        headers = {"Auth-Key": auth_key} if auth_key else {}
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get("https://urlhaus-api.abuse.ch/v1/urls/recent/", headers=headers)
                latency = int((time.perf_counter() - start) * 1000)
                if res.status_code == 200:
                    return {"success": True, "status": "CONNECTED", "message": "URLhaus feed is reachable and operational.", "latency_ms": latency}
                return {"success": False, "status": "ERROR", "message": f"URLhaus returned HTTP {res.status_code}", "latency_ms": latency}
        except Exception as exc:
            return {"success": False, "status": "UNREACHABLE", "message": str(exc), "latency_ms": int((time.perf_counter() - start) * 1000)}
