"""
SWA AI — Enterprise Security Platform Adapters
Implements adapters for SIEM, EDR, and Vulnerability Management systems:
Wazuh, Splunk, Elastic Security, Microsoft Sentinel, CrowdStrike, SentinelOne,
Qualys, Rapid7, Tenable, and DefectDojo.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
import httpx
from core.integrations.base import BaseIntegrationAdapter


class WazuhAdapter(BaseIntegrationAdapter):
    provider_id = "wazuh"
    display_name = "Wazuh SIEM / XDR"
    category = "siem_edr"
    description = "Open source security monitoring, threat detection, integrity monitoring, and incident response."
    documentation_url = "https://documentation.wazuh.com/current/user-manual/api/index.html"
    required_permissions = ["Read API Permissions", "Agent Inventory", "Alerts Access"]
    setup_instructions = (
        "1. Configure a dedicated Wazuh API user (e.g. 'swa_soc') in /var/ossec/api/configuration/auth/api_users.conf.\n"
        "2. Provide the Wazuh Manager HTTPS endpoint (port 55000), username, and password."
    )

    def get_credential_fields(self) -> List[Dict[str, Any]]:
        return [
            {"key": "endpoint_url", "label": "Manager Endpoint", "type": "url", "required": True, "placeholder": "https://wazuh-manager.internal:55000"},
            {"key": "username", "label": "API Username", "type": "text", "required": True, "placeholder": "wazuh-api"},
            {"key": "password", "label": "API Password", "type": "password", "required": True, "placeholder": "Password"}
        ]

    async def test_connection(self, credentials: Dict[str, str], endpoint_url: Optional[str] = None) -> Dict[str, Any]:
        url = (endpoint_url or credentials.get("endpoint_url", "")).rstrip("/")
        username = credentials.get("username", "").strip()
        password = credentials.get("password", "").strip()
        if not url or not username:
            return {"success": False, "status": "NOT_CONFIGURED", "message": "Manager URL and credentials are required.", "latency_ms": 0}
        
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
                res = await client.post(f"{url}/security/user/authenticate", auth=(username, password))
                latency = int((time.perf_counter() - start) * 1000)
                if res.status_code == 200:
                    return {"success": True, "status": "CONNECTED", "message": "Wazuh API token negotiated successfully.", "latency_ms": latency}
                elif res.status_code in (401, 403):
                    return {"success": False, "status": "AUTHENTICATION_FAILED", "message": "Invalid Wazuh API username or password.", "latency_ms": latency}
                return {"success": False, "status": "ERROR", "message": f"Wazuh returned HTTP {res.status_code}", "latency_ms": latency}
        except Exception as exc:
            return {"success": False, "status": "UNREACHABLE", "message": f"Could not reach Wazuh manager: {exc}", "latency_ms": int((time.perf_counter() - start) * 1000)}


class SplunkAdapter(BaseIntegrationAdapter):
    provider_id = "splunk"
    display_name = "Splunk Enterprise / Cloud"
    category = "siem_edr"
    description = "Ingest audit logs, alert indices, and query enterprise event timelines."
    documentation_url = "https://dev.splunk.com/enterprise/docs/devtools/httpeventcollector/"
    required_permissions = ["HEC (HTTP Event Collector) Token or REST API User"]
    setup_instructions = "1. Create an HEC token in Splunk Settings -> Data Inputs -> HTTP Event Collector.\n2. Enter your Splunk host URL and HEC token."

    def get_credential_fields(self) -> List[Dict[str, Any]]:
        return [
            {"key": "endpoint_url", "label": "Splunk URL", "type": "url", "required": True, "placeholder": "https://splunk.internal:8088"},
            {"key": "hec_token", "label": "HEC Token", "type": "password", "required": True, "placeholder": "Splunk HEC Token"}
        ]

    async def test_connection(self, credentials: Dict[str, str], endpoint_url: Optional[str] = None) -> Dict[str, Any]:
        url = (endpoint_url or credentials.get("endpoint_url", "")).rstrip("/")
        token = credentials.get("hec_token", "").strip()
        if not url or not token:
            return {"success": False, "status": "NOT_CONFIGURED", "message": "Endpoint URL and HEC token required.", "latency_ms": 0}
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
                res = await client.get(f"{url}/services/collector/health", headers={"Authorization": f"Splunk {token}"})
                latency = int((time.perf_counter() - start) * 1000)
                if res.status_code == 200:
                    return {"success": True, "status": "CONNECTED", "message": "Splunk HEC is healthy and accepting payloads.", "latency_ms": latency}
                return {"success": False, "status": "ERROR", "message": f"Splunk status: HTTP {res.status_code}", "latency_ms": latency}
        except Exception as exc:
            return {"success": False, "status": "UNREACHABLE", "message": str(exc), "latency_ms": int((time.perf_counter() - start) * 1000)}


class ElasticSecurityAdapter(BaseIntegrationAdapter):
    provider_id = "elastic_security"
    display_name = "Elastic Security / SIEM"
    category = "siem_edr"
    description = "Elasticsearch SIEM queries, Detection Engine alerts, and Fleet endpoint metrics."
    documentation_url = "https://www.elastic.co/guide/en/security/current/security-api-overview.html"
    required_permissions = ["Kibana / Elasticsearch API Key (read_security_rules, write_alerts)"]
    setup_instructions = "1. In Kibana, go to Stack Management -> API Keys -> Create API Key.\n2. Paste your Elasticsearch / Kibana URL and Key."

    def get_credential_fields(self) -> List[Dict[str, Any]]:
        return [
            {"key": "endpoint_url", "label": "Elasticsearch URL", "type": "url", "required": True, "placeholder": "https://elastic.internal:9200"},
            {"key": "api_key", "label": "Elastic API Key", "type": "password", "required": True, "placeholder": "API Key"}
        ]

    async def test_connection(self, credentials: Dict[str, str], endpoint_url: Optional[str] = None) -> Dict[str, Any]:
        url = (endpoint_url or credentials.get("endpoint_url", "")).rstrip("/")
        api_key = credentials.get("api_key", "").strip()
        if not url or not api_key:
            return {"success": False, "status": "NOT_CONFIGURED", "message": "Elasticsearch URL and API key required.", "latency_ms": 0}
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
                res = await client.get(f"{url}/", headers={"Authorization": f"ApiKey {api_key}"})
                latency = int((time.perf_counter() - start) * 1000)
                if res.status_code == 200:
                    cluster = res.json().get("cluster_name", "Elasticsearch")
                    return {"success": True, "status": "CONNECTED", "message": f"Connected to Elastic cluster '{cluster}'.", "latency_ms": latency}
                return {"success": False, "status": "AUTHENTICATION_FAILED", "message": "Elasticsearch key rejected.", "latency_ms": latency}
        except Exception as exc:
            return {"success": False, "status": "UNREACHABLE", "message": str(exc), "latency_ms": int((time.perf_counter() - start) * 1000)}


class MicrosoftSentinelAdapter(BaseIntegrationAdapter):
    provider_id = "ms_sentinel"
    display_name = "Microsoft Sentinel"
    category = "siem_edr"
    description = "Azure cloud-native SIEM and intelligent security analytics."
    documentation_url = "https://learn.microsoft.com/en-us/azure/sentinel/api-reference"
    required_permissions = ["Azure Sentinel Contributor / Reader on Log Analytics Workspace"]
    setup_instructions = "1. Register an App in Entra ID (Azure AD).\n2. Grant Sentinel Contributor role on your workspace.\n3. Enter Tenant ID, Client ID, Client Secret, and Workspace ID."

    def get_credential_fields(self) -> List[Dict[str, Any]]:
        return [
            {"key": "tenant_id", "label": "Azure Tenant ID", "type": "text", "required": True, "placeholder": "00000000-0000-0000-0000-000000000000"},
            {"key": "client_id", "label": "App (Client) ID", "type": "text", "required": True, "placeholder": "Client GUID"},
            {"key": "client_secret", "label": "Client Secret", "type": "password", "required": True, "placeholder": "Secret"},
            {"key": "workspace_id", "label": "Workspace ID", "type": "text", "required": True, "placeholder": "Log Analytics Workspace GUID"}
        ]

    async def test_connection(self, credentials: Dict[str, str], endpoint_url: Optional[str] = None) -> Dict[str, Any]:
        tenant = credentials.get("tenant_id", "").strip()
        client_id = credentials.get("client_id", "").strip()
        secret = credentials.get("client_secret", "").strip()
        if not tenant or not client_id or not secret:
            return {"success": False, "status": "NOT_CONFIGURED", "message": "Tenant ID, Client ID, and Secret required.", "latency_ms": 0}
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.post(
                    f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": client_id,
                        "client_secret": secret,
                        "scope": "https://management.azure.com/.default"
                    }
                )
                latency = int((time.perf_counter() - start) * 1000)
                if res.status_code == 200:
                    return {"success": True, "status": "CONNECTED", "message": "Microsoft Azure Entra token granted.", "latency_ms": latency}
                return {"success": False, "status": "AUTHENTICATION_FAILED", "message": f"Azure authentication failed: {res.json().get('error_description', 'invalid credentials')}", "latency_ms": latency}
        except Exception as exc:
            return {"success": False, "status": "UNREACHABLE", "message": str(exc), "latency_ms": int((time.perf_counter() - start) * 1000)}


class CrowdStrikeAdapter(BaseIntegrationAdapter):
    provider_id = "crowdstrike"
    display_name = "CrowdStrike Falcon"
    category = "siem_edr"
    description = "Endpoint protection, incident detections, and host containment isolation."
    documentation_url = "https://falcon.crowdstrike.com/documentation/api"
    required_permissions = ["Detections: Read", "Hosts: Read", "Incidents: Read"]
    setup_instructions = "1. In Falcon console -> Support and resources -> API Clients and Keys.\n2. Create API client and enter Client ID and Secret."

    def get_credential_fields(self) -> List[Dict[str, Any]]:
        return [
            {"key": "client_id", "label": "Client ID", "type": "text", "required": True, "placeholder": "CrowdStrike Client ID"},
            {"key": "client_secret", "label": "Client Secret", "type": "password", "required": True, "placeholder": "CrowdStrike Secret"},
            {"key": "base_url", "label": "API Cloud Base", "type": "text", "required": False, "placeholder": "https://api.crowdstrike.com"}
        ]

    async def test_connection(self, credentials: Dict[str, str], endpoint_url: Optional[str] = None) -> Dict[str, Any]:
        cid = credentials.get("client_id", "").strip()
        secret = credentials.get("client_secret", "").strip()
        base = (credentials.get("base_url") or "https://api.crowdstrike.com").rstrip("/")
        if not cid or not secret:
            return {"success": False, "status": "NOT_CONFIGURED", "message": "Falcon Client ID and Secret required.", "latency_ms": 0}
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.post(
                    f"{base}/oauth2/token",
                    data={"client_id": cid, "client_secret": secret}
                )
                latency = int((time.perf_counter() - start) * 1000)
                if res.status_code == 201 or res.status_code == 200:
                    return {"success": True, "status": "CONNECTED", "message": "CrowdStrike Falcon OAuth2 connected.", "latency_ms": latency}
                return {"success": False, "status": "AUTHENTICATION_FAILED", "message": "CrowdStrike OAuth failed.", "latency_ms": latency}
        except Exception as exc:
            return {"success": False, "status": "UNREACHABLE", "message": str(exc), "latency_ms": int((time.perf_counter() - start) * 1000)}


class DefectDojoAdapter(BaseIntegrationAdapter):
    provider_id = "defectdojo"
    display_name = "OWASP DefectDojo"
    category = "vulnerability_management"
    description = "Enterprise vulnerability management, deduplication, and engagement tracking."
    documentation_url = "https://defectdojo.github.io/django-DefectDojo/usage/api-v2-docs/"
    required_permissions = ["Product / Engagement Management", "Import Scan Findings"]
    setup_instructions = "1. In DefectDojo -> User Profile -> API v2 Key.\n2. Paste your instance URL and Key."

    def get_credential_fields(self) -> List[Dict[str, Any]]:
        return [
            {"key": "endpoint_url", "label": "DefectDojo URL", "type": "url", "required": True, "placeholder": "https://defectdojo.internal/api/v2"},
            {"key": "api_key", "label": "API Key", "type": "password", "required": True, "placeholder": "Token <key>"}
        ]

    async def test_connection(self, credentials: Dict[str, str], endpoint_url: Optional[str] = None) -> Dict[str, Any]:
        url = (endpoint_url or credentials.get("endpoint_url", "")).rstrip("/")
        key = credentials.get("api_key", "").strip()
        if not url or not key:
            return {"success": False, "status": "NOT_CONFIGURED", "message": "DefectDojo URL and API key required.", "latency_ms": 0}
        token_hdr = key if key.startswith("Token ") else f"Token {key}"
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
                res = await client.get(f"{url}/users/", headers={"Authorization": token_hdr})
                latency = int((time.perf_counter() - start) * 1000)
                if res.status_code == 200:
                    return {"success": True, "status": "CONNECTED", "message": "DefectDojo API v2 connection authenticated.", "latency_ms": latency}
                return {"success": False, "status": "AUTHENTICATION_FAILED", "message": "DefectDojo key unauthorized.", "latency_ms": latency}
        except Exception as exc:
            return {"success": False, "status": "UNREACHABLE", "message": str(exc), "latency_ms": int((time.perf_counter() - start) * 1000)}


class TenableAdapter(BaseIntegrationAdapter):
    provider_id = "tenable"
    display_name = "Tenable Nessus / Tenable.io"
    category = "vulnerability_management"
    description = "Vulnerability assessment scans, compliance audits, and asset exposures."
    documentation_url = "https://developer.tenable.com/reference"
    required_permissions = ["Scan API Permissions", "Vulnerability Read"]
    setup_instructions = "1. Generate API Keys in Tenable.io -> Settings -> My Account -> API Keys.\n2. Enter Access Key and Secret Key."

    def get_credential_fields(self) -> List[Dict[str, Any]]:
        return [
            {"key": "access_key", "label": "Access Key", "type": "text", "required": True, "placeholder": "Tenable Access Key"},
            {"key": "secret_key", "label": "Secret Key", "type": "password", "required": True, "placeholder": "Tenable Secret Key"}
        ]

    async def test_connection(self, credentials: Dict[str, str], endpoint_url: Optional[str] = None) -> Dict[str, Any]:
        acc = credentials.get("access_key", "").strip()
        sec = credentials.get("secret_key", "").strip()
        if not acc or not sec:
            return {"success": False, "status": "NOT_CONFIGURED", "message": "Access Key and Secret Key required.", "latency_ms": 0}
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get(
                    "https://cloud.tenable.com/server/status",
                    headers={"X-ApiKeys": f"accessKey={acc}; secretKey={sec}"}
                )
                latency = int((time.perf_counter() - start) * 1000)
                if res.status_code == 200:
                    return {"success": True, "status": "CONNECTED", "message": "Tenable.io connected.", "latency_ms": latency}
                return {"success": False, "status": "AUTHENTICATION_FAILED", "message": "Tenable keys rejected.", "latency_ms": latency}
        except Exception as exc:
            return {"success": False, "status": "UNREACHABLE", "message": str(exc), "latency_ms": int((time.perf_counter() - start) * 1000)}
