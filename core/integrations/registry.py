"""
SWA AI — Central Integrations Registry & Orchestrator
Provides unified registration, encrypted persistence, secret redaction, and connection testing
for all third-party security, cloud, threat intel, and AI providers.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from core.credentials import credentials_vault, mask_secret
from core.database import db
from core.integrations.ai_providers import (
    AnthropicAdapter,
    GoogleGeminiAdapter,
    OllamaLocalAdapter,
    OpenAIAdapter,
    OpenRouterAdapter,
)
from core.integrations.base import BaseIntegrationAdapter
from core.integrations.cloud_providers import AWSAdapter, AzureCloudAdapter, GCPAdapter
from core.integrations.security_platforms import (
    CrowdStrikeAdapter,
    DefectDojoAdapter,
    ElasticSecurityAdapter,
    MicrosoftSentinelAdapter,
    SplunkAdapter,
    TenableAdapter,
    WazuhAdapter,
)
from core.integrations.threat_intel import (
    AbuseIPDBAdapter,
    AlienVaultOTXAdapter,
    CensysAdapter,
    CisaKevAdapter,
    FirstEpssAdapter,
    ShodanAdapter,
    URLhausAdapter,
    VirusTotalAdapter,
)

logger = logging.getLogger("swa.integrations")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class IntegrationRegistry:
    """Singleton registry holding all active integration adapters and handling database persistence."""

    def __init__(self):
        self._adapters: Dict[str, BaseIntegrationAdapter] = {}
        self._register_defaults()
        self._ensure_tables()

    def _register_defaults(self):
        adapters = [
            # AI
            OpenAIAdapter(),
            AnthropicAdapter(),
            GoogleGeminiAdapter(),
            OpenRouterAdapter(),
            OllamaLocalAdapter(),
            # Threat Intel
            VirusTotalAdapter(),
            AbuseIPDBAdapter(),
            ShodanAdapter(),
            CensysAdapter(),
            AlienVaultOTXAdapter(),
            URLhausAdapter(),
            CisaKevAdapter(),
            FirstEpssAdapter(),
            # SIEM / EDR / Vuln Mgmt
            WazuhAdapter(),
            SplunkAdapter(),
            ElasticSecurityAdapter(),
            MicrosoftSentinelAdapter(),
            CrowdStrikeAdapter(),
            DefectDojoAdapter(),
            TenableAdapter(),
            # Cloud
            AWSAdapter(),
            AzureCloudAdapter(),
            GCPAdapter(),
        ]
        for a in adapters:
            self._adapters[a.provider_id] = a

    def _ensure_tables(self):
        """Creates integration tables additively in the SQLite database."""
        with db.get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS integrations (
                    id TEXT PRIMARY KEY,
                    provider_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    endpoint_url TEXT,
                    enabled INTEGER DEFAULT 1,
                    status TEXT DEFAULT 'NOT_CONFIGURED',
                    last_tested_at TEXT,
                    last_error TEXT,
                    config_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS encrypted_credentials (
                    integration_id TEXT NOT NULL,
                    field_key TEXT NOT NULL,
                    ciphertext_b64 TEXT NOT NULL,
                    salt_b64 TEXT NOT NULL,
                    masked_value TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (integration_id, field_key)
                )
                """
            )
            conn.commit()

    def get_adapter(self, provider_id: str) -> Optional[BaseIntegrationAdapter]:
        return self._adapters.get(provider_id.lower())

    def list_supported_providers(self) -> List[Dict[str, Any]]:
        """Returns metadata for all available integrations with setup guides and required fields."""
        out = []
        for p_id, adapter in sorted(self._adapters.items(), key=lambda x: (x[1].category, x[1].display_name)):
            out.append({
                "provider_id": adapter.provider_id,
                "display_name": adapter.display_name,
                "category": adapter.category,
                "description": adapter.description,
                "documentation_url": adapter.documentation_url,
                "required_permissions": adapter.required_permissions,
                "setup_instructions": adapter.setup_instructions,
                "credential_fields": adapter.get_credential_fields(),
            })
        return out

    def list_configured_integrations(self) -> List[Dict[str, Any]]:
        """Returns list of all configured integrations with masked secrets."""
        with db.get_connection() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM integrations ORDER BY category, display_name").fetchall()
            results = []
            for r in rows:
                row_dict = dict(r)
                # Fetch masked credentials
                cred_rows = conn.execute(
                    "SELECT field_key, masked_value FROM encrypted_credentials WHERE integration_id = ?",
                    (row_dict["id"],)
                ).fetchall()
                creds_masked = {c["field_key"]: c["masked_value"] for c in cred_rows}
                row_dict["masked_credentials"] = creds_masked
                try:
                    row_dict["config"] = json.loads(row_dict.get("config_json") or "{}")
                except Exception:
                    row_dict["config"] = {}
                results.append(row_dict)
            return results

    def get_integration(self, integration_id: str) -> Optional[Dict[str, Any]]:
        with db.get_connection() as conn:
            conn.row_factory = sqlite3.Row
            r = conn.execute("SELECT * FROM integrations WHERE id = ?", (integration_id,)).fetchone()
            if not r:
                return None
            row_dict = dict(r)
            cred_rows = conn.execute(
                "SELECT field_key, masked_value FROM encrypted_credentials WHERE integration_id = ?",
                (integration_id,)
            ).fetchall()
            row_dict["masked_credentials"] = {c["field_key"]: c["masked_value"] for c in cred_rows}
            try:
                row_dict["config"] = json.loads(row_dict.get("config_json") or "{}")
            except Exception:
                row_dict["config"] = {}
            return row_dict

    def save_integration(
        self,
        provider_id: str,
        display_name: str,
        credentials: Dict[str, str],
        endpoint_url: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
        integration_id: Optional[str] = None,
        enabled: bool = True
    ) -> Dict[str, Any]:
        """Saves or updates an integration with encrypted credentials at rest."""
        adapter = self.get_adapter(provider_id)
        if not adapter:
            raise ValueError(f"Unknown integration provider '{provider_id}'")

        iid = integration_id or f"int_{uuid.uuid4().hex[:12]}"
        now = _utc_now()
        config_json = json.dumps(config or {})

        with db.get_connection() as conn:
            # Check if exists
            existing = conn.execute("SELECT id FROM integrations WHERE id = ?", (iid,)).fetchone()
            if existing:
                conn.execute(
                    """
                    UPDATE integrations
                    SET display_name = ?, endpoint_url = ?, enabled = ?, config_json = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (display_name, endpoint_url, 1 if enabled else 0, config_json, now, iid)
                )
            else:
                conn.execute(
                    """
                    INSERT INTO integrations (
                        id, provider_id, category, display_name, endpoint_url,
                        enabled, status, config_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'CONFIGURED', ?, ?, ?)
                    """,
                    (iid, adapter.provider_id, adapter.category, display_name, endpoint_url, 1 if enabled else 0, config_json, now, now)
                )

            # Store credentials encrypted
            for k, val in credentials.items():
                if not val:
                    continue  # preserve existing if empty during edit
                cipher_b64, salt_b64 = credentials_vault.encrypt(val)
                masked = mask_secret(val)
                conn.execute(
                    """
                    INSERT INTO encrypted_credentials (integration_id, field_key, ciphertext_b64, salt_b64, masked_value, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(integration_id, field_key) DO UPDATE SET
                        ciphertext_b64 = excluded.ciphertext_b64,
                        salt_b64 = excluded.salt_b64,
                        masked_value = excluded.masked_value,
                        updated_at = excluded.updated_at
                    """,
                    (iid, k, cipher_b64, salt_b64, masked, now)
                )
            conn.commit()

        return self.get_integration(iid)

    def delete_integration(self, integration_id: str) -> bool:
        with db.get_connection() as conn:
            conn.execute("DELETE FROM encrypted_credentials WHERE integration_id = ?", (integration_id,))
            res = conn.execute("DELETE FROM integrations WHERE id = ?", (integration_id,))
            conn.commit()
            return res.rowcount > 0

    def toggle_integration(self, integration_id: str, enabled: bool) -> Optional[Dict[str, Any]]:
        now = _utc_now()
        with db.get_connection() as conn:
            conn.execute(
                "UPDATE integrations SET enabled = ?, updated_at = ? WHERE id = ?",
                (1 if enabled else 0, now, integration_id)
            )
            conn.commit()
        return self.get_integration(integration_id)

    def _get_decrypted_credentials(self, integration_id: str) -> Dict[str, str]:
        """Internal only: Decrypts secrets in memory for authorized network dispatch. Never log or leak."""
        with db.get_connection() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT field_key, ciphertext_b64, salt_b64 FROM encrypted_credentials WHERE integration_id = ?",
                (integration_id,)
            ).fetchall()
            out = {}
            for r in rows:
                plaintext = credentials_vault.decrypt(r["ciphertext_b64"], r["salt_b64"])
                if plaintext:
                    out[r["field_key"]] = plaintext
            return out

    async def test_integration(self, integration_id: str) -> Dict[str, Any]:
        """Performs a live connection test using decrypted credentials and updates status in SQLite."""
        integ = self.get_integration(integration_id)
        if not integ:
            return {"success": False, "status": "NOT_FOUND", "message": f"Integration {integration_id} not found."}

        adapter = self.get_adapter(integ["provider_id"])
        if not adapter:
            return {"success": False, "status": "ERROR", "message": f"No adapter for provider {integ['provider_id']}"}

        creds = self._get_decrypted_credentials(integration_id)
        endpoint = integ.get("endpoint_url")

        res = await adapter.test_connection(creds, endpoint_url=endpoint)
        now = _utc_now()
        new_status = res.get("status", "CONNECTED" if res.get("success") else "FAILED")
        last_error = "" if res.get("success") else res.get("message", "Test failed")

        with db.get_connection() as conn:
            conn.execute(
                """
                UPDATE integrations
                SET status = ?, last_tested_at = ?, last_error = ?, updated_at = ?
                WHERE id = ?
                """,
                (new_status, now, last_error, now, integration_id)
            )
            conn.commit()

        res["integration_id"] = integration_id
        res["checked_at"] = now
        return res


integration_registry = IntegrationRegistry()
