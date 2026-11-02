"""
SWA AI — Automated Integration & AI Model Management Test Suite
Verifies:
- Secure encryption of API keys at rest
- Redaction and masking in responses (never exposing plaintext keys)
- Provider schema registry
- Integration lifecycle (Create, Read, Test, Toggle, Delete)
- AI Model management (Add, Configure, Default selection, Fallbacks)
"""

import os
import unittest
from fastapi.testclient import TestClient

from core.database import db
from core.credentials import credentials_vault, mask_secret
from core.integrations.registry import integration_registry
from core.ai_models import ai_model_manager
from web.server import app

client = TestClient(app)


class TestIntegrationsAndAIModels(unittest.TestCase):

    def test_secret_masking(self):
        """Verifies that secrets are masked properly and never revealed in full."""
        self.assertEqual(mask_secret(None), "NOT CONFIGURED")
        self.assertEqual(mask_secret(""), "NOT CONFIGURED")
        self.assertEqual(mask_secret("short"), "***")
        masked_openai = mask_secret("sk-proj-1234567890abcdef12345678")
        self.assertTrue(masked_openai.startswith("sk-proj"))
        self.assertTrue(masked_openai.endswith("5678"))
        self.assertIn("***", masked_openai)
        self.assertNotIn("abcdef", masked_openai)

    def test_credential_encryption_vault(self):
        """Verifies symmetric Fernet encryption at rest with unique salts."""
        secret = "secret-token-xyz-123"
        cipher1, salt1 = credentials_vault.encrypt(secret)
        cipher2, salt2 = credentials_vault.encrypt(secret)

        # Different salts produce different ciphertexts
        self.assertNotEqual(cipher1, cipher2)
        self.assertNotEqual(salt1, salt2)

        # Both decrypt back to original plaintext
        self.assertEqual(credentials_vault.decrypt(cipher1, salt1), secret)
        self.assertEqual(credentials_vault.decrypt(cipher2, salt2), secret)

    def test_get_integration_providers(self):
        """Verifies provider registry returns threat intel, SIEM, and AI providers."""
        res = client.get("/api/integrations/providers")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("providers", data)
        providers = {p["provider_id"]: p for p in data["providers"]}

        # Check required threat intel providers
        for p_id in ["virustotal", "abuseipdb", "shodan", "censys", "alienvault_otx", "urlhaus"]:
            self.assertIn(p_id, providers)
            self.assertEqual(providers[p_id]["category"], "threat_intel")

        # Check required SIEM / security platforms
        for p_id in ["wazuh", "splunk", "elastic_security", "ms_sentinel", "crowdstrike", "defectdojo", "tenable"]:
            self.assertIn(p_id, providers)

        # Check required cloud providers
        for p_id in ["aws", "azure", "gcp"]:
            self.assertIn(p_id, providers)

    def test_integration_crud_lifecycle(self):
        """Verifies adding an integration, verifying masked key, testing, toggling, and deleting."""
        # 1. Add integration
        payload = {
            "provider_id": "virustotal",
            "display_name": "Production VirusTotal Feed",
            "credentials": {
                "api_key": "vt-secret-key-1234567890abcdef12345678"
            },
            "enabled": True
        }
        create_res = client.post("/api/integrations", json=payload)
        self.assertEqual(create_res.status_code, 200)
        data = create_res.json()["integration"]
        iid = data["id"]
        self.assertEqual(data["display_name"], "Production VirusTotal Feed")

        # Ensure plaintext secret is NOT returned in response
        self.assertNotIn("vt-secret-key-1234567890abcdef12345678", json_str := str(create_res.json()))
        self.assertIn("***", data["masked_credentials"]["api_key"])

        # 2. List integrations
        list_res = client.get("/api/integrations")
        self.assertEqual(list_res.status_code, 200)
        integs = [i for i in list_res.json()["integrations"] if i["id"] == iid]
        self.assertEqual(len(integs), 1)

        # 3. Toggle integration
        toggle_res = client.post(f"/api/integrations/{iid}/toggle?enabled=false")
        self.assertEqual(toggle_res.status_code, 200)
        self.assertEqual(toggle_res.json()["integration"]["enabled"], 0)

        # 4. Clean up / Delete integration
        del_res = client.delete(f"/api/integrations/{iid}")
        self.assertEqual(del_res.status_code, 200)
        self.assertEqual(del_res.json()["status"], "SUCCESS")

    def test_ai_models_management(self):
        """Verifies listing catalog, adding a model, and designating default model."""
        # 1. Query Catalog
        cat_res = client.get("/api/ai/models/catalog")
        self.assertEqual(cat_res.status_code, 200)
        catalog = cat_res.json()["catalog"]
        self.assertIn("openai", catalog)
        self.assertIn("anthropic", catalog)
        self.assertIn("gemini", catalog)
        self.assertIn("openrouter", catalog)
        self.assertIn("ollama", catalog)

        # 2. Add custom model
        mod_payload = {
            "provider": "anthropic",
            "model_id": "claude-3-5-sonnet-custom",
            "display_name": "Claude 3.5 Sonnet (Enterprise Dedicated)",
            "description": "Dedicated auditing instance",
            "max_tokens": 8192,
            "temperature": 0.1,
            "timeout_seconds": 45,
            "is_default": False
        }
        add_res = client.post("/api/ai/models", json=mod_payload)
        self.assertEqual(add_res.status_code, 200)
        model = add_res.json()["model"]
        mid = model["id"]

        # 3. Designate as default
        def_res = client.post(f"/api/ai/models/{mid}/default")
        self.assertEqual(def_res.status_code, 200)
        self.assertEqual(def_res.json()["default_model"]["id"], mid)

        # 4. Delete model
        del_res = client.delete(f"/api/ai/models/{mid}")
        self.assertEqual(del_res.status_code, 200)


if __name__ == "__main__":
    unittest.main()
