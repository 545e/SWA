"""
SWA AI — Secure API Key Management & Integration Verification Suite
Tests cryptographic storage, masked secret handling, ad-hoc connection probing,
rotation workflows, and integration with the SWALLMClient.
"""

import os
import pytest
from fastapi.testclient import TestClient
from web.server import app
from core.credentials import credentials_vault, mask_secret
from core.integrations.registry import integration_registry
from core.llm_client import SWALLMClient

client = TestClient(app)


def test_api_keys_summary_endpoint():
    """Verify that summary reports 23 supported integrations and accurate counts."""
    res = client.get("/api/integrations/summary")
    assert res.status_code == 200
    data = res.json()
    assert data["total_supported"] == 23
    assert "total_configured" in data
    assert "connected" in data
    assert "attention_required" in data
    assert "unconfigured" in data


def test_zero_secret_leakage_in_api():
    """Ensure that plain-text secret keys never appear in any API response."""
    test_secret = "sk-super-sensitive-secret-token-12345"
    save_payload = {
        "provider_id": "openai",
        "display_name": "Test OpenAI Key Leakage",
        "credentials": {"api_key": test_secret},
        "config": {"scope": "global"}
    }
    create_res = client.post("/api/integrations", json=save_payload)
    assert create_res.status_code == 200
    created = create_res.json()["integration"]
    integ_id = created["id"]

    try:
        # 1. Create response check
        assert test_secret not in str(create_res.json())
        assert created["masked_credentials"]["api_key"] == mask_secret(test_secret)

        # 2. Get single detail check
        detail_res = client.get(f"/api/integrations/{integ_id}")
        assert detail_res.status_code == 200
        assert test_secret not in str(detail_res.json())

        # 3. List all check
        list_res = client.get("/api/integrations")
        assert list_res.status_code == 200
        assert test_secret not in str(list_res.json())

    finally:
        client.delete(f"/api/integrations/{integ_id}")


def test_adhoc_connection_testing():
    """Test connection probe against real endpoint without saving credential."""
    test_payload = {
        "provider_id": "gemini",
        "credentials": {"api_key": "AIzaSyFakeKeyShouldFailGracefully1234"}
    }
    res = client.post("/api/integrations/test", json=test_payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ("AUTHENTICATION_FAILED", "ERROR", "FAILED")
    assert "latency_ms" in data
    assert data["latency_ms"] >= 0


def test_credential_rotation_endpoint():
    """Test secret rotation updates ciphertext while preserving configuration."""
    initial_payload = {
        "provider_id": "virustotal",
        "display_name": "Rotation Test Integration",
        "credentials": {"api_key": "initial-secret-1111"},
        "config": {"scope": "workspace", "workspace_id": "ws_test"}
    }
    create_res = client.post("/api/integrations", json=initial_payload)
    assert create_res.status_code == 200
    integ_id = create_res.json()["integration"]["id"]

    try:
        rotate_payload = {
            "credentials": {"api_key": "rotated-secret-9999"}
        }
        rot_res = client.post(f"/api/integrations/{integ_id}/rotate", json=rotate_payload)
        assert rot_res.status_code == 200
        data = rot_res.json()
        assert data["status"] == "SUCCESS"
        assert data["integration"]["masked_credentials"]["api_key"] == mask_secret("rotated-secret-9999")
        # Config should be preserved
        assert data["integration"]["config"]["scope"] == "workspace"

    finally:
        client.delete(f"/api/integrations/{integ_id}")


def test_llm_client_vault_integration():
    """Test that SWALLMClient detects and decrypts active vault credentials."""
    test_key = "sk-test-llm-vault-key-abc12345"
    save_payload = {
        "provider_id": "gemini",
        "display_name": "Gemini Vault Test",
        "credentials": {"api_key": test_key},
        "config": {"is_default": True, "default_model": "gemini-2.0-flash"}
    }
    create_res = client.post("/api/integrations", json=save_payload)
    assert create_res.status_code == 200
    integ_id = create_res.json()["integration"]["id"]

    try:
        # Instantiate SWALLMClient without env vars
        llm = SWALLMClient(provider="auto")
        status = llm.get_status()
        assert status["has_api_key"] is True
        assert status["provider"] == "gemini"
        assert status["credential_source"] == "database_vault"
        assert llm.api_key == test_key
    finally:
        client.delete(f"/api/integrations/{integ_id}")
