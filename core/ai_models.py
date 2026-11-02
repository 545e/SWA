"""
SWA AI — AI Model Management System
Provides centralized configuration, dynamic model discovery, availability probes,
token limit tuning, temperature adjustment, fallback chains, and default selection
for AI models across OpenAI, Anthropic, Google Gemini, OpenRouter, and Local/Ollama.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

import httpx

from core.database import db
from core.integrations.registry import integration_registry

logger = logging.getLogger("swa.ai_models")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# Curated catalog of production-tested LLM models per provider
KNOWN_PROVIDER_MODELS: Dict[str, List[Dict[str, Any]]] = {
    "openai": [
        {"model_id": "gpt-4o", "name": "GPT-4o (Omni)", "context_window": 128000, "description": "High-intelligence flagship model for complex exploit validation and report drafting."},
        {"model_id": "gpt-4o-mini", "name": "GPT-4o Mini", "context_window": 128000, "description": "Fast, cost-efficient model for real-time asset classification and IOC lookup."},
        {"model_id": "gpt-4-turbo", "name": "GPT-4 Turbo", "context_window": 128000, "description": "High-accuracy code inspection and OWASP triage."},
        {"model_id": "o1-preview", "name": "o1 Preview", "context_window": 128000, "description": "Advanced multi-step reasoning for deep threat architecture analysis."},
    ],
    "anthropic": [
        {"model_id": "claude-3-5-sonnet-20241022", "name": "Claude 3.5 Sonnet", "context_window": 200000, "description": "State-of-the-art reasoning for vulnerability finding verification and reverse engineering analysis."},
        {"model_id": "claude-3-opus-20240229", "name": "Claude 3 Opus", "context_window": 200000, "description": "Maximum capability for extensive forensic artifact correlation."},
        {"model_id": "claude-3-haiku-20240307", "name": "Claude 3 Haiku", "context_window": 200000, "description": "Ultra-fast response for continuous log analysis and alert triaging."},
    ],
    "gemini": [
        {"model_id": "gemini-1.5-pro", "name": "Gemini 1.5 Pro", "context_window": 1000000, "description": "1M token context window for ingesting full codebase repositories and extensive scan logs."},
        {"model_id": "gemini-1.5-flash", "name": "Gemini 1.5 Flash", "context_window": 1000000, "description": "Sub-second multi-modal analysis for rapid recon and header inspection."},
        {"model_id": "gemini-2.0-flash-exp", "name": "Gemini 2.0 Flash (Experimental)", "context_window": 1000000, "description": "Next-generation autonomous agent execution engine."},
    ],
    "openrouter": [
        {"model_id": "anthropic/claude-3.5-sonnet", "name": "Claude 3.5 Sonnet (OpenRouter)", "context_window": 200000, "description": "Routed through OpenRouter gateway."},
        {"model_id": "openai/gpt-4o", "name": "GPT-4o (OpenRouter)", "context_window": 128000, "description": "Routed through OpenRouter gateway."},
        {"model_id": "meta-llama/llama-3.3-70b-instruct", "name": "Llama 3.3 70B Instruct", "context_window": 128000, "description": "Open-weight frontier model for private enterprise analysis."},
        {"model_id": "deepseek/deepseek-chat", "name": "DeepSeek V3", "context_window": 64000, "description": "High-throughput coding and vulnerability analysis."},
    ],
    "ollama": [
        {"model_id": "llama3.2:latest", "name": "Llama 3.2 (Local)", "context_window": 128000, "description": "Local offline execution with 0 external network requests."},
        {"model_id": "mistral:latest", "name": "Mistral 7B (Local)", "context_window": 32000, "description": "Private local security scanning."},
        {"model_id": "qwen2.5-coder:latest", "name": "Qwen 2.5 Coder (Local)", "context_window": 32000, "description": "Specialized local source code analysis and exploit payload inspection."},
    ]
}


class AIModelManager:
    """Manages AI model definitions, parameters, and defaults in SQLite."""

    def __init__(self):
        self._ensure_tables()
        self._seed_defaults_if_empty()

    def _ensure_tables(self):
        with db.get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ai_models (
                    id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    description TEXT,
                    max_tokens INTEGER DEFAULT 4096,
                    temperature REAL DEFAULT 0.2,
                    timeout_seconds INTEGER DEFAULT 30,
                    is_default INTEGER DEFAULT 0,
                    fallback_model_id TEXT,
                    enabled INTEGER DEFAULT 1,
                    status TEXT DEFAULT 'CONFIGURED',
                    last_tested_at TEXT,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def _seed_defaults_if_empty(self):
        with db.get_connection() as conn:
            cnt = conn.execute("SELECT count(*) FROM ai_models").fetchone()[0]
            if cnt > 0:
                return

            now = _utc_now()
            default_seeds = [
                ("gpt-4o", "openai", "gpt-4o", "GPT-4o (Omni)", "Flagship multi-modal model for vulnerability verification and remediation.", 4096, 0.2, 30, 1, "claude-3-5-sonnet"),
                ("claude-3-5-sonnet", "anthropic", "claude-3-5-sonnet-20241022", "Claude 3.5 Sonnet", "High-accuracy code inspection and advanced security reasoning.", 4096, 0.2, 30, 0, "gemini-1.5-flash"),
                ("gemini-1.5-flash", "gemini", "gemini-1.5-flash", "Gemini 1.5 Flash", "High-speed multi-modal analysis and rapid reconnaissance.", 8192, 0.1, 20, 0, "openrouter-default"),
                ("openrouter-default", "openrouter", "anthropic/claude-3.5-sonnet", "Claude 3.5 Sonnet (OpenRouter)", "Universal gateway fallback model.", 4096, 0.2, 30, 0, "ollama-local"),
                ("ollama-local", "ollama", "llama3.2:latest", "Llama 3.2 (Local)", "Offline local privacy-preserving scanner.", 2048, 0.2, 45, 0, None),
            ]
            for row in default_seeds:
                conn.execute(
                    """
                    INSERT INTO ai_models (
                        id, provider, model_id, display_name, description,
                        max_tokens, temperature, timeout_seconds, is_default,
                        fallback_model_id, enabled, status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'CONFIGURED', ?, ?)
                    """,
                    (*row, now, now)
                )
            conn.commit()

    def list_models(self) -> List[Dict[str, Any]]:
        with db.get_connection() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM ai_models ORDER BY is_default DESC, provider, display_name").fetchall()
            return [dict(r) for r in rows]

    def get_model(self, model_pk: str) -> Optional[Dict[str, Any]]:
        with db.get_connection() as conn:
            conn.row_factory = sqlite3.Row
            r = conn.execute("SELECT * FROM ai_models WHERE id = ? OR model_id = ?", (model_pk, model_pk)).fetchone()
            return dict(r) if r else None

    def get_default_model(self) -> Optional[Dict[str, Any]]:
        with db.get_connection() as conn:
            conn.row_factory = sqlite3.Row
            r = conn.execute("SELECT * FROM ai_models WHERE is_default = 1 AND enabled = 1 LIMIT 1").fetchone()
            if not r:
                r = conn.execute("SELECT * FROM ai_models WHERE enabled = 1 LIMIT 1").fetchone()
            return dict(r) if r else None

    def save_model(
        self,
        provider: str,
        model_id: str,
        display_name: str,
        description: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.2,
        timeout_seconds: int = 30,
        is_default: bool = False,
        fallback_model_id: Optional[str] = None,
        enabled: bool = True,
        model_pk: Optional[str] = None
    ) -> Dict[str, Any]:
        now = _utc_now()
        pk = model_pk or f"mod_{uuid.uuid4().hex[:10]}"
        with db.get_connection() as conn:
            if is_default:
                conn.execute("UPDATE ai_models SET is_default = 0")

            existing = conn.execute("SELECT id FROM ai_models WHERE id = ?", (pk,)).fetchone()
            if existing:
                conn.execute(
                    """
                    UPDATE ai_models
                    SET provider = ?, model_id = ?, display_name = ?, description = ?,
                        max_tokens = ?, temperature = ?, timeout_seconds = ?, is_default = ?,
                        fallback_model_id = ?, enabled = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (provider, model_id, display_name, description, max_tokens, temperature,
                     timeout_seconds, 1 if is_default else 0, fallback_model_id, 1 if enabled else 0, now, pk)
                )
            else:
                conn.execute(
                    """
                    INSERT INTO ai_models (
                        id, provider, model_id, display_name, description,
                        max_tokens, temperature, timeout_seconds, is_default,
                        fallback_model_id, enabled, status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'CONFIGURED', ?, ?)
                    """,
                    (pk, provider, model_id, display_name, description, max_tokens, temperature,
                     timeout_seconds, 1 if is_default else 0, fallback_model_id, 1 if enabled else 0, now, now)
                )
            conn.commit()
        return self.get_model(pk)

    def delete_model(self, model_pk: str) -> bool:
        with db.get_connection() as conn:
            res = conn.execute("DELETE FROM ai_models WHERE id = ?", (model_pk,))
            conn.commit()
            return res.rowcount > 0

    def set_default(self, model_pk: str) -> Optional[Dict[str, Any]]:
        with db.get_connection() as conn:
            conn.execute("UPDATE ai_models SET is_default = 0")
            conn.execute("UPDATE ai_models SET is_default = 1, updated_at = ? WHERE id = ?", (_utc_now(), model_pk))
            conn.commit()
        return self.get_model(model_pk)

    async def test_model_availability(self, model_pk: str) -> Dict[str, Any]:
        """Runs a live reachability test for the specified model."""
        model = self.get_model(model_pk)
        if not model:
            return {"success": False, "status": "NOT_FOUND", "message": f"Model {model_pk} not found."}

        provider = model["provider"]
        adapter = integration_registry.get_adapter(provider)
        now = _utc_now()

        if not adapter:
            return {"success": False, "status": "ERROR", "message": f"No adapter for provider '{provider}'"}

        # Look up configured integration credentials for this provider
        integs = [i for i in integration_registry.list_configured_integrations() if i["provider_id"] == provider]
        creds = {}
        endpoint = None
        if integs:
            creds = integration_registry._get_decrypted_credentials(integs[0]["id"])
            endpoint = integs[0].get("endpoint_url")
        else:
            # Check environment variables
            def _is_valid(k: str) -> bool:
                if not k or len(k.strip()) < 8:
                    return False
                kl = k.strip().lower()
                return not (kl in ("your_api_key_here", "change_me", "none", "null") or "your_api_key" in kl or "change_me" in kl)

            env_map = {
                "openai": ["OPENAI_API_KEY", "SWA_AI_API_KEY", "LLM_API_KEY"],
                "anthropic": ["ANTHROPIC_API_KEY", "SWA_AI_API_KEY", "LLM_API_KEY"],
                "gemini": ["GEMINI_API_KEY", "SWA_AI_API_KEY", "LLM_API_KEY"],
                "openrouter": ["OPENROUTER_API_KEY", "SWA_AI_API_KEY", "LLM_API_KEY"],
            }
            if provider in env_map:
                for ev in env_map[provider]:
                    k = os.environ.get(ev, "").strip()
                    if _is_valid(k):
                        creds = {"api_key": k}
                        break

        if not creds and provider != "ollama":
            res = {
                "success": False,
                "status": "NOT_CONFIGURED",
                "message": f"No API credentials configured for {provider}. Configure in Settings -> API Keys & Integrations.",
                "latency_ms": 0,
            }
        else:
            res = await adapter.test_connection(creds, endpoint_url=endpoint)

        new_status = "CONNECTED" if res.get("success") else res.get("status", "FAILED")
        last_error = "" if res.get("success") else res.get("message", "Test failed")

        with db.get_connection() as conn:
            conn.execute(
                """
                UPDATE ai_models
                SET status = ?, last_tested_at = ?, last_error = ?, updated_at = ?
                WHERE id = ?
                """,
                (new_status, now, last_error, now, model["id"])
            )
            conn.commit()

        res["model_id"] = model["model_id"]
        res["display_name"] = model["display_name"]
        return res

    def get_known_catalog(self) -> Dict[str, List[Dict[str, Any]]]:
        return KNOWN_PROVIDER_MODELS


ai_model_manager = AIModelManager()
