"""
SWA AI — AI Provider Adapters
Implements adapters for OpenAI, Anthropic, Google Gemini, OpenRouter, and Local/Ollama.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
import httpx
from core.integrations.base import BaseIntegrationAdapter


class OpenAIAdapter(BaseIntegrationAdapter):
    provider_id = "openai"
    display_name = "OpenAI"
    category = "ai_provider"
    description = "GPT-4o, GPT-4 Turbo, GPT-3.5, and reasoning models for vulnerability triage and remediation."
    documentation_url = "https://platform.openai.com/docs/api-reference"
    required_permissions = ["Model Query / Chat Completions"]
    setup_instructions = "1. Sign in to platform.openai.com -> API keys.\n2. Create a new secret key and paste below."

    def get_credential_fields(self) -> List[Dict[str, Any]]:
        return [
            {"key": "api_key", "label": "API Key", "type": "password", "required": True, "placeholder": "sk-..."},
            {"key": "base_url", "label": "Base URL (Optional)", "type": "text", "required": False, "placeholder": "https://api.openai.com/v1"}
        ]

    async def test_connection(self, credentials: Dict[str, str], endpoint_url: Optional[str] = None) -> Dict[str, Any]:
        api_key = credentials.get("api_key", "").strip()
        base_url = (credentials.get("base_url") or "https://api.openai.com/v1").rstrip("/")
        if not api_key:
            return {"success": False, "status": "NOT_CONFIGURED", "message": "OpenAI API key missing.", "latency_ms": 0}
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get(f"{base_url}/models", headers={"Authorization": f"Bearer {api_key}"})
                latency = int((time.perf_counter() - start) * 1000)
                if res.status_code == 200:
                    models = [m.get("id") for m in res.json().get("data", [])][:5]
                    return {"success": True, "status": "CONNECTED", "message": f"Connected. Available models: {', '.join(models)}", "latency_ms": latency}
                elif res.status_code in (401, 403):
                    return {"success": False, "status": "AUTHENTICATION_FAILED", "message": "Invalid OpenAI API key.", "latency_ms": latency}
                return {"success": False, "status": "ERROR", "message": f"OpenAI HTTP {res.status_code}", "latency_ms": latency}
        except Exception as exc:
            return {"success": False, "status": "UNREACHABLE", "message": str(exc), "latency_ms": int((time.perf_counter() - start) * 1000)}


class AnthropicAdapter(BaseIntegrationAdapter):
    provider_id = "anthropic"
    display_name = "Anthropic Claude"
    category = "ai_provider"
    description = "Claude 3.5 Sonnet, Claude 3 Opus, and Claude 3 Haiku for deep code analysis and security auditing."
    documentation_url = "https://docs.anthropic.com/en/api/getting-started"
    required_permissions = ["Messages API Access"]
    setup_instructions = "1. Sign in to console.anthropic.com -> Settings -> API Keys.\n2. Create key and paste below."

    def get_credential_fields(self) -> List[Dict[str, Any]]:
        return [
            {"key": "api_key", "label": "API Key", "type": "password", "required": True, "placeholder": "sk-ant-..."}
        ]

    async def test_connection(self, credentials: Dict[str, str], endpoint_url: Optional[str] = None) -> Dict[str, Any]:
        api_key = credentials.get("api_key", "").strip()
        if not api_key:
            return {"success": False, "status": "NOT_CONFIGURED", "message": "Anthropic API key missing.", "latency_ms": 0}
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                    json={"model": "claude-3-haiku-20240307", "max_tokens": 5, "messages": [{"role": "user", "content": "ping"}]}
                )
                latency = int((time.perf_counter() - start) * 1000)
                if res.status_code in (200, 400):  # 400 with valid key means auth succeeded
                    return {"success": True, "status": "CONNECTED", "message": "Anthropic Claude API authenticated.", "latency_ms": latency}
                elif res.status_code in (401, 403):
                    return {"success": False, "status": "AUTHENTICATION_FAILED", "message": "Invalid Anthropic API key.", "latency_ms": latency}
                return {"success": False, "status": "ERROR", "message": f"Anthropic HTTP {res.status_code}", "latency_ms": latency}
        except Exception as exc:
            return {"success": False, "status": "UNREACHABLE", "message": str(exc), "latency_ms": int((time.perf_counter() - start) * 1000)}


class GoogleGeminiAdapter(BaseIntegrationAdapter):
    provider_id = "gemini"
    display_name = "Google Gemini"
    category = "ai_provider"
    description = "Gemini 1.5 Pro and Gemini 1.5 Flash for high-speed multi-modal threat analysis."
    documentation_url = "https://ai.google.dev/gemini-api/docs"
    required_permissions = ["Generative Language API Access"]
    setup_instructions = "1. In Google AI Studio (aistudio.google.com), click Get API Key.\n2. Paste the key below."

    def get_credential_fields(self) -> List[Dict[str, Any]]:
        return [
            {"key": "api_key", "label": "API Key", "type": "password", "required": True, "placeholder": "AIzaSy..."}
        ]

    async def test_connection(self, credentials: Dict[str, str], endpoint_url: Optional[str] = None) -> Dict[str, Any]:
        api_key = credentials.get("api_key", "").strip()
        if not api_key:
            return {"success": False, "status": "NOT_CONFIGURED", "message": "Google Gemini API key missing.", "latency_ms": 0}
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get(f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}")
                latency = int((time.perf_counter() - start) * 1000)
                if res.status_code == 200:
                    models = [m.get("name", "").split("/")[-1] for m in res.json().get("models", [])][:4]
                    return {"success": True, "status": "CONNECTED", "message": f"Gemini API authenticated. Models: {', '.join(models)}", "latency_ms": latency}
                elif res.status_code in (400, 401, 403):
                    return {"success": False, "status": "AUTHENTICATION_FAILED", "message": "Invalid Google Gemini API key.", "latency_ms": latency}
                return {"success": False, "status": "ERROR", "message": f"Gemini HTTP {res.status_code}", "latency_ms": latency}
        except Exception as exc:
            return {"success": False, "status": "UNREACHABLE", "message": str(exc), "latency_ms": int((time.perf_counter() - start) * 1000)}


class OpenRouterAdapter(BaseIntegrationAdapter):
    provider_id = "openrouter"
    display_name = "OpenRouter"
    category = "ai_provider"
    description = "Unified gateway to over 100+ state-of-the-art open-source and proprietary LLM models."
    documentation_url = "https://openrouter.ai/docs"
    required_permissions = ["OpenRouter Query Access"]
    setup_instructions = "1. Sign in to openrouter.ai -> Keys.\n2. Create key and paste below."

    def get_credential_fields(self) -> List[Dict[str, Any]]:
        return [
            {"key": "api_key", "label": "API Key", "type": "password", "required": True, "placeholder": "sk-or-v1-..."}
        ]

    async def test_connection(self, credentials: Dict[str, str], endpoint_url: Optional[str] = None) -> Dict[str, Any]:
        api_key = credentials.get("api_key", "").strip()
        if not api_key:
            return {"success": False, "status": "NOT_CONFIGURED", "message": "OpenRouter API key missing.", "latency_ms": 0}
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get("https://openrouter.ai/api/v1/auth/key", headers={"Authorization": f"Bearer {api_key}"})
                latency = int((time.perf_counter() - start) * 1000)
                if res.status_code == 200:
                    data = res.json().get("data", {})
                    return {"success": True, "status": "CONNECTED", "message": f"OpenRouter connected. Usage: {data.get('usage', 0)} USD.", "latency_ms": latency}
                return {"success": False, "status": "AUTHENTICATION_FAILED", "message": "OpenRouter key rejected.", "latency_ms": latency}
        except Exception as exc:
            return {"success": False, "status": "UNREACHABLE", "message": str(exc), "latency_ms": int((time.perf_counter() - start) * 1000)}


class OllamaLocalAdapter(BaseIntegrationAdapter):
    provider_id = "ollama"
    display_name = "Ollama (Local LLM)"
    category = "ai_provider"
    description = "Run private, offline open-source models locally (Llama 3, Mistral, Qwen, DeepSeek)."
    documentation_url = "https://ollama.ai/"
    required_permissions = ["Localhost HTTP Connection"]
    setup_instructions = "1. Start Ollama locally ('ollama serve').\n2. Provide base URL (default: http://127.0.0.1:11434)."

    def get_credential_fields(self) -> List[Dict[str, Any]]:
        return [
            {"key": "base_url", "label": "Ollama Base URL", "type": "url", "required": True, "placeholder": "http://127.0.0.1:11434"}
        ]

    async def test_connection(self, credentials: Dict[str, str], endpoint_url: Optional[str] = None) -> Dict[str, Any]:
        base_url = (endpoint_url or credentials.get("base_url") or "http://127.0.0.1:11434").rstrip("/")
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.get(f"{base_url}/api/tags")
                latency = int((time.perf_counter() - start) * 1000)
                if res.status_code == 200:
                    models = [m.get("name") for m in res.json().get("models", [])][:5]
                    return {"success": True, "status": "CONNECTED", "message": f"Ollama operational. Models: {', '.join(models) if models else 'None installed'}", "latency_ms": latency}
                return {"success": False, "status": "ERROR", "message": f"Ollama HTTP {res.status_code}", "latency_ms": latency}
        except Exception as exc:
            return {"success": False, "status": "UNREACHABLE", "message": f"Ollama is not running on {base_url}: {exc}", "latency_ms": int((time.perf_counter() - start) * 1000)}
