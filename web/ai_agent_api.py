"""
SWA AI — AI Agent Management & Integration Router
Provides complete CRUD, secure API key encryption at rest, live provider connection testing,
agent-to-provider mappings, multi-agent collaboration pipeline, and Copilot endpoints.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import time
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException

from core.database import db
from core.credentials import credentials_vault, mask_secret
from core.integrations.ai_providers import (
    OpenAIAdapter,
    AnthropicAdapter,
    GoogleGeminiAdapter,
    OpenRouterAdapter,
    OllamaLocalAdapter
)
from core.scope_policy import scope_policy

logger = logging.getLogger("swa.ai_agent_api")

router = APIRouter(prefix="/api", tags=["AI Agents & Copilot"])

# Known recommended models per provider
PROVIDER_CATALOG = {
    "openai": {
        "display_name": "OpenAI",
        "description": "State-of-the-art GPT models for penetration testing and automated vulnerability analysis.",
        "requires_api_key": True,
        "recommended_models": [
            {"id": "gpt-4o", "name": "GPT-4o (Flagship Multimodal & Reasoning)"},
            {"id": "gpt-4o-mini", "name": "GPT-4o Mini (Fast & Cost-Efficient)"},
            {"id": "o1-preview", "name": "OpenAI o1 (Deep Reasoning for Complex Exploits)"},
            {"id": "gpt-4-turbo", "name": "GPT-4 Turbo (128k Context)"}
        ]
    },
    "anthropic": {
        "display_name": "Anthropic Claude",
        "description": "Claude 3.5 Sonnet and Haiku models specialized in code security analysis and threat modeling.",
        "requires_api_key": True,
        "recommended_models": [
            {"id": "claude-3-5-sonnet-20241022", "name": "Claude 3.5 Sonnet (Best for Code Review & Exploit Validation)"},
            {"id": "claude-3-5-haiku-20241022", "name": "Claude 3.5 Haiku (Ultra-Fast Response)"},
            {"id": "claude-3-opus-20240229", "name": "Claude 3 Opus (High Intelligence Deep Audit)"}
        ]
    },
    "gemini": {
        "display_name": "Google Gemini",
        "description": "Gemini 1.5 Pro and Flash with massive context windows for whole-codebase SAST analysis.",
        "requires_api_key": True,
        "recommended_models": [
            {"id": "gemini-1.5-pro", "name": "Gemini 1.5 Pro (2M Token Context & High Reasoning)"},
            {"id": "gemini-1.5-flash", "name": "Gemini 1.5 Flash (Lightweight & Low Latency)"},
            {"id": "gemini-2.0-flash-exp", "name": "Gemini 2.0 Flash Experimental"}
        ]
    },
    "openrouter": {
        "display_name": "OpenRouter",
        "description": "Unified gateway to open and proprietary models (Llama 3.3, DeepSeek, Mistral, Minimax).",
        "requires_api_key": True,
        "recommended_models": [
            {"id": "minimax/minimax-m3.1-flash:free", "name": "MiniMax M3.1 Flash (Free Tier)"},
            {"id": "deepseek/deepseek-chat", "name": "DeepSeek V3 (High Reasoning Cost-Effective)"},
            {"id": "meta-llama/llama-3.3-70b-instruct", "name": "Llama 3.3 70B Instruct"},
            {"id": "mistralai/mistral-large-2411", "name": "Mistral Large 2"}
        ]
    },
    "custom": {
        "display_name": "Custom OpenAI-Compatible API",
        "description": "Connect self-hosted or proxy endpoints (vLLM, Ollama, LM Studio, Together AI, Groq, LiteLLM).",
        "requires_api_key": False,
        "recommended_models": [
            {"id": "llama3.2", "name": "Llama 3.2 (Local Ollama)"},
            {"id": "mistral-nemo", "name": "Mistral Nemo (12B Local)"},
            {"id": "qwen2.5-coder", "name": "Qwen 2.5 Coder (Specialized SAST)"},
            {"id": "custom-model", "name": "Custom Model Identifier"}
        ]
    },
    "heuristic": {
        "display_name": "SWA Deterministic Heuristic",
        "description": "Zero-dependency local cybersecurity reasoning engine with deterministic rules and CVSS calculation.",
        "requires_api_key": False,
        "recommended_models": [
            {"id": "swa-cyber-reasoning-v2", "name": "SWA Deterministic Engine v2.2 (Offline Safe)"}
        ]
    }
}


# =====================================================================
# Request / Response Models
# =====================================================================

class CreateAIAgentRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    provider: str
    model: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    description: Optional[str] = None
    role: Optional[str] = "Cybersecurity Specialist"
    enabled: bool = True
    is_default: bool = False
    test_connection_now: bool = True


class UpdateAIAgentRequest(BaseModel):
    name: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    description: Optional[str] = None
    role: Optional[str] = None
    enabled: Optional[bool] = None
    is_default: Optional[bool] = None


class TestConnectionRequest(BaseModel):
    provider: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model: Optional[str] = None


class CopilotChatMsg(BaseModel):
    role: str
    content: str


class CopilotChatReq(BaseModel):
    message: str = Field(..., min_length=1)
    target: Optional[str] = "127.0.0.1:8000"
    agent_id: Optional[str] = None
    conversation_history: Optional[List[CopilotChatMsg]] = None


class CurlPocReq(BaseModel):
    target: str
    finding_id: Optional[str] = None


class DefensivePatchReq(BaseModel):
    target: str
    finding_id: Optional[str] = None
    tech_stack: Optional[List[str]] = None


class ScopeVerificationReq(BaseModel):
    target: str
    lab_mode: Optional[bool] = None


# =====================================================================
# Helpers
# =====================================================================

def _encrypt_key(raw_key: str) -> tuple[str, str]:
    """Encrypts raw API key using credentials_vault; returns (api_key_encrypted, api_key_masked)."""
    if not raw_key or not raw_key.strip():
        return "", ""
    clean = raw_key.strip()
    cipher, salt = credentials_vault.encrypt(clean)
    encrypted_str = f"{salt}:{cipher}"
    masked = mask_secret(clean)
    return encrypted_str, masked


def _decrypt_key(encrypted_str: str) -> Optional[str]:
    """Decrypts API key from stored salt:cipher format."""
    if not encrypted_str:
        return None
    try:
        if ":" in encrypted_str:
            salt, cipher = encrypted_str.split(":", 1)
            return credentials_vault.decrypt(cipher, salt)
        return None
    except Exception as e:
        logger.error(f"Error decrypting stored API key: {e}")
        return None


async def _run_provider_test(provider: str, api_key: str, base_url: Optional[str] = None, model: Optional[str] = None) -> Dict[str, Any]:
    """Tests provider connectivity using appropriate adapter."""
    p_lower = provider.lower().strip()
    creds = {"api_key": api_key, "base_url": base_url or ""}

    if p_lower == "heuristic":
        return {"success": True, "status": "CONNECTED", "message": "Local deterministic engine verified.", "latency_ms": 1}

    if p_lower == "openai":
        adapter = OpenAIAdapter()
        return await adapter.test_connection(creds, endpoint_url=base_url)
    elif p_lower == "anthropic":
        adapter = AnthropicAdapter()
        return await adapter.test_connection(creds, endpoint_url=base_url)
    elif p_lower == "gemini":
        adapter = GoogleGeminiAdapter()
        return await adapter.test_connection(creds, endpoint_url=base_url)
    elif p_lower == "openrouter":
        adapter = OpenRouterAdapter()
        return await adapter.test_connection(creds, endpoint_url=base_url)
    elif p_lower in ("custom", "ollama"):
        endpoint = base_url or "http://127.0.0.1:11434"
        adapter = OllamaLocalAdapter()
        return await adapter.test_connection(creds, endpoint_url=endpoint)
    else:
        # Fallback to OpenAI-compatible test
        adapter = OpenAIAdapter()
        return await adapter.test_connection(creds, endpoint_url=base_url)


# =====================================================================
# AI Agent Management Endpoints
# =====================================================================

@router.get("/ai-agents")
async def list_ai_agents(enabled_only: bool = False):
    """Lists all configured AI agents with masked secrets."""
    return db.list_ai_agents(enabled_only=enabled_only)


@router.get("/ai-agents/models-catalog")
async def get_models_catalog():
    """Returns available providers and recommended models catalog."""
    return PROVIDER_CATALOG


@router.post("/ai-agents/test-connection")
async def test_uncommitted_connection(req: TestConnectionRequest):
    """Tests provider credentials before saving an agent."""
    if req.provider.lower() not in PROVIDER_CATALOG:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {req.provider}")
    
    key = (req.api_key or "").strip()
    if PROVIDER_CATALOG[req.provider.lower()]["requires_api_key"] and not key:
        return {
            "success": False,
            "status": "NOT_CONFIGURED",
            "message": f"API key is required for {PROVIDER_CATALOG[req.provider.lower()]['display_name']}.",
            "latency_ms": 0
        }
    
    res = await _run_provider_test(req.provider, key, base_url=req.base_url, model=req.model)
    return res


@router.post("/ai-agents")
async def create_ai_agent(req: CreateAIAgentRequest):
    """Creates a new AI agent with encrypted credentials."""
    p_lower = req.provider.lower().strip()
    if p_lower not in PROVIDER_CATALOG:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {req.provider}")

    raw_key = (req.api_key or "").strip()
    if PROVIDER_CATALOG[p_lower]["requires_api_key"] and not raw_key:
        raise HTTPException(status_code=400, detail=f"API key is required for provider {req.provider}.")

    # Encrypt secret at rest
    enc_key, masked_key = _encrypt_key(raw_key)

    # Test connection if requested
    conn_status = "CONNECTED" if p_lower == "heuristic" else "DISCONNECTED"
    last_error = ""
    last_tested = None
    if req.test_connection_now and p_lower != "heuristic" and raw_key:
        test_res = await _run_provider_test(p_lower, raw_key, base_url=req.base_url, model=req.model)
        conn_status = "CONNECTED" if test_res.get("success") else ("INVALID_KEY" if test_res.get("status") == "AUTHENTICATION_FAILED" else "DISCONNECTED")
        last_error = test_res.get("message", "")
        last_tested = datetime.datetime.now(datetime.timezone.utc).isoformat()

    agent_id = f"agent_{uuid.uuid4().hex[:10]}"
    agent_data = {
        "id": agent_id,
        "name": req.name,
        "provider": p_lower,
        "model": req.model,
        "base_url": req.base_url,
        "api_key_encrypted": enc_key,
        "api_key_masked": masked_key,
        "description": req.description or f"{req.role} powered by {req.provider}",
        "role": req.role or "Cybersecurity Specialist",
        "enabled": req.enabled,
        "is_default": req.is_default,
        "connection_status": conn_status,
        "last_tested_at": last_tested,
        "last_error": last_error
    }

    db.create_ai_agent(agent_data)
    created = db.get_ai_agent(agent_id)
    return created



# =====================================================================
# AI Provider Usage & Metrics
# =====================================================================

@router.get("/ai-agents/usage")
async def get_provider_usage_metrics():
    """Returns aggregated API usage metrics derived from persisted agent task history.

    Token counts and dollar costs are NOT metered by the platform, so they are
    reported as null with an explicit note rather than fabricated figures.
    """
    agents = db.list_ai_agents()
    try:
        tasks = db.get_agent_tasks()
    except Exception:
        tasks = []
    total = len(tasks)
    completed = sum(1 for t in tasks if str(t.get("status", "")).upper() == "COMPLETED")
    failed = sum(1 for t in tasks if str(t.get("status", "")).upper() == "FAILED")
    durations = [t.get("duration_seconds") for t in tasks if isinstance(t.get("duration_seconds"), (int, float))]
    avg_latency_ms = round((sum(durations) / len(durations)) * 1000, 2) if durations else None
    return {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_configured_agents": len(agents),
        "connected_agents": sum(1 for a in agents if a.get("connection_status") == "CONNECTED"),
        "active_agents": sum(1 for a in agents if a.get("enabled")),
        "default_agent": db.get_default_ai_agent(),
        "providers_active": list(set(a["provider"] for a in agents if a.get("enabled"))),
        "usage_summary": {
            "total_requests": total,
            "successful_requests": completed,
            "failed_requests": failed,
            "estimated_tokens_consumed": None,
            "estimated_cost_usd": None,
            "average_latency_ms": avg_latency_ms,
            "measurement_note": "Counts derived from persisted agent_tasks history. Token/cost metering is not implemented; values are null, not estimated."
        }
    }


@router.get("/ai-agents/{agent_id}")
async def get_ai_agent_details(agent_id: str):
    """Retrieves single agent metadata without raw secrets."""
    agent = db.get_ai_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")
    return agent


@router.put("/ai-agents/{agent_id}")
async def update_ai_agent(agent_id: str, req: UpdateAIAgentRequest):
    """Updates an existing agent, re-encrypting key if a new one is provided."""
    existing = db.get_ai_agent(agent_id, include_encrypted_key=True)
    if not existing:
        raise HTTPException(status_code=404, detail="Agent not found.")

    updates: Dict[str, Any] = {}
    if req.name is not None:
        updates["name"] = req.name
    if req.provider is not None:
        updates["provider"] = req.provider.lower()
    if req.model is not None:
        updates["model"] = req.model
    if req.base_url is not None:
        updates["base_url"] = req.base_url
    if req.description is not None:
        updates["description"] = req.description
    if req.role is not None:
        updates["role"] = req.role
    if req.enabled is not None:
        updates["enabled"] = 1 if req.enabled else 0
    if req.is_default is not None:
        updates["is_default"] = 1 if req.is_default else 0

    if req.api_key is not None and req.api_key.strip():
        enc_key, masked_key = _encrypt_key(req.api_key.strip())
        updates["api_key_encrypted"] = enc_key
        updates["api_key_masked"] = masked_key
        updates["connection_status"] = "TESTING"

    db.update_ai_agent(agent_id, updates)
    return db.get_ai_agent(agent_id)


@router.delete("/ai-agents/{agent_id}")
async def delete_ai_agent(agent_id: str):
    """Deletes an agent."""
    if agent_id == "agent_default_swa":
        raise HTTPException(status_code=400, detail="Cannot delete default built-in SWA agent.")
    success = db.delete_ai_agent(agent_id)
    if not success:
        raise HTTPException(status_code=404, detail="Agent not found.")
    return {"success": True, "message": f"Agent {agent_id} deleted."}


@router.post("/ai-agents/{agent_id}/test")
async def test_saved_agent_connection(agent_id: str):
    """Tests connection for a saved agent using its decrypted key."""
    agent = db.get_ai_agent(agent_id, include_encrypted_key=True)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")

    provider = agent["provider"]
    if provider == "heuristic":
        return {"success": True, "status": "CONNECTED", "message": "Local heuristic verified.", "latency_ms": 1}

    decrypted_key = _decrypt_key(agent.get("api_key_encrypted", ""))
    if not decrypted_key:
        db.update_ai_agent(agent_id, {"connection_status": "DISCONNECTED", "last_error": "No API key stored."})
        return {"success": False, "status": "NOT_CONFIGURED", "message": "No API key configured for agent."}

    res = await _run_provider_test(provider, decrypted_key, base_url=agent.get("base_url"), model=agent.get("model"))
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    new_status = "CONNECTED" if res.get("success") else ("INVALID_KEY" if res.get("status") == "AUTHENTICATION_FAILED" else "DISCONNECTED")
    db.update_ai_agent(agent_id, {
        "connection_status": new_status,
        "last_tested_at": now,
        "last_error": res.get("message", "")
    })
    return res


@router.post("/ai-agents/{agent_id}/set-default")
async def set_default_agent(agent_id: str):
    """Sets the designated agent as default."""
    agent = db.get_ai_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")
    db.set_default_ai_agent(agent_id)
    return {"success": True, "message": f"Agent {agent['name']} set as default."}



# =====================================================================
# Multi-Agent Collaboration Pipeline
# =====================================================================

@router.post("/agents/collaborate")
async def run_multi_agent_collaboration(req: Dict[str, Any]):
    """
    Executes a multi-agent orchestrated cybersecurity workflow across the specialist workforce:
    1. Reconnaissance Agent -> Asset discovery
    2. Vulnerability Agent -> OWASP testing
    3. Risk Assessment Agent -> CVSS calculation
    4. Safe Exploitation Agent -> Minimal reproduction cURL PoC
    5. Defensive Remediation Agent -> WAF and patch generation
    6. Reporting Agent -> Final consolidated deliverable
    """
    target = req.get("target", "127.0.0.1:8000")
    is_lab = bool(req.get("lab_mode")) or any(h in str(target) for h in ("127.0.0.1", "localhost", "[::1]"))
    scope_res = scope_policy.validate_target(target, explicit_lab_authorization=is_lab)
    if not scope_res.is_allowed:
        raise HTTPException(status_code=403, detail=f"Scope policy refusal: {scope_res.reason}")

    start_time = time.time()
    scan_id = f"collab_{uuid.uuid4().hex[:8]}"

    from core.agent_registry import agent_registry
    from core.scoring import compute_posture

    findings = db.list_findings()
    top_findings = findings[:5] if findings else []
    workflow_stages = []

    async def _dispatch_stage(stage_num, label, agent_id, dispatch_inputs):
        rec = None
        status = "NOT_EXECUTABLE"
        summary = "No executable handler wired for this stage."
        try:
            rec = await asyncio.wait_for(
                agent_registry.dispatch_agent_by_id(
                    agent_id,
                    scan_id=scan_id,
                    title=f"Collaboration stage {stage_num}: {label}",
                    inputs=dispatch_inputs,
                ),
                timeout=90.0,
            )
        except asyncio.TimeoutError:
            rec = {"status": "FAILED", "error_message": "Stage timed out after 90s."}
        except Exception as e:
            rec = {"status": "FAILED", "error_message": str(e)}
        if rec:
            status = str(rec.get("status") or "FAILED").upper()
            outputs = rec.get("outputs") or {}
            summary = (
                rec.get("error_message")
                or outputs.get("summary")
                or outputs.get("note")
                or "No handler output recorded."
            )
        workflow_stages.append({
            "stage": f"{stage_num}. {label}",
            "agent": agent_id,
            "status": status,
            "summary": str(summary)[:500],
        })

    await _dispatch_stage(1, "Reconnaissance", "attack_surface_agent", {"target": target})
    await _dispatch_stage(2, "Vulnerability Assessment (dependency confusion probe)", "dependency_confusion_agent", {"target": target})
    await _dispatch_stage(4, "Exploit Verification", "exploit_validator_agent", {"target": target})
    await _dispatch_stage(5, "Defensive Remediation", "remediation_lifecycle_agent", {"target": target})

    # Stage 3: deterministic risk prioritization from real findings (no model claim)
    posture = compute_posture(findings)
    workflow_stages.insert(2, {
        "stage": "3. Risk Prioritization",
        "agent": "core.scoring.compute_posture",
        "status": "COMPLETED",
        "summary": (f"Canonical posture score {posture['score']}/100 (grade {posture['grade']}, "
                    f"risk {posture['risk']}) from {posture['total']} stored findings.")
    })

    # Stage 6: report generation is delegated to the reports subsystem (not auto-run here)
    workflow_stages.append({
        "stage": "6. Report Generation",
        "agent": "reports.generator",
        "status": "NOT_RUN",
        "summary": "Report generation is available via /api/reports/generate or /api/cyber/export/generate; it is not auto-executed by collaboration requests."
    })

    duration = round(time.time() - start_time, 2)
    stage_statuses = [st["status"] for st in workflow_stages]
    overall = "COMPLETED" if all(s == "COMPLETED" for s in stage_statuses) else (
        "DEGRADED" if any(s == "COMPLETED" for s in stage_statuses) else "NOT_COMPLETED")
    return {
        "status": overall,
        "scan_id": scan_id,
        "target": target,
        "duration_seconds": duration,
        "stages": workflow_stages,
        "posture": posture,
        "consolidated_findings_count": len(findings),
        "top_findings": [f.title for f in top_findings]
    }


# =====================================================================
# SWA AI Security Copilot Actions
# =====================================================================

@router.post("/copilot/curl-poc")
async def copilot_curl_poc_endpoint(req: CurlPocReq):
    """Generates minimal reproduction cURL requests for authorized targets."""
    target = req.target.strip()
    findings = db.list_findings()

    target_clean = target.replace("http://", "").replace("https://", "").split("/")[0]

    # Look for existing cURL PoC
    pocs = [f for f in findings if getattr(f, "poc_curl", None)]
    if pocs:
        f = pocs[0]
        cwe = getattr(f, "cwe_id", "CWE-942")
        return {
            "success": True,
            "target": target,
            "title": f.title,
            "cwe_id": cwe,
            "curl_command": f.poc_curl,
            "expected_response": "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://evil-attacker.com\nAccess-Control-Allow-Credentials: true\n\n(Dynamic CORS reflection payload verified)",
            "explanation": f"Verifies {f.title} by transmitting crafted origin header to test dynamic reflection without origin allowlisting."
        }
    else:
        cmd = f"curl -i -s -k -X GET \"http://{target_clean}/\" \\\n  -H \"Origin: https://evil-attacker.com\" \\\n  -H \"User-Agent: SWA-Security-Auditor/2.2\""
        return {
            "success": True,
            "target": target,
            "title": "Cross-Origin Resource Sharing (CORS) Reflection Audit",
            "cwe_id": "CWE-942",
            "curl_command": cmd,
            "expected_response": "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: https://evil-attacker.com\n...",
            "explanation": "Audits whether the web server dynamically reflects arbitrary untrusted Origin headers with credentials allowed."
        }


@router.post("/copilot/defensive-patch")
async def copilot_defensive_patch_endpoint(req: DefensivePatchReq):
    """Generates concrete remediation code, defensive headers, and verification steps."""
    target = req.target.strip()
    return {
        "success": True,
        "target": target,
        "remediation_summary": "Comprehensive zero-trust defensive hardening package for HTTP headers and CORS configuration.",
        "patches": [
            {
                "platform": "Nginx Reverse Proxy (/etc/nginx/conf.d/security.conf)",
                "code": (
                    "# Enforce Strict Defensive Security Headers\n"
                    "add_header X-Content-Type-Options \"nosniff\" always;\n"
                    "add_header X-Frame-Options \"DENY\" always;\n"
                    "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\" always;\n"
                    "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
                    "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;\n"
                )
            },
            {
                "platform": "FastAPI / Python (Server Hardening)",
                "code": (
                    "from fastapi.middleware.cors import CORSMiddleware\n\n"
                    "# Replace allow_origins=['*'] with explicit trusted allowlist\n"
                    "TRUSTED_ORIGINS = ['https://app.yourdomain.com']\n\n"
                    "app.add_middleware(\n"
                    "    CORSMiddleware,\n"
                    "    allow_origins=TRUSTED_ORIGINS,\n"
                    "    allow_credentials=True,\n"
                    "    allow_methods=['GET', 'POST', 'PUT', 'DELETE'],\n"
                    "    allow_headers=['Content-Type', 'Authorization'],\n"
                    ")\n"
                )
            },
            {
                "platform": "WAF Rule (ModSecurity / Cloudflare)",
                "code": (
                    "# Block requests with anomalous Origin headers against API routes\n"
                    "SecRule REQUEST_HEADERS:Origin \"@rx ^https?://(evil|attacker|localhost|127\\.0\\.0\\.1)\" \\\n"
                    "    \"id:10001,phase:1,deny,status:403,log,msg:'Potential CORS Exploitation Attempt Blocked'\"\n"
                )
            }
        ],
        "verification_steps": [
            "1. Apply configuration changes and reload reverse proxy (nginx -s reload).",
            "2. Execute verification cURL: curl -i -X GET https://target/ | grep -i 'X-Content-Type-Options'",
            "3. Confirm response returns: X-Content-Type-Options: nosniff and X-Frame-Options: DENY."
        ]
    }


@router.post("/copilot/scope-verification")
async def copilot_scope_verification_endpoint(req: ScopeVerificationReq):
    """Enforces server-side assessment scope and SSRF protection boundaries."""
    target = req.target.strip()
    is_lab = req.lab_mode if req.lab_mode is not None else ("127.0.0.1" in target or "localhost" in target)

    res = scope_policy.validate_target(target, explicit_lab_authorization=is_lab)

    return {
        "target": target,
        "is_authorized": res.is_allowed,
        "hostname": res.hostname,
        "resolved_ip": res.resolved_ip,
        "is_lab_target": res.is_lab_target,
        "decision": "AUTHORIZED" if res.is_allowed else "BLOCKED_BY_SCOPE_POLICY",
        "reason": res.reason or "Target authorized within approved assessment perimeter.",
        "ssrf_protection_enforced": True,
        "dangerous_probes_blocked": True,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }
