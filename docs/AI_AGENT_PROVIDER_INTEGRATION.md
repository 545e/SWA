# SWA AI / SNMK — AI Agent & Model Provider Integration

## Executive Summary
This document explains how encrypted API keys stored in the SNMK Vault are dynamically retrieved, decrypted, and injected into the multi-agent reasoning pipeline (`SWALLMClient`), powering all **85 specialized autonomous cybersecurity agents**.

---

## 1. Credential Resolution Chain

When an agent needs LLM reasoning (for exploit verification, vulnerability remediation, AST analysis, threat hunting, or report synthesis), `SWALLMClient` resolves its provider credentials in order of precedence:

```
1. Explicit Constructor Arguments
   └── Provided directly during agent initialization.

2. Database Cryptographic Vault (High Priority)
   └── IntegrationRegistry.get_default_ai_provider()
       Queries: SELECT * FROM integrations WHERE category = 'ai_provider' AND enabled = 1
       Selects default provider or most recently updated provider.
       Decrypts secret via CredentialsVault.decrypt() into RAM.

3. Environment Variables (Fallback)
   └── OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY, OPENROUTER_API_KEY

4. Deterministic Heuristic Engine v2.3 (Offline Air-Gapped Fallback)
   └── If no valid API key is present or all endpoints are unreachable,
       agents execute rule-based heuristic threat deduction with zero downtime.
```

---

## 2. Dynamic Model Switching & Default Provider Selection

The API Key Management Center allows operators to designate a default AI provider via the `is_default` checkbox in `#apiKeyModal`.

- **Automatic Selection:** When marked `is_default = true`, `IntegrationRegistry.get_default_ai_provider()` immediately routes all future agent calls to this provider.
- **Provider Switching:** If an operator adds Google Gemini Pro, it immediately becomes the active reasoning engine across:
  - `agents/recon_agent.py`
  - `agents/exploit_verifier.py`
  - `agents/remediation_agent.py`
  - `agents/threat_intel_agent.py`
  - `agents/soc_analyst_agent.py`
  - All 85 autonomous agents registered in `agents/registry.py`.

---

## 3. Grounded Retrieval-Augmented Generation (RAG) Integration

Once an AI key is connected:
1. `SWALLMClient.reason(prompt, use_rag=True, session_id=sid)` automatically queries the `EnterpriseRAGEngine` (`core/rag_engine.py`).
2. Relevant security findings, CVE catalogs, and mitigation playbooks are retrieved via hybrid BM25 + semantic similarity.
3. Citations (`[Doc: ... | Chunk #...]`) are prepended into the system prompt.
4. Episodic and working memory in `AgentMemoryStore` (`core/agent_memory.py`) are sanitized for credential leakage before passing context to external LLM APIs.
