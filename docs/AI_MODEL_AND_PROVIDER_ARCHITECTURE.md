# AI MODEL AND PROVIDER ARCHITECTURE
## Multi-Provider Orchestration, Dynamic Fallback & Encrypted Credential Brokerage

### 1. Supported Providers & Models

| Provider | Supported Model Identifiers | Authentication Mechanism | Streaming Support | Function / Tool Calling |
|---|---|---|---|---|
| **OpenAI** | `gpt-4o`, `gpt-4o-mini`, `o1-preview`, `o3-mini` | `Authorization: Bearer <key>` | YES | Standard OpenAI Tool JSON |
| **Anthropic** | `claude-3-5-sonnet-20241022`, `claude-3-haiku-20240307` | `x-api-key: <key>`, `anthropic-version: 2023-06-01` | YES | Anthropic Tool Block Schema |
| **Google Gemini** | `gemini-1.5-pro`, `gemini-1.5-flash`, `gemini-2.0-flash` | Query parameter `?key=<key>` or Bearer | YES | Gemini Function Declarations |
| **OpenRouter** | `meta-llama/llama-3.3-70b-instruct`, `mistralai/mistral-large-2407` | `Authorization: Bearer <key>` | YES | OpenAI Compatible |
| **Azure OpenAI** | Custom deployed endpoints (`gpt-4o`) | `api-key: <key>` | YES | OpenAI Compatible |
| **Ollama (Local)** | `llama3.2:latest`, `deepseek-r1:latest`, `codellama` | HTTP endpoint (`http://localhost:11434/api/generate`) | YES | Direct JSON Payload |
| **Deterministic Fallback** | `heuristic-engine-v2.3` | Internal rule-based scoring (Zero dependency) | NO | Direct Rule Execution |

---

### 2. Credential Brokerage & Zero-Leakage Guarantee

All external provider keys are stored in an encrypted database table (`integration_credentials`) using Fernet symmetric encryption (AES-128-CBC with HMAC-SHA256).
- **Master Key**: Generated and isolated in `.swa_master.key` outside the database.
- **PBKDF2 Key Derivation**: 100,000 SHA-256 iterations with per-installation salt.
- **Zero Plain-Text Leakage**: All API responses (`GET /api/integrations`, `GET /api/settings`) mask secrets automatically (e.g. `sk-pro************9aF`).

---

### 3. Fail-Safe Execution Flow

```text
User Request / Assessment Probe
              │
              ▼
   Is Vault Credential Configured?
        ├── YES ──► Route to Target Provider API (OpenAI / Anthropic / Gemini / Ollama)
        │                 │
        │           Is API Successful?
        │                 ├── YES ──► Parse Structured JSON Output
        │                 └── NO (Network / Quota) ──► Transparent Fallback
        │                                                     │
        └── NO ───────────────────────────────────────────────▼
                                                 Autonomous Deterministic Engine
                                                 • CVSS v3.1 Matrix Engine
                                                 • RAG Grounded Context Analysis
                                                 • Zero False-Positive Evidence Rules
```
