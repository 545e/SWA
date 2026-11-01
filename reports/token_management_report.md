# SWA AI — Token & API Provider Management Report
**Document ID:** SEC-TOK-2026  
**Generated:** 2026-11-01T06:57:46.575012+00:00  

---

## 1. Provider & Credential Architecture
SWA AI manages credentials and API keys through a centralized secure configuration store:
- **Secret Storage:** Environment variable injection and encrypted local storage; zero hardcoded secrets in version control.
- **Secret Display:** Strict masking (e.g. `sk-proj-****48f2`) across all frontend views and API responses.
- **Provider Status:**
  - Local AI Engine: **HEALTHY** (Python transformers runtime active)
  - OpenAI / Anthropic / Gemini: **INTEGRATED_NOT_CONFIGURED** (Awaiting user API key)
  - Jira / Slack: **INTEGRATED_NOT_CONFIGURED** (Webhook formatters active)
