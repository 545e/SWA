# SWA AI Secure API Key & Provider Integrations Management

## Overview
SWA AI incorporates an enterprise-grade, cryptographically protected API Key Management Center supporting 23 external AI, threat intelligence, SIEM/EDR, vulnerability management, and cloud security providers.

---

## 1. Cryptographic Storage Architecture

* **Encryption Standard**: Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256 authenticated encryption) derived via **PBKDF2HMAC** (100,000 iterations of SHA-256 with unique 16-byte random salt per secret).
* **Master Key Isolation**: Stored strictly outside the database in an isolated local keyfile (`.swa_master.key`) with restricted filesystem permissions, or supplied via environment variable `SWA_ENCRYPTION_KEY`.
* **Zero Secret Leakage Guarantee**:
  - Raw secrets are never stored in browser `localStorage`, `sessionStorage`, cookies, or JavaScript variables.
  - Raw secrets are never returned in ordinary API responses (`GET /api/integrations`, `GET /api/integrations/{id}`, or `/api/v1/integrations`).
  - All credential listings return masked representations (e.g. `sk-ant-***-8x9q`, `AIzaSy***1234`).
  - Raw keys are purged from frontend form memory immediately upon submission.
  - Audit logs record credential actions (`integration.save`, `integration.test`, `integration.rotate`, `integration.delete`) with masked identifiers only.

---

## 2. API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/integrations/summary` | Real-time counts: total supported, configured, connected, attention required, unconfigured |
| `GET` | `/api/integrations/providers` | Metadata, credential schemas, setup instructions, and docs URLs for all 23 providers |
| `GET` | `/api/integrations` | List configured integrations with masked secrets and connection status |
| `GET` | `/api/integrations/{id}` | Single integration metadata (masked) |
| `POST` | `/api/integrations` | Add or update integration credentials (encrypted at rest) |
| `POST` | `/api/integrations/test` | Ad-hoc live connection probe using supplied test key before saving |
| `POST` | `/api/integrations/{id}/test` | Execute live connection test against provider using decrypted vault credentials |
| `POST` | `/api/integrations/{id}/rotate` | Rotate secret token without destroying existing configuration or metadata |
| `POST` | `/api/integrations/{id}/toggle` | Enable or disable integration |
| `DELETE` | `/api/integrations/{id}` | Purge integration configuration and encrypted credentials |
| `GET` | `/api/ai/llm-status` | Truthful operational status of the active AI reasoning client |

---

## 3. Supported Provider Categories

### A. AI Model Reasoning Providers
- **Google Gemini**: Gemini 2.0 Flash, Gemini 1.5 Pro, Gemini 1.5 Flash
- **OpenAI**: GPT-4o, GPT-4o-mini, GPT-4-Turbo, o1-preview
- **Anthropic Claude**: Claude 3.5 Sonnet, Claude 3 Opus, Claude 3 Haiku
- **OpenRouter**: Unified access to 100+ open-source and commercial models
- **Ollama**: Local, private, offline models (Llama 3, Mistral, Qwen, DeepSeek Coder) without requiring an external API key

### B. Threat Intelligence Feeds
- **VirusTotal**: IP, domain, hash reputation & malware detection
- **AbuseIPDB**: Crowdsourced malicious IP reporting and threat confidence scores
- **Shodan**: Internet-wide open port, banner grab, and IoT service intelligence
- **Censys**: Certificate, host, and attack surface discovery
- **AlienVault OTX**: Threat pulses, indicators of compromise (IOCs)
- **FIRST EPSS**: Empirical exploit prediction scoring system
- **CISA KEV**: Known Exploited Vulnerabilities catalog
- **URLhaus**: Active malicious malware distribution URLs

### C. Security & Cloud Platforms
- **Wazuh**: Open-source SIEM & XDR endpoint telemetry
- **Splunk**: Security information and event management
- **Elastic Security**: Elasticsearch security analytics
- **Microsoft Sentinel**: Cloud-native SIEM/SOAR
- **CrowdStrike Falcon**: Next-gen EDR & threat hunting
- **OWASP DefectDojo**: Vulnerability management & deduplication
- **Tenable Nessus / Tenable.io**: Infrastructure vulnerability scanning
- **AWS / Azure / GCP**: Cloud security posture management & audit

---

## 4. SWALLMClient Vault Integration

The `SWALLMClient` in `core/llm_client.py` is directly connected to the encrypted credentials vault:
1. When instantiated with `provider="auto"` and no environment variables are set, it queries `integration_registry.get_default_ai_provider()`.
2. It decrypts the active credential in memory for authorized network dispatch only.
3. If no AI provider is configured in the vault, it gracefully operates in **Deterministic Heuristic Engine v2.3** mode (CVSS scoring, OWASP categorization, and verified PoC templates) without fabricating artificial responses.
