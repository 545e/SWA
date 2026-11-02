# SWA AI — API Key & Secrets Configuration Guide

## 1. Overview & Cryptographic Architecture

SWA AI provides enterprise-grade API key and secret token management for all external AI providers, threat intelligence feeds, SIEM/EDR platforms, and cloud environments.

### Key Security Principles
1. **Zero Secret Exposure to Frontend**: Full API keys and secrets are never returned in REST API responses or injected into client-side JavaScript. Only safe, masked tokens (e.g., `sk-ant-***-8x9q`) are presented in the UI.
2. **Encryption at Rest**: Stored credentials are encrypted in SQLite using Fernet (AES-128-CBC + HMAC-SHA256) with unique per-credential salt derivation (PBKDF2HMAC with SHA-256 and 100,000 iterations).
3. **Master Key Isolation**: The master encryption key is kept strictly outside the database. It can be supplied via the `SWA_ENCRYPTION_KEY` environment variable or read from a restricted keyfile (`.swa_master.key`).
4. **SSRF & Egress Protection**: All outbound connection tests validate destinations against strict SSRF rules, disallowing loopback addresses and cloud metadata endpoints (IMDSv2 `169.254.169.254`).

---

## 2. Configuring Keys via Web UI (Recommended)

1. Open the SWA AI Dashboard at `http://127.0.0.1:8000`.
2. In the left navigation, click **Settings**.
3. Select the **API Keys & Integrations** tab.
4. Click **+ Add Integration**.
5. Select your provider (e.g., VirusTotal, OpenAI, Wazuh, AWS).
6. Enter your credentials. The UI displays provider-specific setup guides and required permissions.
7. Click **Save Integration**.
8. Click **Test** to immediately verify live reachability and authentication.

---

## 3. Configuring Keys via Environment Variables (`.env`)

For headless, automated, and containerized deployments, you can supply API keys directly in `.env`. Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

### Supported Environment Variables

#### Master Encryption Key
```bash
# Generate via: python -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
SWA_ENCRYPTION_KEY=your_base64_master_encryption_key_here
```

#### AI Providers
```bash
OPENAI_API_KEY=sk-proj-your_openai_api_key
ANTHROPIC_API_KEY=sk-ant-your_anthropic_api_key
GEMINI_API_KEY=AIzaSy_your_gemini_api_key
OPENROUTER_API_KEY=sk-or-v1-your_openrouter_api_key
# For local offline models:
OLLAMA_BASE_URL=http://127.0.0.1:11434
```

#### Threat Intelligence Feeds
```bash
VIRUSTOTAL_API_KEY=your_virustotal_v3_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
SHODAN_API_KEY=your_shodan_api_key
CENSYS_API_ID=your_censys_api_id
CENSYS_API_SECRET=your_censys_api_secret
ALIENVAULT_OTX_KEY=your_alienvault_otx_key
URLHAUS_AUTH_KEY=your_urlhaus_auth_key
```

#### SIEM & Security Platforms
```bash
WAZUH_MANAGER_URL=https://wazuh-manager.internal:55000
WAZUH_API_USER=wazuh-api
WAZUH_API_PASSWORD=your_wazuh_password

SPLUNK_URL=https://splunk.internal:8088
SPLUNK_HEC_TOKEN=your_splunk_hec_token

ELASTICSEARCH_URL=https://elastic.internal:9200
ELASTIC_API_KEY=your_elastic_api_key

DEFECTDOJO_URL=https://defectdojo.internal/api/v2
DEFECTDOJO_API_KEY=Token your_defectdojo_api_key
```

---

## 4. Credential Rotation & Deletion

- **Rotation**: In **Settings → API Keys & Integrations**, click **Rotate** or **Edit** on any configured integration card. Enter the new token and save. SWA generates a fresh cryptographic salt, re-encrypts the secret, and tests connectivity.
- **Revocation**: Click **Delete** on any integration card. SWA immediately deletes both the integration entry and the associated row from `encrypted_credentials`, ensuring no cached secrets remain in storage.
