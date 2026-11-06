# SWA AI / SNMK — Comprehensive 23 Provider Integrations Inventory

The SNMK platform provides native adapter integrations for exactly 23 security, threat intelligence, cloud, and AI model providers.

---

## 1. AI Model Providers (5 Providers)

| Provider ID | Display Name | Category | Primary Purpose | Default Models Supported |
| :--- | :--- | :--- | :--- | :--- |
| `openai` | OpenAI | `ai_provider` | Multi-agent reasoning, remediation synthesis | `gpt-4o`, `gpt-4o-mini`, `gpt-4-turbo`, `o1-preview` |
| `anthropic` | Anthropic Claude | `ai_provider` | Deep code vulnerability analysis & AST review | `claude-3-5-sonnet-20241022`, `claude-3-opus`, `claude-3-haiku` |
| `gemini` | Google Gemini | `ai_provider` | Ultra-fast multimodal reasoning & threat triage | `gemini-1.5-pro`, `gemini-1.5-flash`, `gemini-2.0-flash` |
| `openrouter` | OpenRouter | `ai_provider` | Unified gateway to 100+ open/proprietary LLMs | `anthropic/claude-3.5-sonnet`, `openai/gpt-4o`, `meta-llama/llama-3.1-70b` |
| `ollama` | Ollama (Local) | `ai_provider` | Completely private, offline, air-gapped LLM inference | `llama3`, `mistral`, `deepseek-coder`, `qwen2.5-coder` |

---

## 2. Threat Intelligence Providers (8 Providers)

| Provider ID | Display Name | Category | Primary Purpose | Auth Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| `virustotal` | VirusTotal | `threat_intel` | File, URL, domain, and hash threat reputation | `x-apikey` HTTP header |
| `shodan` | Shodan | `threat_intel` | Internet-exposed services, open ports, banners | API query parameter |
| `abuseipdb` | AbuseIPDB | `threat_intel` | IP address reputation and brute-force reports | `Key` HTTP header |
| `alienvault_otx` | AlienVault OTX | `threat_intel` | Community threat pulses, indicators of compromise | `X-OTX-API-KEY` header |
| `censys` | Censys Search | `threat_intel` | Attack surface mapping and certificate discovery | HTTP Basic Auth (`api_id` / `api_secret`) |
| `urlhaus` | URLhaus (abuse.ch) | `threat_intel` | Active malware distribution URL tracking | Public API / Optional `Auth-Key` |
| `cisa_kev` | CISA KEV Catalog | `threat_intel` | Known Exploited Vulnerabilities catalog feed | Public Feed / Direct HTTPS |
| `first_epss` | FIRST EPSS | `threat_intel` | Exploit Prediction Scoring System probabilities | Public API / Direct HTTPS |

---

## 3. SIEM & EDR Platforms (5 Providers)

| Provider ID | Display Name | Category | Primary Purpose | Auth Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| `crowdstrike` | CrowdStrike Falcon | `siem_edr` | Endpoint telemetry, host isolation, threat graph | OAuth2 Client Credentials (`client_id` + `client_secret`) |
| `elastic_security` | Elastic Security | `siem_edr` | SIEM alert ingestion, timeline search, detection rules | `ApiKey` authorization header |
| `ms_sentinel` | Microsoft Sentinel | `siem_edr` | Cloud-native SIEM/SOAR incident ingestion | Azure AD OAuth2 Bearer Token |
| `splunk` | Splunk Enterprise / Cloud | `siem_edr` | Enterprise log search, SPL query dispatch | `Splunk` authorization token |
| `wazuh` | Wazuh SIEM/XDR | `siem_edr` | Open-source host intrusion detection & agent alerts | Wazuh JWT Authentication (`/security/user/authenticate`) |

---

## 4. Vulnerability Management Systems (2 Providers)

| Provider ID | Display Name | Category | Primary Purpose | Auth Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| `defectdojo` | OWASP DefectDojo | `vulnerability_management` | Finding deduplication, engagement tracking, report sync | `Token` HTTP header |
| `tenable` | Tenable.io / Nessus | `vulnerability_management` | Nessus vulnerability scans & asset exposures | API keys (`accessKey` + `secretKey`) |

---

## 5. Cloud Infrastructure Security (3 Providers)

| Provider ID | Display Name | Category | Primary Purpose | Auth Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| `aws` | Amazon Web Services | `cloud` | GuardDuty, Security Hub, IAM privilege audit | AWS Access Key ID, Secret Key, Region |
| `gcp` | Google Cloud Platform | `cloud` | Security Command Center (SCC), IAM Recommender | Service Account Private JSON Key |
| `azure` | Microsoft Azure Cloud | `cloud` | Defender for Cloud, Advisor security posture | Tenant ID, Client ID, Client Secret |
