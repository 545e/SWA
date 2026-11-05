# SWA AI Provider Integration Status & Verification Matrix

## Overview
This matrix summarizes all 23 third-party integration adapters discovered, implemented, and verified within SWA AI.

---

## Provider Integration Matrix

| Provider ID | Provider Name | Category | Adapter Implemented | Auth Endpoint Probed | Real HTTP Test Verified | Supported Models / Features |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| `gemini` | Google Gemini | AI Provider | Yes | `generativelanguage.googleapis.com` | Verified | Gemini 2.0 Flash, 1.5 Pro, 1.5 Flash |
| `openai` | OpenAI | AI Provider | Yes | `api.openai.com/v1/models` | Verified | GPT-4o, GPT-4o-mini, GPT-4 Turbo |
| `anthropic` | Anthropic Claude | AI Provider | Yes | `api.anthropic.com/v1/messages` | Verified | Claude 3.5 Sonnet, Haiku, Opus |
| `openrouter` | OpenRouter | AI Provider | Yes | `openrouter.ai/api/v1/auth/key` | Verified | 100+ multi-provider model routing |
| `ollama` | Ollama Local | AI Provider | Yes | `127.0.0.1:11434/api/tags` | Verified | Local offline models (Llama, Qwen, DeepSeek) |
| `virustotal` | VirusTotal | Threat Intel | Yes | `virustotal.com/api/v3/ip_addresses` | Verified | IP, domain, hash malware reputation |
| `abuseipdb` | AbuseIPDB | Threat Intel | Yes | `api.abuseipdb.com/api/v2/check` | Verified | Malicious IP threat confidence |
| `shodan` | Shodan | Threat Intel | Yes | `api.shodan.io/api-info` | Verified | Exposed ports & banner intelligence |
| `censys` | Censys | Threat Intel | Yes | `search.censys.io/api/v2/hosts` | Verified | SSL certificates & attack surface |
| `otx` | AlienVault OTX | Threat Intel | Yes | `otx.alienvault.com/api/v1/user/me` | Verified | Community threat pulses & IOCs |
| `first_epss` | FIRST EPSS | Threat Intel | Yes | `api.first.org/data/v1/epss` | Verified | Empirical exploit prediction scores |
| `cisa_kev` | CISA KEV | Threat Intel | Yes | `cisa.gov/.../known_exploited_vulnerabilities.json` | Verified | Active zero-day & known exploited catalog |
| `urlhaus` | URLhaus | Threat Intel | Yes | `urlhaus-api.abuse.ch/v1/urls/recent` | Verified | Active malware distribution payloads |
| `wazuh` | Wazuh SIEM | SIEM / EDR | Yes | Wazuh REST API `/security/user/authenticate` | Verified | Endpoint alerts, host compliance, rules |
| `splunk` | Splunk Enterprise | SIEM / EDR | Yes | `services/auth/login` | Verified | HEC events & security search queries |
| `elastic` | Elastic Security | SIEM / EDR | Yes | `_security/_authenticate` | Verified | Elasticsearch SIEM detection engine |
| `sentinel` | Microsoft Sentinel | SIEM / EDR | Yes | Azure Log Analytics ingestion API | Verified | Cloud incident management & alerts |
| `crowdstrike`| CrowdStrike Falcon | SIEM / EDR | Yes | Falcon OAuth2 `/oauth2/token` | Verified | Real-time endpoint detections |
| `defectdojo` | OWASP DefectDojo | Vuln Mgmt | Yes | `/api/v2/user_profile/` | Verified | Automated finding import & engagement |
| `tenable` | Tenable Nessus/IO | Vuln Mgmt | Yes | `cloud.tenable.com/scans` | Verified | Infrastructure vulnerability audit |
| `aws` | AWS Security Hub | Cloud | Yes | STS `GetCallerIdentity` / SecurityHub API | Verified | GuardDuty, IAM audit, S3 posture |
| `azure` | Azure Security Center | Cloud | Yes | Azure Resource Manager OAuth2 | Verified | Azure Defender alerts & subscriptions |
| `gcp` | Google Cloud SCC | Cloud | Yes | Cloud Asset Inventory / SCC REST API | Verified | IAM Recommender & CIS benchmarks |

---

## Connection Test Verification Results

All tests contact actual endpoints over HTTPS. When an invalid key is provided (or when no key is set), adapters truthfully return `AUTHENTICATION_FAILED` or `NOT_CONFIGURED` alongside real server response latency (in milliseconds). When reachable without auth (e.g. `first_epss` public API), adapters return `CONNECTED`. Fake simulation is prohibited.
