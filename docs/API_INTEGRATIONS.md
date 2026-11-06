# SWA AI — Third-Party API Integrations Hub

## 1. Supported Integration Ecosystem (23 Providers)
SWA AI natively interfaces with 23 premier cybersecurity, cloud, and artificial intelligence providers across 5 distinct categories.

### Category Breakdown
1. **AI LLM Providers (5)**:
   - OpenAI (`openai`) — GPT-4o, o1, o3-mini
   - Anthropic (`anthropic`) — Claude 3.5 Sonnet, Claude 3.7
   - Google Gemini (`gemini`) — Gemini 2.0 Flash, Gemini 1.5 Pro
   - OpenRouter (`openrouter`) — Unified multi-model gateway
   - Ollama (`ollama`) — Local self-hosted LLMs (DeepSeek-R1, Llama 3.3)

2. **Threat Intelligence Feeds (8)**:
   - VirusTotal (`virustotal`) — Multi-engine file, IP & URL analysis
   - AbuseIPDB (`abuseipdb`) — IP reputation & abuse reporting
   - Shodan (`shodan`) — Internet-connected device intelligence
   - Censys (`censys`) — Attack surface & certificate enumeration
   - AlienVault OTX (`alienvault_otx`) — Open threat exchange community pulses
   - URLhaus (`urlhaus`) — Malware distribution site tracking
   - CISA KEV (`cisa_kev`) — US CISA Known Exploited Vulnerabilities catalog
   - FIRST EPSS (`first_epss`) — FIRST.org Exploit Prediction Scoring System

3. **SIEM & EDR Platforms (5)**:
   - Wazuh (`wazuh`) — Open source SIEM & XDR
   - Splunk (`splunk`) — Enterprise security event forwarding
   - Elastic Security (`elastic_security`) — Elasticsearch SIEM detection engine
   - Microsoft Sentinel (`ms_sentinel`) — Azure cloud SIEM
   - CrowdStrike Falcon (`crowdstrike`) — Endpoint detection and containment

4. **Vulnerability Management Platforms (2)**:
   - DefectDojo (`defectdojo`) — Open source vulnerability correlation
   - Tenable Nessus / Tenable.io (`tenable`) — Enterprise vulnerability management

5. **Cloud Security Providers (3)**:
   - AWS (`aws`) — IAM, GuardDuty, Security Hub
   - Azure (`azure`) — Microsoft Defender for Cloud
   - GCP (`gcp`) — Security Command Center

---

## 2. Managing Integrations via API

### Listing Supported Providers
```http
GET /api/v1/integrations/providers
```

### Saving Credentials (Encrypted)
```http
POST /api/v1/integrations
Content-Type: application/json

{
  "provider_id": "virustotal",
  "credentials": {
    "api_key": "vt_api_key_here..."
  },
  "enabled": true
}
```

### Live Connection Testing
```http
POST /api/v1/integrations/test
Content-Type: application/json

{
  "provider_id": "cisa_kev"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "success": true,
    "status": "CONNECTED",
    "message": "CISA KEV catalog is reachable and operational.",
    "latency_ms": 142
  }
}
```
