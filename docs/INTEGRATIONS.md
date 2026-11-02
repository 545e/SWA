# SWA AI — Security Platform & Threat Feed Integrations

## 1. Supported Integration Categories

SWA AI features native modular adapters for over 18 external platforms across four major domains:

```text
       ┌────────────────────────────────────────────────────────┐
       │                SWA AI Integration Hub                 │
       └──────────────────────────┬─────────────────────────────┘
                                  │
     ┌──────────────────┬─────────┴────────┬───────────────────┐
     │                  │                  │                   │
┌────▼──────┐      ┌────▼──────┐      ┌────▼──────┐      ┌─────▼──────┐
│  Threat   │      │  SIEM &   │      │   Cloud   │      │     AI     │
│  Intel    │      │    EDR    │      │ Providers │      │ Providers  │
└───────────┘      └───────────┘      └───────────┘      └────────────┘
 VirusTotal         Wazuh              AWS (STS/SecHub)   OpenAI
 AbuseIPDB          Splunk HEC         Azure Defender     Anthropic
 Shodan             Elastic SIEM       GCP Security Cmd   Google Gemini
 Censys             MS Sentinel                           OpenRouter
 AlienVault OTX     CrowdStrike Falcon                    Ollama Local
 URLhaus            DefectDojo & Tenable
```

---

## 2. Threat Intelligence Integrations

### VirusTotal v3
- **Role**: File hash reputation, malicious domain verdicts, URL telemetry.
- **Adapter**: `core/integrations/threat_intel.py:VirusTotalAdapter`
- **Setup**: Provide a VirusTotal v3 API key. Connection test probes `/api/v3/users/current`.

### AbuseIPDB
- **Role**: IP reputation scoring, attack categorization, abusive subnet identification.
- **Adapter**: `core/integrations/threat_intel.py:AbuseIPDBAdapter`
- **Setup**: Provide API Key. Probes `/api/v2/check` for endpoint health.

### Shodan
- **Role**: Internet device discovery, exposed port intelligence, service banner inspection.
- **Adapter**: `core/integrations/threat_intel.py:ShodanAdapter`
- **Setup**: Provide Shodan key. Probes `/api-info` and verifies query credit availability.

### Censys Search
- **Role**: Attack surface discovery and certificate transparency monitoring.
- **Adapter**: `core/integrations/threat_intel.py:CensysAdapter`
- **Setup**: Requires API ID and API Secret. Probes `/api/v1/account`.

### AlienVault OTX
- **Role**: Community threat indicator pulses and IOC enrichment.
- **Adapter**: `core/integrations/threat_intel.py:AlienVaultOTXAdapter`

### URLhaus
- **Role**: Malicious payload distribution URLs and malware feed ingestion.
- **Adapter**: `core/integrations/threat_intel.py:URLhausAdapter`

---

## 3. SIEM & Security Platforms

### Wazuh XDR / SIEM
- **Role**: Agent inventory retrieval, syscheck FIM alerts, rootcheck logs.
- **Adapter**: `core/integrations/security_platforms.py:WazuhAdapter`
- **Setup**: Requires manager URL (`https://host:55000`), API user, and password.

### Splunk Enterprise / Cloud
- **Role**: Ingestion of SWA audit logs and alerts via HTTP Event Collector (HEC).
- **Adapter**: `core/integrations/security_platforms.py:SplunkAdapter`

### Elastic Security
- **Role**: Detection Engine rule alerts and Elasticsearch threat indices.
- **Adapter**: `core/integrations/security_platforms.py:ElasticSecurityAdapter`

### Microsoft Sentinel
- **Role**: Log Analytics Workspace security events and Microsoft Defender for Cloud incidents.
- **Adapter**: `core/integrations/security_platforms.py:MicrosoftSentinelAdapter`

### CrowdStrike Falcon
- **Role**: Host isolation, active detections, and real-time Falcon telemetry.
- **Adapter**: `core/integrations/security_platforms.py:CrowdStrikeAdapter`

### OWASP DefectDojo
- **Role**: Vulnerability tracking, deduplication, and compliance engagement synchronization.
- **Adapter**: `core/integrations/security_platforms.py:DefectDojoAdapter`

---

## 4. Cloud Providers

### Amazon Web Services (AWS)
- **Role**: Security Hub findings, GuardDuty threat alerts, IAM policy auditing.
- **Adapter**: `core/integrations/cloud_providers.py:AWSAdapter`

### Microsoft Azure
- **Role**: Defender for Cloud recommendations and Entra ID IAM assessment.
- **Adapter**: `core/integrations/cloud_providers.py:AzureCloudAdapter`

### Google Cloud Platform (GCP)
- **Role**: Security Command Center (SCC) finding ingestion and Asset Inventory tracking.
- **Adapter**: `core/integrations/cloud_providers.py:GCPAdapter`
