# SWA AI — Repository Inventory

## 1. Primary Repository

- **Repository Name**: SWA (Security Workflow Automation / Autonomous Enterprise Cybersecurity Platform)
- **Repository URL**: `https://github.com/545e/SWA.git`
- **Status**: `INTEGRATED`
- **Branches Analyzed**:
  - `main` (commit `3ee8c90` on origin)
  - `generation-2-complete-modernization` (commit `211c60f` on origin)
- **Local Active Branch**: `generation-2-work` (integrating modernization branch with preserved uncommitted changes and database history)
- **Description**: SWA AI is a full-featured, autonomous cybersecurity operating system and SOC operations platform featuring multi-agent AI workforces, automated vulnerability hunting, asset discovery, attack surface correlation, remediation orchestration, OWASP checks, reverse engineering (REA) analysis, and enterprise compliance reporting.

## 2. Discovered External & Tool Repositories

The following repositories were discovered through code references, tool integrations, and dependencies:

| Repository Name | Repository URL | Status | Category | Integration Method |
|---|---|---|---|---|
| REA Engine | `https://github.com/morluto/rea` | `INTEGRATED` | Reverse Engineering | Native Fallback + CLI / Python Engine (`core/rea_engine.py`) |
| ProjectDiscovery Nuclei | `https://github.com/projectdiscovery/nuclei` | `INTEGRATED` | Vulnerability Scanning | Subprocess / CLI Adapter with Scope Validation (`core/scanner_integrations.py`) |
| SQLMap | `https://github.com/sqlmapproject/sqlmap` | `INTEGRATED` | SQL Injection Assessment | Core SQLLi Module + CLI Integration Adapter (`core/sqli_engine.py`) |
| Sullo Nikto | `https://github.com/sullo/nikto` | `INTEGRATED` | Web Vulnerability Scanner | Adapter (`core/scanner_integrations.py`) with Scoped Fallback |
| Gitleaks | `https://github.com/gitleaks/gitleaks` | `INTEGRATED` | Secret & Token Detection | Pattern Regex Engine + Shannon Entropy Scanner (`core/js_intelligence.py`) |

## 3. Discovered Local Workspace States

| Workspace Path | Head Commit / State | Status | Role in Integration |
|---|---|---|---|
| `C:\Users\krish\.gemini\antigravity\scratch\swa` | `origin/generation-2-complete-modernization` (`211c60f`) | `INTEGRATED` | Primary workspace containing 85-agent registry, cross-platform scripts, security suites |
| `C:\Users\krish\.gemini\antigravity\scratch\swa-ai` | `c63d55e` + uncommitted changes (Oct 31, 2026) | `INTEGRATED` | Historical workspace containing recovered modules (`core/audit.py`, `core/scoring.py`, `core/version.py`, `deploy/`, 60 scans DB) |
| `_backups_checkpoint_20261102` | Snapshot of `swa` and `swa-ai` | `CHECKPOINT` | Complete immutable preservation backup created before any modifications |

## 4. Discovered Provider Repositories & API Targets

- **OpenAI API**: `https://api.openai.com/v1` (`core/llm_client.py`, `core/integrations/`)
- **Anthropic API**: `https://api.anthropic.com/v1` (`core/llm_client.py`, `core/integrations/`)
- **Google Gemini API**: `https://generativelanguage.googleapis.com/v1beta` (`core/llm_client.py`, `core/integrations/`)
- **OpenRouter API**: `https://openrouter.ai/api/v1` (`core/llm_client.py`, `core/integrations/`)
- **VirusTotal API**: `https://www.virustotal.com/api/v3` (`core/integrations/threat_intel.py`)
- **AbuseIPDB API**: `https://api.abuseipdb.com/api/v2` (`core/integrations/threat_intel.py`)
- **Shodan API**: `https://api.shodan.io` (`core/integrations/threat_intel.py`)
- **Censys API**: `https://search.censys.io/api` (`core/integrations/threat_intel.py`)
- **AlienVault OTX**: `https://otx.alienvault.com/api/v1` (`core/integrations/threat_intel.py`)
- **URLhaus API**: `https://urlhaus-api.abuse.ch/v1` (`core/integrations/threat_intel.py`)
- **Wazuh / Splunk / Elastic / Sentinel**: Security SIEM/EDR Adapters (`core/integrations/siem_edr.py`)
