# SWA AI — Complete Cybersecurity Tool Inventory
**Document ID:** SEC-INV-2026-001  
**Generated:** 2026-11-01T06:13:28.585946+00:00  
**Classification:** Enterprise Security Operational Record  
**Platform Version:** 2.2.0-Enterprise  

---

## 1. Executive Summary
This report inventories the complete cyber tool ecosystem across the SWA AI Autonomous Cybersecurity Operating System, covering both native internal Python security engines and external third-party security CLI integrations.

## 2. 12-Domain Capability Inventory

| Domain | Capability / Tool | Engine Type | Execution Mode | Integration Path | Status |
|:---|:---|:---|:---|:---|:---|
| **A: Reconnaissance** | Amass Subdomain Discovery | Native Async Prober | Active/Passive | `agents/amass_engine.py` | OPERATIONAL |
| **A: Reconnaissance** | DNS / SPF / DMARC Auditing | Native Resolver | Active DNS | `core/cyber_tools.py` | OPERATIONAL |
| **A: Reconnaissance** | Port / Service Scanner | Native Async Sockets | Active SYN/Connect | `core/scanner.py` | OPERATIONAL |
| **B: Network Security** | Subnet & CIDR Calculator | Native Bitmask Engine | Local Calculation | `core/cyber_tools.py` | OPERATIONAL |
| **B: Network Security** | TLS/SSL Cipher & Cert Auditor | Native OpenSSL / Sockets | Active Handshake | `core/cyber_tools.py` | OPERATIONAL |
| **B: Network Security** | Nmap Network Prober | External Subprocess | Subprocess CLI | `core/scanner_integrations.py` | CLI ADAPTER READY |
| **C: Web Security** | OWASP Top 10 Active Prober | Native HTTP Async | Active Probe | `plugins/owasp_plugins.py` | OPERATIONAL |
| **C: Web Security** | HTTP Security Headers Auditor | Native Header Evaluator | Active HTTP | `core/cyber_tools.py` | OPERATIONAL |
| **C: Web Security** | OWASP ZAP Baseline Scanner | External Subprocess | Headless / Daemon | `core/scanner_integrations.py` | CLI ADAPTER READY |
| **D: API Security** | REST / OpenAPI Endpoint Auditor | Native Schema Analyzer | Dynamic Active | `core/scanner.py` | OPERATIONAL |
| **D: API Security** | Broken Authentication Prober | Native Token Analyzer | Dynamic Auth | `plugins/owasp_plugins.py` | OPERATIONAL |
| **E: Vulnerability Mgmt** | Unified CVE Correlator | Native Hybrid DB | Local Match & Score | `core/scanner.py` | OPERATIONAL |
| **E: Vulnerability Mgmt** | Nuclei Template Runner | External Subprocess | Subprocess CLI | `core/scanner_integrations.py` | CLI ADAPTER READY |
| **F: Source Code / SAST** | GhostJS Client Secret Miner | Native AST Regex Miner | Static Analysis | `core/js_intelligence.py` | OPERATIONAL |
| **F: Source Code / SAST** | Dependency Confusion Auditor | Native Package Auditor | Dependency AST | `core/js_intelligence.py` | OPERATIONAL |
| **F: Source Code / SAST** | Bandit Python SAST | External Subprocess | AST Python Scanner | `core/scanner_integrations.py` | CLI ADAPTER READY |
| **G: Cloud & Infra** | Trivy Container & Cloud Scanner | External Subprocess | Subprocess CLI | `core/scanner_integrations.py` | CLI ADAPTER READY |
| **H: Threat Intelligence** | MITRE ATT&CK Mapping Engine | Native Matrix Correlator | Memory / DB Matrix | `core/forensics_engine.py` | OPERATIONAL |
| **I: DFIR & Incident Resp** | Digital Forensics Log Analyzer | Native Regex / Pattern Parser | File / Stream Parser | `core/forensics_engine.py` | OPERATIONAL |
| **I: DFIR & Incident Resp** | Threat Hunting Query Generator | Native PowerShell & Grep Gen | Target Platform Query | `core/forensics_engine.py` | OPERATIONAL |
| **J: Binary & File Analysis** | REA Binary & Artifact Disassembler | Native PE/ELF/Mach-O Inspector | Static Binary Parser | `core/rea_engine.py` | OPERATIONAL |
| **K: Security Config & WAF** | Blue Team Virtual Patcher | Native Rule Generator | ModSec/Cloudflare/AWS | `core/blue_team_engine.py` | OPERATIONAL |
| **L: AI & LLM Security** | Prompt Injection & Jailbreak Prober | Native LLM Boundary Fuzzer | Adversarial Prompting | `core/llm_router.py` | OPERATIONAL |

## 3. Tool Health Verification Architecture
The `/api/health/diagnostics` endpoint provides automated continuous telemetry on all registered tools. External third-party CLI tools adhere to strict sandbox execution with path traversal prevention, timeout bounding (default 120s), and memory caps.
