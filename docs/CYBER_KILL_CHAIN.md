# SWA AI — Cyber Kill Chain Intelligence & Attack Lifecycle Analyzer
## Enterprise Defensive Threat Analysis & SOC Operations Documentation

### Executive Summary

The **Cyber Kill Chain Intelligence & Attack Lifecycle Analyzer** is an enterprise-grade defensive threat investigation and incident operations module integrated natively inside the SWA AI platform. Built upon the **Lockheed Martin Cyber Kill Chain** seven-stage framework and mapped comprehensively to **MITRE ATT&CK**, this module equips Security Operations Center (SOC) Level 2/3 analysts and security architects with end-to-end attack surface visibility, automated evidence correlation, risk quantification, threat intelligence enrichment, and defensive playbooks.

---

### 1. Architectural Architecture & Seven-Stage Engine

The platform implements all seven stages of the Lockheed Martin framework as autonomous, modular analyzers under `core/kill_chain/`:

```
core/kill_chain/
├── __init__.py                # Package exports and public interfaces
├── models.py                  # Pydantic schemas, Enums, dataclasses
├── db.py                      # SQLite database schema, indexes, CRUD transactions
├── engine.py                  # Central CyberKillChainEngine orchestrator
├── correlation.py             # Multi-stage ThreatCorrelationEngine
├── threat_intel.py            # ThreatIntelligenceEngine (VT, AbuseIPDB, CISA KEV, URLhaus)
├── ai_analyzer.py             # KillChainAIAnalyzer (7 SOC questions + deterministic fallback)
├── controls_matrix.py         # SecurityControlMatrix (7x5 matrix: Detect, Deny, Disrupt, Degrade, Deceive)
├── incident_manager.py        # IncidentManager & 7 Defensive Playbooks
├── reporter.py                # Enterprise Nessus-Style multi-format reporting engine
└── stages/
    ├── __init__.py            # Stage exports
    ├── base.py                # Abstract BaseStageAnalyzer, risk & confidence math
    ├── reconnaissance.py      # Stage 01 — Reconnaissance Analyzer
    ├── weaponization.py       # Stage 02 — Weaponization Analyzer (Defensive only)
    ├── delivery.py            # Stage 03 — Delivery Analyzer
    ├── exploitation.py        # Stage 04 — Exploitation Analyzer
    ├── installation.py        # Stage 05 — Installation & Persistence Analyzer
    ├── c2.py                  # Stage 06 — Command & Control (C2) Analyzer
    └── actions.py             # Stage 07 — Actions on Objectives Analyzer
```

---

### 2. The Seven Kill Chain Stages

#### Stage 01 — Reconnaissance (TA0043)
- **Objective:** Discover external attack surface exposure, information gathering, and adversary scanning.
- **Defensive Telemetry:**
  - Subdomain inventory via SWA Amass and Subdomain Engine.
  - DNS record analysis (A, MX, NS, TXT, SOA) and zone transfer detection.
  - Public IP and open port findings from SWA Port Scanner.
  - SSL/TLS certificate chain, expiration, and weak cipher analysis.
  - Technology stack fingerprinting and service banner exposure.

#### Stage 02 — Weaponization (TA0042)
- **Objective:** Identify intelligence associated with malicious payload preparation and weaponized artifacts.
- **Defensive Telemetry:**
  - Cryptographic file hash identification (SHA-256, MD5).
  - Static YARA signature and heuristic pattern matching via REA Engine.
  - Known malware family correlation (e.g. Carbanak, Cobalt Strike, Mirai).
  - Malicious Office document macro and script embedding inspection.
  - *Strict Rule:* Never creates malware or weaponized exploits; purely analyzes defensive artifacts.

#### Stage 03 — Delivery (TA0001)
- **Objective:** Analyze potential malicious content delivery mechanisms.
- **Defensive Telemetry:**
  - Phishing email and spoofed sender analysis (SPF, DKIM, DMARC verification).
  - Malicious URL detection and drive-by download vectoring.
  - Dangerous container attachment inspection (.iso, .lnk, .vbs, .hta, .zip).
  - Secure Web Gateway (SWG) and proxy log event ingestion.

#### Stage 04 — Exploitation (TA0002)
- **Objective:** Detect attempted or successful exploitation against software vulnerabilities and web endpoints.
- **Defensive Telemetry:**
  - SQL injection (SQLi, CWE-89), XSS (CWE-79), SSRF (CWE-918), and LFI/RFI (CWE-22).
  - CVE vulnerability correlation with **CISA Known Exploited Vulnerabilities (KEV)** catalog.
  - Web Application Firewall (WAF) rule violation alerts and payload capture.
  - HTTP 500 error analysis and stack trace leakage telemetry.

#### Stage 05 — Installation (TA0003)
- **Objective:** Detect adversary persistence mechanisms and unauthorized service creation.
- **Defensive Telemetry:**
  - Suspicious process spawning (e.g., cmd/powershell spawning from nginx/w3wp/node/python).
  - Unauthorized Windows Registry autoruns (Run/RunOnce, IFEO) and scheduled tasks (`schtasks`).
  - Linux systemd persistence services and crontab modifications.
  - File Integrity Monitoring (FIM) and system binary alteration.

#### Stage 06 — Command & Control (C2) (TA0011)
- **Objective:** Detect suspicious communication patterns, periodic heartbeats, and covert channels.
- **Defensive Telemetry:**
  - Network beaconing frequency, interval periodicity, and low-jitter flow detection.
  - DNS tunneling and high-entropy domain query inspection.
  - Suspicious outbound connections on non-standard ports (4444, 1337, 8443, 6667).
  - IP and domain reputation correlation.
  - *Strict Rule:* Strictly passive detection; no C2 servers or implants are deployed.

#### Stage 07 — Actions on Objectives (TA0040 / TA0010)
- **Objective:** Identify evidence of data exfiltration, ransomware, privilege escalation, and business disruption.
- **Defensive Telemetry:**
  - High-volume egress data transfers to untrusted external buckets or channels.
  - Ransomware encryption alerts (mass extension changes, Volume Shadow Copy deletion).
  - Lateral movement telemetry (SMB, WMI, WinRM, PsExec, SSH key reuse).
  - Privilege escalation (SYSTEM token impersonation, sudo abuse).

---

### 3. Risk and Confidence Scoring Methodologies

To maintain scientific integrity in security operations, **Risk** and **Confidence** are calculated completely independently:

#### Risk Score Calculation ($0.0 - 100.0$)
$$\text{Risk} = \min\left(100.0, \frac{\text{Impact} \times 10.0 \times \text{Likelihood} \times \text{AssetCriticality} \times \text{Exploitability} \times \text{Exposure}}{1.5}\right)$$
- **Impact Weight:** $1.0$ (Low) to $10.0$ (Critical)
- **Likelihood:** $0.1$ to $1.0$
- **Asset Criticality:** $0.5$ (Development) to $1.5$ (Production / Crown Jewels)
- **Exploitability:** $0.5$ (Theoretical) to $1.5$ (Active in wild / CISA KEV catalog)
- **Exposure:** $0.5$ (Internal isolated) to $1.5$ (Public internet perimeter)

#### Confidence Score Calculation ($0.0 - 100.0$)
$$\text{Confidence} = (\text{EvidenceQuality} \times 0.40) + (\text{SourceReliability} \times 0.30) + (\text{CorroborationFactor} \times 0.15) + (\text{Completeness} \times 0.15)$$
- **Confidence Levels:**
  - `CONFIRMED`: Score $\ge 85.0$
  - `SUSPECTED`: Score $65.0 - 84.9$
  - `INFERRED`: Score $40.0 - 64.9$
  - `UNKNOWN`: Score $< 40.0$
- *Security Rule:* AI confidence is never substituted for empirical binary/network proof.

---

### 4. AI-Powered SOC Analysis & Deterministic Fallback

The analyzer integrates directly with SWA AI's encrypted credential vault and model client (`SWALLMClient`). When queried, the system provides answers to the **7 mandatory SOC questions**:
1. **What happened?** (Detailed incident narrative)
2. **Which stage is involved?** (Kill Chain phase + MITRE ATT&CK tactic/technique)
3. **What evidence supports the finding?** (Direct artifact, hash, and detection source)
4. **Which assets are affected?** (Specific hosts, IPs, and endpoints)
5. **How confident is the assessment?** (Confirmed, Suspected, Inferred, Unknown, Not assessed)
6. **What is the potential impact?** (Operational and business consequences)
7. **What should the security analyst do next?** (Actionable immediate mitigation steps)

*Continuous Operations:* If no AI model or external API key is configured, the analyzer seamlessly transitions to its built-in **Deterministic Expert Heuristics Engine**, guaranteeing 100% operational uptime.

---

### 5. Security Control Coverage Matrix (7 x 5)

The platform evaluates defensive readiness by mapping all 7 stages against 5 core defensive capabilities:

| Stage | Detect | Deny | Disrupt | Degrade | Deceive |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **01 Recon** | EASM / Port Scanner | Firewall ACLs | DNS Rate Limiting | Service Banner Masking | HoneyPort Decoy |
| **02 Weapon** | YARA Static Scanner | AppLocker / App Control | Binary Emulation Sandbox | PowerShell Constrained Language | Threat Infrastructure Canary |
| **03 Delivery**| Email Phish Guard | SPF/DKIM/DMARC Reject | SWG Attachment Stripping | Remote Browser Isolation (RBI) | SpamTrap Inboxes |
| **04 Exploit** | OWASP Hunter / Vuln Scanner| Web Application Firewall | RASP Active Intercept | ASLR & Stack Protections | Canary HoneyTokens |
| **05 Install** | EDR Process Lineage | Driver Signing / WHQL | Process Kill Engine | Registry Autorun Quarantine | Canary Registry Keys |
| **06 C2**      | NetFlow & Jitter Profiler | DNS Sinkhole (RPZ) | Egress TLS Reset | Bandwidth QoS Shaper | Fake C2 Sinkhole Listener |
| **07 Actions** | Data Loss Prevention (DLP)| Privileged Access (PAM) | Ransomware Mass-Kill | Air-Gapped Immutable Backups | HoneyData Traps |

Coverage percentages are calculated strictly from verified, configured controls, highlighting identified gaps and investment recommendations.

---

### 6. Incident Management & Stage Playbooks

Incidents advance through formal SOC lifecycle stages:
`NEW` $\rightarrow$ `INVESTIGATING` $\rightarrow$ `CONFIRMED` $\rightarrow$ `CONTAINMENT_RECOMMENDED` $\rightarrow$ `CONTAINED` $\rightarrow$ `REMEDIATED` $\rightarrow$ `CLOSED`.

Each stage includes a step-by-step response playbook:
- **Reconnaissance Playbook:** Verify target boundary, apply perimeter firewall blocks, disable AXFR transfers, strip server banners, deploy honeypot ports.
- **Weaponization Playbook:** Compute SHA-256 digests, query threat intel, run YARA triage, deploy perimeter block rules, quarantine staging storage.
- **Delivery Playbook:** Message search & purge, block domain/IPs, sinkhole URLs, force credential resets, quarantine dangerous file attachments.
- **Exploitation Playbook:** Deploy WAF virtual patches, verify CISA KEV priority, isolate web worker processes, rotate secrets, enforce parameterized queries.
- **Installation Playbook:** Emergency host network isolation, force kill rogue processes, delete autorun keys/services, audit user accounts, restore golden image.
- **C2 Playbook:** Terminate outbound sockets, sinkhole C2 domains, capture RAM memory dump, filter high-entropy DNS, correlate lateral flows.
- **Actions Playbook:** Sever external egress bandwidth, freeze file shares, verify air-gapped backups, double-reset Kerberos krbtgt, engage incident counsel.

---

### 7. Professional Nessus-Style Deliverables

Reports can be generated on-demand and exported in **5 standard formats**:
- **HTML:** Standalone enterprise dashboard with dark theme, severity badges, and code blocks.
- **PDF:** Native formatted document via ReportLab with executive summary tables and top findings.
- **JSON:** Machine-readable compliance payload for SIEM/SOAR ingestion.
- **CSV:** Tabular findings inventory with CVE, CWE, CVSS, risk scores, and remediation steps.
- **Markdown:** Clean documentation format for GitHub, Jira, and internal wikis.

---

### 8. API Reference Summary

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/kill-chain/health` | Service health status probe |
| `GET` | `/api/kill-chain/overview` | High-level metrics across all 7 stages |
| `GET` | `/api/kill-chain/stages` | Seven-stage summaries and statuses |
| `GET` | `/api/kill-chain/stages/{stage_id}` | Detailed telemetry, findings, and playbooks |
| `POST`| `/api/kill-chain/analyze` | Ingests telemetry and runs all 7 stage analyzers |
| `GET` | `/api/kill-chain/findings` | Lists verified findings with risk/confidence filters |
| `GET` | `/api/kill-chain/findings/{id}` | Single finding inspection |
| `POST`| `/api/kill-chain/correlate` | Executes central threat correlation engine |
| `GET` | `/api/kill-chain/evidence` | Forensic evidence repository |
| `POST`| `/api/kill-chain/evidence` | Ingests raw evidence artifact with SHA-256 digest |
| `GET` | `/api/kill-chain/intelligence` | Threat intel provider health and indicators |
| `POST`| `/api/kill-chain/intelligence/lookup` | Real-time IOC lookup (IP, Domain, CVE, Hash) |
| `GET` | `/api/kill-chain/controls` | 7x5 security control coverage matrix |
| `GET` | `/api/kill-chain/timeline` | UTC chronological event progression |
| `POST`| `/api/kill-chain/ai/analyze` | AI analysis addressing the 7 SOC questions |
| `POST`| `/api/kill-chain/response/recommend` | Defensive response playbook for given stage |
| `GET` | `/api/kill-chain/incidents` | Lists tracked SOC incidents |
| `POST`| `/api/kill-chain/incidents` | Creates new incident case |
| `PATCH`| `/api/kill-chain/incidents/{id}` | Updates incident status and audit notes |
| `GET` | `/api/kill-chain/reports` | Lists generated assessment reports |
| `POST`| `/api/kill-chain/reports/generate` | Generates deliverables (PDF, HTML, JSON, CSV, MD) |
| `GET` | `/api/kill-chain/reports/{id}/download` | Downloads specific deliverable file |
| `POST`| `/api/kill-chain/seed-demo` | Seeds authentic 7-stage multi-stage scenario |
