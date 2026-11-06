# MULTI-AGENT WORKFLOWS & THREAT ORCHESTRATION
## End-to-End Task Delegation, Context Passing, and Kill Chain Correlation

### 1. The Standard Security Assessment Workflow

```text
[Step 1: Scoped Reconnaissance]
  AssetDiscoveryAgent ──► Subdomain & DNS enumeration
          │
          ▼
[Step 2: Service & Perimeter Probing]
  PortScannerAgent & WebCrawlerAgent ──► Open ports, endpoints, technologies
          │
          ▼
[Step 3: Multi-Vector Vulnerability Analysis]
  VulnHunterAgent & OWASP Agents ──► Injection, auth, and configuration checks
          │
          ▼
[Step 4: Non-Destructive Exploit Validation]
  ExploitValidatorAgent ──► Generates minimal cURL reproduction PoC
          │
          ▼
[Step 5: Threat Correlation & Risk Analysis]
  IncidentCorrelatorAgent ──► Maps findings into 7-stage Cyber Kill Chain
  RiskAnalyzerAgent       ──► Calculates contextual CVSS v3.1 score
          │
          ▼
[Step 6: Defensive Remediation Planning]
  RemediationPlannerAgent ──► Synthesizes code fixes and WAF blocking rules
          │
          ▼
[Step 7: Reporting & Export]
  ReportGeneratorAgent    ──► Compiles executive PDF, HTML, SARIF, and Nessus XML
```

---

### 2. Guardrails Against Runaway Execution
- **Infinite Loop Prevention**: Task delegation depth is bounded to a maximum of 5 recursive handoffs.
- **Human Approval Gates**: High-impact operations (e.g. active exploitation or destructive probes) transition agent state to `WAITING_FOR_APPROVAL` until approved via the Approval Gates UI.
- **Unified Context Object**: Each agent receives a validated `ScanJob` and passes structured `VulnerabilityFinding` instances to downstream workers.
