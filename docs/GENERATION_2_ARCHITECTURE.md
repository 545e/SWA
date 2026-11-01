# SWA AI — Generation 2 & 3 System Architecture Specification
**Platform:** Autonomous Enterprise Cybersecurity Operating System  
**Repository:** https://github.com/545e/SWA.git  
**Version:** 3.0.0-Enterprise  

---

## 1. System Topology & Architectural Principles

SWA AI is designed as a decoupled, multi-tier autonomous cybersecurity platform:

```
[ Frontend: Vanilla ES6+ SPA ]
             │
      REST / SSE JSON
             ▼
[ FastAPI Gateway & Server: web/server.py ]
   ├── Authentication & Rate Limiting
   ├── Target Scope Governance (core/scope_policy.py)
   └── Route Dispatchers (API, Scans, Tools, Agents)
             │
   ┌─────────┴────────────────────────┐
   ▼                                  ▼
[ Autonomous Agent Workforce ]   [ Integrated Security Toolkit ]
  17 Specialist Roles:             Amass, GhostJS AST, PortScan,
  Recon, Hunter, BlueTeam,         OWASP Top 10, REA Engine,
  DFIR, Remediation, etc.          WAF Analyzer, SSL Auditor
   │                                  │
   └─────────┬────────────────────────┘
             ▼
[ Persistence & State: core/database.py (SQLite) ]
   Assessments • Vulnerabilities • Assets • Audit Logs
```

### Architectural Principles:
1. **Single Unified Dashboard:** One primary dashboard route (`/`) with seamless hash-routed views. Zero competing interfaces.
2. **Zero False-Positive Engine:** Active probes strictly filter out HTTP 403 Forbidden access-denied responses and dead routes.
3. **Safety by Default:** Out-of-the-box scope policy blocks RFC-1918 private IPs and cloud metadata IP (`169.254.169.254`).
4. **Deterministic Audits:** Every critical vulnerability finding requires reproducible proof-of-concept cURL commands and verified server response evidence.

---

## 2. Component Directory Map

- `agents/`: Autonomous specialist agent implementations with permission boundaries.
- `config/`: Enterprise environment variables and default profiles.
- `core/`: Database engine, models, scanner integrations, scope policy, AI training, and REA disassembler.
- `docs/`: Technical manuals, installation guides, baseline audits, and API references.
- `plugins/`: OWASP Top 10 automated fuzzers and probers.
- `reports/`: Multi-format deliverable generators (SARIF 2.1.0, CSV, HTML, PDF, Markdown).
- `tests/`: 110 automated tests.
- `web/`: FastAPI server, enterprise routes, and modernized frontend assets.
