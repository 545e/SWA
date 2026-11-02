# SWA AI — Autonomous Multi-Agent Workforce Guide

## 1. Multi-Agent System Architecture

SWA AI utilizes a decentralized, tiered multi-agent architecture where specialist agents collaborate to conduct reconnaissance, vulnerability hunting, exploit verification, and remediation orchestration.

All agents are centrally registered through `core/agent_registry.py` and exposed via `/api/agents`.

### Dynamic Registry & Operational Tiers

The 85 agents are organized into 5 functional tiers:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   Tier 1: Specialist Workforce (17)                   │
│   Supervisor, Reconnaissance, Attack Surface, Web Security, API, ...   │
├────────────────────────────────────────────────────────────────────────┤
│                   Tier 2: Offensive Reconnaissance (9)                 │
│      Subdomain Engine, DNS Enum, Port Scanner, TLS Inspector, ...      │
├────────────────────────────────────────────────────────────────────────┤
│                   Tier 3: OWASP Plugin Suite (10)                     │
│    SQLi, XSS, SSRF, Auth Bypass, IDOR, Command Injection, XXE, ...     │
├────────────────────────────────────────────────────────────────────────┤
│                   Tier 4: Core Cybersecurity Engines (32)              │
│      REA Reverse Engineering, Shannon Entropy, Knowledge Graph, ...    │
├────────────────────────────────────────────────────────────────────────┤
│                   Tier 5: External Tool Adapters (17)                  │
│       Nmap, Nuclei, Nikto, SQLmap, Amass, Gitleaks, DefectDojo, ...     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Agent Metadata Schema

Every agent manifest in the registry contains complete metadata:
- **`agent_id`**: Canonical identifier (e.g., `web_security`, `exploit_validator`).
- **`name`**: Human-readable agent name.
- **`tier`**: Operational tier (`specialist_workforce`, `offensive_recon`, `owasp_plugins`, `core_engines`, `tool_adapters`).
- **`category`**: Functional category (e.g., `Reconnaissance`, `Vulnerability Assessment`, `Exploit Verification`).
- **`capabilities`**: List of validated agent competencies.
- **`supported_tools`**: External or native tools invoked by the agent.
- **`input_schema`**: Required JSON parameters for task dispatch.
- **`output_schema`**: JSON structure returned by the agent upon task completion.
- **`permissions`**: Required access boundaries (e.g., `READ_TARGET_ASSETS`, `EXECUTE_SYNTHETIC_PROBES`).
- **`status`**: Live execution state (`IDLE`, `RUNNING`, `COMPLETED`, `FAILED`).

---

## 3. Human Approval Gates for Sensitive Actions

To prevent unauthorized offensive actions, agents cannot perform intrusive operations without human consent.

Sensitive actions (e.g., active exploit validation, credential stuffing tests, brute-force simulation) automatically generate an **Approval Request** in the Approval Gates queue (`/api/approvals`).

Operations remain paused in state `PENDING_APPROVAL` until a security engineer approves the request via the dashboard or REST API:

```http
POST /api/approvals/{request_id}/decide
Content-Type: application/json

{
    "decision": "APPROVED",
    "approver": "sec-lead@swa.ai",
    "rationale": "Authorized in pentest engagement scope document."
}
```

---

## 4. Dispatching Agent Tasks via REST API

You can dispatch tasks to any registered agent programmatically:

```bash
curl -X POST http://127.0.0.1:8000/api/agents/web_security/task \
  -H "Content-Type: application/json" \
  -d '{
    "task": "Analyze security headers and cookie flags for target",
    "context": {
      "target_url": "https://example.com",
      "scan_id": "scan_manual_01"
    }
  }'
```
