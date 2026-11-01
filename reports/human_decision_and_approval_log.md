# SWA AI — Human Decision & Authorization Audit Log

**Document Version:** 2.2.0-Enterprise  
**Effective Date:** 2026-11-01  
**Audit Scope:** Human-in-the-Loop Governance & Administrative Decisions

---

## 1. Approval Register & Policy Mandates

In strict compliance with the **Human-in-the-Loop Operating Model**, AI agents are prohibited from autonomously executing aggressive, intrusive, or production-impacting operations without explicit human authorization.

The following operations require mandatory sign-off:
1. `AGGRESSIVE_SCANNING`: High-concurrency path or parameter fuzzing.
2. `EXPLOIT_VALIDATION`: Active PoC exploit verification against non-lab targets.
3. `DESTRUCTIVE_TESTING`: Payloads altering target state or service availability.
4. `PRODUCTION_CHANGE`: Applying remediation code directly to live environments.
5. `RISK_ACCEPTANCE`: Suppressing or accepting business risk for critical vulnerabilities.
6. `SCOPE_EXPANSION`: Adding domains/IPs outside the initial authorization allowlist.

---

## 2. Audited Approval Decisions

| Approval ID | Timestamp | Action Type | Target | Requesting Agent | Impact Assessment | Human Operator | Decision | Operator Rationale |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **appr_e1bd56ef** | 2026-11-01T01:45:37Z | `AGGRESSIVE_SCANNING` | `127.0.0.1:8000` | SWA AI Orchestrator | Target server resource load increase; possible rate-limit trigger | CISO / Lead Architect | **APPROVED** | Target is authorized local lab environment. Approved with 10 concurrency limit. |
| **appr_7f39a012** | 2026-11-01T01:46:12Z | `SCOPE_EXPANSION` | `api.internal.corp` | Reconnaissance Agent | Perimeter discovery of new internal service | Security Operations Lead | **REJECTED** | Asset is currently outside authorized testing window; reschedule for maintenance period. |
| **appr_9c82b415** | 2026-11-01T01:48:05Z | `HIGH_IMPACT_REMEDIATION` | `127.0.0.1:8000` | Remediation Agent | Nginx server header configuration reload | Lead DevSecOps Eng | **APPROVED** | Configuration change verified in staging; safe reload approved. |

---

## 3. Cryptographic & Audit Trail Protection
All approval decisions are persisted in the SQLite `approval_requests` table and mirrored to `cyber_audit_logs` with timestamps, actor IDs, IP addresses, and decision reasons.
