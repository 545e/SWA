# SWA AI — Generation 3 Security Model

## 1. Threat Landscape & Boundaries

SWA AI is designed to test security defenses while operating under strict application security guardrails:

```
[ External User / Auditor ] 
       │
       ▼
 [ Security Headers & Rate Limiter ]
       │
       ▼
 [ Role-Based Access Control (RBAC) ]
       │
       ▼
 [ Scope Policy & SSRF Gate ] ── (Blocks Private IPs & Cloud Metadata)
       │
       ▼
 [ Scanner Integrations & Subprocess Sandboxing ]
       │
       ▼
 [ Evidence Redaction Engine ]
       │
       ▼
 [ SQLite WAL Database ]
```

---

## 2. Security Controls

### 2.1 Scope Enforcement & SSRF Protection
- All targets are validated against IP address filters in `core/scope_policy.py`.
- Blocks loopback (`127.0.0.0/8`, `::1`), RFC1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local addresses, and cloud metadata endpoints (`169.254.169.254`) unless explicit lab authorization flag is set.

### 2.2 Token-Bucket Rate Limiting
- Prevents resource exhaustion from automated scraping.
- Enforces burst and sustained request thresholds per client IP.
- Exempts internal crawler loopback addresses (`127.0.0.1`, `::1`, `localhost`) to prevent self-throttling during local scans.

### 2.3 Evidence Redaction
- Strips authorization bearer tokens, basic auth credentials, passwords, cookies, and API keys before storing findings or rendering reports.

### 2.4 Prompt Injection Delimiters
- Enforces strict semantic delimiters `<untrusted_target_evidence_boundary>` around raw target responses to neutralize prompt injection attacks targeting LLM agents.
