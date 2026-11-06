# AI SECURITY, GOVERNANCE & RED-TEAMING
## Guardrails Against Adversarial LLM Threats, Jailbreaks, and Data Leakage

The platform enforces strict AI security controls in compliance with the OWASP Top 10 for Large Language Model Applications:

### 1. 12-Vector LLM Adversarial Test Coverage

Tested and verified via `core/llm_security_testing.py` and accessible in the UI at `viewAiLab`:

1. **LLM-01: Direct Prompt Injection**:
   - Defended via delimiter escape isolation and system instruction precedence enforcement.
2. **LLM-02: Indirect Prompt Injection**:
   - Sanitizes third-party retrieved documents prior to LLM context assembly.
3. **LLM-03: System Prompt Extraction**:
   - System prompts forbid verbatim quotation of internal operating instructions or canary tokens.
4. **LLM-04: Jailbreak & Roleplay Evasion**:
   - Rejects "DAN", fictional persona, or anti-restriction roleplay attempts.
5. **LLM-05: Sensitive Data Disclosure**:
   - Prevents exfiltration of private canary tokens and synthetic secrets.
6. **LLM-06: Insecure Output Handling**:
   - Enforces HTML entity escaping to prevent model-generated XSS payloads in web renderers.
7. **LLM-07: Excessive Agency & Tool Invocation**:
   - Destructive operating system commands (`rm -rf`, `del /f`) require human-in-the-loop approval.
8. **LLM-08: RAG Poisoning & Retrieval Manipulation**:
   - Enforces threshold relevancy, document validation, and source citation verification.
9. **LLM-09: Training Data Leakage**:
   - Forbids memorized proprietary PII or database credential disclosures.
10. **LLM-10: Unsafe Tool Permissions**:
    - Disallows unauthorized permission flags (`force_admin_grant=true`) passed in tool arguments.
11. **LLM-11: Denial of Service & Token Flooding**:
    - Enforces hard token limits (`max_tokens`) and request timeouts.
12. **LLM-12: Multi-Tenant Cross-Contamination**:
    - Segregates session context and knowledge bases by `project_id`.

---

### 2. Zero-Trust Tool Calling Protocol
- Models are **never** given direct shell execution capabilities.
- Tools only accept typed, validated schemas defined in `core/tool_registry.py`.
- Outputs from tools are treated as untrusted strings and sanitized before client display.
