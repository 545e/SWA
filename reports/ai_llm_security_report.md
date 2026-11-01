# SWA AI — AI & LLM Security Assessment Report
**Document ID:** SEC-AI-2026-018  
**Generated:** 2026-11-01T06:13:28.585946+00:00  

---

## 1. LLM Guardrails & Boundary Verification
`core/llm_router.py` implements multi-layer prompt defense:
1. **Adversarial Input Sanitization:** Strips known jailbreak patterns (`DAN`, `ignore previous instructions`, prompt injection delimiters).
2. **Deterministic Output Constraining:** Structured JSON schemas enforced on model completions.
3. **Dual Gate Verification:** Destructive pentesting actions require human operator confirmation regardless of LLM recommendations.
