# SWA AI — False-Positive Management & Suppression Governance

## 1. Overview & Policy

False positives pollute reporting, degrade engineering trust, and obscure genuine attack paths. SWA AI implements a formal **False-Positive Review Workflow** (§5.3) requiring:
1. Senior analyst review rationale.
2. Contradictory replay evidence.
3. Immutable audit trail logging.
4. Segregated reporting (§10.4 False-Positive Review Report).

---

## 2. Review Classification Rules

- **`LIKELY_FALSE_POSITIVE`**: Candidate flagged by AI triage agents or automated heuristic replay where output did not produce expected vulnerability signature. Remains visible in triage view pending human analyst sign-off.
- **`FALSE_POSITIVE`**: Confirmed non-vulnerability reviewed and suppressed by a senior security engineer. Suppressed from open vulnerability totals, compliance score deductions, and executive action items.

---

## 3. Predefined Justifications

When submitting false positive reviews via `POST /api/findings/{id}/false-positive`:
1. `WAF / Defense-in-Depth blocks execution payload`: Upstream reverse proxy or WAF sanitized or rejected payload before reaching application code.
2. `Non-exploitable architectural configuration`: Feature is isolated, non-routable, or sandboxed.
3. `Synthetic test harness artifact only`: Symptom occurs exclusively within test instrumentation mock data.
4. `Third-party vendor library false alarm`: Known scanner pattern mismatch against third-party dependency.
5. `Custom senior analyst justification`: Unique architectural rationale documented in contradictory evidence.
