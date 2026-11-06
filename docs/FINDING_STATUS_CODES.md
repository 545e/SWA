# SWA AI — Finding Status Codes Standard

## 1. Specification & Scope

SWA AI defines **13 standardized finding lifecycle status codes** (§3.1) and **8 remediation status codes** (§3.3). Each status represents an unambiguous stage in vulnerability verification, engineering remediation, and closure.

HTTP response codes (such as `200`, `404`, `500`) are strictly transport protocol signals and must NEVER be conflated with vulnerability finding statuses.

---

## 2. Catalog of 13 Finding Lifecycle Status Codes

| Code | Label | Color | Background | Description | Entry Criteria | Exit Criteria |
|---|---|---|---|---|---|---|
| `NEW` | New | `#3B82F6` (Blue) | `rgba(59,130,246,0.15)` | Finding ingested from automated scanner or telemetry feed | Initial scanner discovery | Triaged by analyst or dispatched to AI agent |
| `NEEDS_VALIDATION` | Needs Validation | `#F59E0B` (Amber) | `rgba(245,158,11,0.15)` | Potential issue flagged by scanner with low confidence | Scanner heuristics match without PoC execution | Analyst or AI replay agent validates exploitability |
| `IN_PROGRESS` | In Progress | `#06B6D4` (Cyan) | `rgba(6,182,212,0.15)` | Under active investigation or replay verification | Analyst assigned to investigate | Validation complete; transitioned to Confirmed or FP |
| `CONFIRMED` | Confirmed | `#6366F1` (Indigo) | `rgba(99,102,241,0.15)` | Validated vulnerability with proven exploitability | PoC command succeeds or signature matches | Ticket assigned to engineering for remediation |
| `LIKELY_FALSE_POSITIVE` | Likely False Positive | `#F97316` (Orange) | `rgba(249,115,22,0.15)` | Suspected false detection flagged for senior review | Contradictory behavior observed during replay | Reviewed by Senior Analyst with formal sign-off |
| `FALSE_POSITIVE` | False Positive | `#64748B` (Slate) | `rgba(100,116,139,0.15)` | Formally verified as false alarm and suppressed | Senior analyst provides contradictory evidence | Reopened if architecture or code changes |
| `DUPLICATE` | Duplicate | `#94A3B8` (Slate Light) | `rgba(148,163,184,0.12)` | Duplicate detection of an existing tracked finding | Same root cause and endpoint already tracked | Merged into primary finding |
| `ACCEPTED_RISK` | Accepted Risk | `#A855F7` (Purple) | `rgba(168,85,247,0.15)` | Business or technical decision to accept risk | Executive sign-off and compensating controls | Periodic risk review or retest |
| `FIX_IN_PROGRESS` | Fix In Progress | `#0EA5E9` (Sky Blue) | `rgba(14,165,233,0.15)` | Engineering team developing software mitigation | Development ticket created and assigned | Code commit submitted for retest |
| `FIXED_PENDING_RETEST` | Fixed – Pending Retest | `#8B5CF6` (Violet) | `rgba(139,92,246,0.15)` | Remediation deployed to target environment | Pull request merged or deployment complete | Retest scan executed by autonomous engine |
| `RESOLVED_VERIFIED` | Resolved – Verified | `#22C55E` (Emerald) | `rgba(34,197,94,0.15)` | Retest confirmed finding is no longer reproducible | Replay cURL returns non-exploitable response | Vulnerability permanently closed |
| `REOPENED` | Reopened | `#EF4444` (Red) | `rgba(239,68,68,0.15)` | Finding reappeared during regression retest | Retest executes PoC and receives exploit response | Engineering notified to patch regression |
| `INCONCLUSIVE` | Inconclusive | `#A1A1AA` (Zinc) | `rgba(161,161,170,0.12)` | Reproduction attempt timed out or target unreachable | Target rate-limited, timed out, or offline | Retest when target availability is restored |

---

## 3. Catalog of 8 Remediation Status Codes

Remediation status operates independently from lifecycle status to track engineering workflows:

1. `OPEN`: Newly discovered or unaddressed finding.
2. `ASSIGNED`: Allocated to engineering team or developer.
3. `IN_PROGRESS`: Mitigation code actively under development.
4. `FIX_SUBMITTED`: Pull request or patch submitted.
5. `PENDING_RETEST`: Mitigation deployed to testbed; awaiting verification.
6. `RESOLVED`: Confirmed remediated by autonomous verification agent.
7. `RISK_ACCEPTED`: Documented business risk acceptance.
8. `REOPENED`: Fix failed retest; returned to engineering backlog.
