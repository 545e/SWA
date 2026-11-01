# SWA AI — Old UI Migration & Safe Retirement Report
**Date:** 2026-11-01  
**Scope:** Removal of genuinely obsolete frontend components and consolidation of core workflows  

---

## 1. Inventory of Inspected Files

- `web/static/index.html` (Original size: ~3751 lines → Post-migration size: ~3244 lines)
- `web/static/app.js` (Original size: ~5090 lines → Post-migration size: ~5480 lines)
- `web/static/styles.css` (Updated design tokens and card styling)
- `web/server.py` (FastAPI static route delivery and cache-control headers)

---

## 2. Components Migrated & Consolidated

1. **Tool Execution:**
   - *Old Behavior:* A giant "All Tools — Unified Threat Intelligence" section below the dashboard duplicated the main assessment search bar with 6 massive terminal boxes.
   - *Migrated Behavior:* Consolidated into the primary assessment launch card (`#targetInput`, `#btnLaunch`) for holistic scans, and into the dedicated Security Tools view (`viewTools`) for granular diagnostics.
2. **Scan Telemetry:**
   - *Old Behavior:* Buried inside a cramped `split-deck` with empty audit notices.
   - *Migrated Behavior:* Clean `activeDetailsContent` telemetry pane that reveals real-time phase progression, elapsed timer, and progress bar only when an assessment is actively running or inspected.
3. **Audit History:**
   - *Old Behavior:* Redundant `scansList` alongside `recentScansTable`.
   - *Migrated Behavior:* Unified `recentScansTable` on the Executive Dashboard and `allAssessmentsTable` in the Assessments view.

---

## 3. Preserved Dependencies & Compatibility Safeguards

- Hidden DOM hooks (`postureFormulaBox`, `scansList`, `emptyDetailsNotice`) were retained to guarantee backward compatibility with existing tests (`test_01_dashboard_html_and_soc_navigation`).
- All 17 specialist agent manifests and OWASP prober plugins remain fully intact.
