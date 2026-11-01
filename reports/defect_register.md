# SWA AI — Defect Register & Resolution Tracking
**Platform:** SWA AI Autonomous Enterprise Security Auditor  
**Date:** 2026-11-01  
**Auditor:** SWA Independent Quality & Security Engineering  
**Version:** 3.0.0-Enterprise  

---

## 1. Summary of Defect Management

Every defect discovered during the repository audit, code inspection, and runtime verification has been cataloged, classified by severity, and tracked through root-cause analysis, corrective action, and automated retesting.

| Defect ID | Title | Severity | Priority | Component | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **DEF-01** | Duplicate & Obsolete "All Tools" Hub | High | P1 | `web/static/index.html` | **RESOLVED** |
| **DEF-02** | Stale Split-Deck & Empty Audits Area | Medium | P2 | `web/static/index.html` | **RESOLVED** |
| **DEF-03** | 13 Missing Core JavaScript Functions | Critical | P0 | `web/static/app.js` | **RESOLVED** |
| **DEF-04** | Missing Generation 2 Audit Documentation | Medium | P2 | `docs/` | **RESOLVED** |
| **DEF-05** | Headless Chrome Screenshot IPC Named Pipe Restriction | Low | P3 | Automated Preview CLI | **DOCUMENTED** |
| **DEF-06** | Cloud AI Provider API Keys Configuration Requirement | Low | P3 | `core/ai_training.py` | **DOCUMENTED** |

---

## 2. Detailed Defect Records

### DEF-01: Duplicate & Obsolete "All Tools — Unified Threat Intelligence" Hub
- **Severity:** High (Impacts User Experience & Usability)
- **Component:** `web/static/index.html` (Lines ~530 to ~936)
- **Root Cause:** A legacy redundant tool runner remained in the template below the new Generation 2 hero assessment card, duplicating tool triggers, search fields, and terminal boxes.
- **Fix Applied:** Completely removed the obsolete markup block in commit `1b61a2c`. Tool invocation is consolidated into the primary launch card and the dedicated Security Tools view (`viewTools`).
- **Verification:** Serviced HTML verified via regex; zero duplicate forms remain. Tested in test suite.
- **Retest Status:** **PASS**

---

### DEF-02: Stale Split-Deck & Empty Audits Area
- **Severity:** Medium
- **Component:** `web/static/index.html` (Lines ~940 to ~1111)
- **Root Cause:** The old split-deck design displayed unclickable placeholders ("Select an assessment or enter a target above") and empty audit lists that conflicted with the modern `recentScansTable`.
- **Fix Applied:** Replaced with the clean `activeDetailsContent` telemetry pane that displays only when an assessment is actively running or inspected.
- **Retest Status:** **PASS**

---

### DEF-03: 13 Missing Core JavaScript Controller Functions
- **Severity:** Critical (P0 — Functional Regression)
- **Component:** `web/static/app.js`
- **Root Cause:** Click handlers declared in HTML (`launchScan()`, `loadScans()`, `selectProfile()`, `toggleTheme()`, `quickAuditFromTopbar()`, `toggleMobileSidebar()`, `toggleSidebarCollapse()`, `closeAssetInspectionModal()`, `copyAssetCurl()`, `toggleAiCopilotDrawer()`, `sendAiCopilotMessage()`, `useAiPromptChip()`, `toggleAdvancedOptions()`) were missing definitions in `app.js`, triggering client-side `ReferenceError` exceptions.
- **Fix Applied:** Implemented all 13 controller functions with full backend API integration, state management, and real DOM updates in commit `1b61a2c`.
- **Verification:** Ran automated function validator `check_funcs.py`; confirmed 0 missing functions across 94 audited controls.
- **Retest Status:** **PASS**

---

### DEF-04: Missing Generation 2 Audit & Technical Documentation
- **Severity:** Medium
- **Component:** `docs/` directory
- **Root Cause:** Required architectural specifications, UI matrices, and installation runbooks were not yet tracked in version control.
- **Fix Applied:** Authored and committed all 10 required technical documents in commits `1b61a2c` and `e4a5378`.
- **Retest Status:** **PASS**

---

### DEF-05: Headless Chrome Screenshot Named Pipe IPC Restriction
- **Severity:** Low (Operational Limitation)
- **Component:** Chrome CLI Headless Subprocess
- **Root Cause:** Invoking Google Chrome in headless mode on Windows inside standard non-elevated user contexts encountered `Failed to open named pipe server process: Access is denied (0x5)`.
- **Mitigation:** In strict accordance with Specification §31.7, the running server process was validated via live HTTP endpoints on port 8000, and exact browser instructions were documented in `docs/GENERATION_2_LIVE_PREVIEW_REPORT.md`.
- **Retest Status:** **DOCUMENTED LIMITATION**

---

### DEF-06: Cloud AI Provider Key Dependency
- **Severity:** Low (External Configuration Requirement)
- **Component:** `core/ai_training.py` & `web/server.py`
- **Root Cause:** Advanced LLM reasoning using external commercial providers (e.g. OpenAI GPT-4, Anthropic Claude) requires user-supplied API keys in `.env` or the Settings panel.
- **Mitigation:** Fallback heuristic and local rule-based probers operate 100% autonomously without external keys. Documented in `docs/AI_EVALUATION.md`.
- **Retest Status:** **DOCUMENTED REQUIREMENT**
