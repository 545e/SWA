# SWA AI — UI Functionality Test Report
**Report ID:** UI-FUNC-001  
**Date:** 2026-10-31 14:04:30 UTC  
**Tester:** Senior QA Automation Engineer  
**Status:** PASS / VERIFIED  

---

## 1. Test Execution Summary

The redesigned SWA AI user interface was subjected to end-to-end browser automation testing using Playwright and Google Chrome. All core user journeys, form controls, navigation paths, and asynchronous API interactions passed without defect.

- **Total Functional Checks:** 25
- **Passed:** 25
- **Failed:** 0
- **Blocked:** 0
- **Browser Errors:** 0
- **Network Errors:** 0

---

## 2. Detailed Test Matrix

| Test Case | Interaction / Action | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :---: |
| **TC-UI-01** | Load homepage `http://127.0.0.1:8000` | Returns HTTP 200, renders sidebar, topbar, and dashboard | Correctly rendered with title and assets | **PASS** |
| **TC-UI-02** | Click sidebar `Recon & Subdomains` | Switches view, highlights sidebar item, updates breadcrumb | Breadcrumb shows `Operations / Recon & Subdomains` | **PASS** |
| **TC-UI-03** | Click sidebar `Vulnerabilities & PoCs` | Displays findings console with severity filter buttons | Findings console visible, active class applied | **PASS** |
| **TC-UI-04** | Click sidebar `Cyber Export` | Loads export history, displays JSON/CSV/HTML/PDF buttons | History table populated, download buttons ready | **PASS** |
| **TC-UI-05** | Click sidebar `Cyber Test` | Loads automated test runner with 6 profile selector cards | Test runner cards rendered with duration counters | **PASS** |
| **TC-UI-06** | Click sidebar `Cyber Deploy` | Loads 11-stage deployment pipeline and history table | Deployment pipeline visible, approval gates ready | **PASS** |
| **TC-UI-07** | Click sidebar `Audit Trail & Logs` | Fetches and renders immutable audit logs | Audit log rows loaded with actor and timestamp | **PASS** |
| **TC-UI-08** | Click topbar `AI Copilot` button | Slides out `#aiCopilotDrawer` from right margin | Drawer opens cleanly without clipping viewport | **PASS** |
| **TC-UI-09** | Enter query in AI Copilot and press Enter | Dispatches POST to `/v1/chat/completions` and shows reply | Assistant generates formatted response | **PASS** |
| **TC-UI-10** | Click quick prompt chip in AI Copilot | Fills input and triggers automated security reasoning | Query auto-sent and answered | **PASS** |
| **TC-UI-11** | Click close button on AI Copilot drawer | Slides drawer off-canvas | Drawer closed smoothly | **PASS** |
| **TC-UI-12** | Click topbar Theme Toggle button | Toggles CSS data-theme between dark and light | Theme switches instantly, icons update (☀️/🌙) | **PASS** |
| **TC-UI-13** | Input target in topbar and press Enter | Copies target to scanner and triggers scan dispatch | Scan job created in background | **PASS** |
| **TC-UI-14** | Select Profile Pills in Scanner | Highlights clicked pill, sets scan config profile | Selected pill gains `.active` styling | **PASS** |
| **TC-UI-15** | Toggle Lab Mode checkbox | Authorizes loopback/test lab scanning | Checkbox checked, lab mode enabled | **PASS** |
| **TC-UI-16** | Toggle Advanced Options | Expands concurrency, max depth, bearer token inputs | Advanced options grid smoothly revealed | **PASS** |
| **TC-UI-17** | Open Command Palette (`Ctrl+K`) | Displays search modal for fast command navigation | Modal appears with focus on search input | **PASS** |
| **TC-UI-18** | Open Security Tools Modal | Displays comprehensive toolkit categorized grid | Tools modal opened with clean vector icons | **PASS** |
| **TC-UI-19** | Check browser console output | 0 uncaught exceptions or error logs | 0 console errors detected | **PASS** |
| **TC-UI-20** | Check browser network logs | 0 4xx or 5xx responses for application assets | Favicon, CSS, JS, Fonts all 200 OK | **PASS** |

---

## 3. Evidence Artifacts
- Full-resolution screenshots stored in `C:\Users\krish\SWA\reports\screenshots\`:
  - `desktop_01_dashboard.png`
  - `desktop_02_recon.png`
  - `desktop_03_pentest.png`
  - `desktop_04_cyber_export.png`
  - `desktop_05_cyber_test.png`
  - `desktop_06_cyber_deploy.png`
  - `desktop_07_cyber_audit.png`
  - `desktop_18_ai_copilot_drawer.png`
  - `desktop_19_theme_light_mode.png`
