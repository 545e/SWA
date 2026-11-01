# SWA AI — UI Control Audit Report
**Document ID:** SEC-UICONTROL-2026  
**Generated:** 2026-11-01T06:57:46.575012+00:00  

---

## 1. Control Audit Results
Every button, form, tab, and modal in `web/static/index.html` was audited:
- Quick Audit Button: Connected to `/api/scans`
- Tools Health Check Button: Connected to `/api/health/diagnostics`
- Initiate Deploy Button: Connected to `/api/cyber/deploy/initiate`
- Approve Deploy Button: Connected to `/api/cyber/deploy/{id}/approve`
- Rollback Deploy Button: Connected to `/api/cyber/deploy/{id}/rollback`
- Acceptance Checklist Panel: Connected to `/api/cyber/deploy/{id}/acceptance-checklist`
