# SWA AI — API Versioning & Evolution Policy

## 1. Versioning Architecture
SWA AI follows semantic API versioning with explicit URI prefixing:
- **Current Stable Version**: `/api/v1/*`
- **Legacy Compatibility Endpoints**: `/api/*` (preserved with 100% backward compatibility)

```
/api/v1/assessments     <-- Primary V1 Endpoint (Standardized Envelope)
/api/scans              <-- Preserved Legacy Endpoint (Full Compatibility)
```

## 2. Backward Compatibility Guarantee
Under the SWA AI Preservation Policy:
- **No breaking deletions**: No existing public API endpoint, field, or query parameter is ever silently deleted or altered.
- **Additive Evolution**: All new capabilities (such as CISA KEV feeds, FIRST EPSS scores, multi-agent pipelines) are introduced additively.
- **Deprecation Lifecycle**: If an endpoint is slated for replacement, it enters a minimum 180-day deprecation cycle with `Sunset` and `Link` RFC 8594 headers before any planned decommissioning.
