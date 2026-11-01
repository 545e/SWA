# SWA AI — Generation 3 Changelog

## [Generation 3.0.0-Enterprise] — 2026-11-01

### Major Architecture & UI Upgrades
- **Unified Application Shell:** Completely eliminated old duplicate UI layouts and unencapsulated dashboard elements.
- **Strict View Isolation:** Encapsulated all 20 views (`viewDashboard`, `viewAssessments`, `viewAssets`, `viewVulnerabilities`, `viewCompare`, `viewTools`, `viewWebSecurity`, `viewNetworkSecurity`, `viewApiSecurity`, `viewCodeSecurity`, `viewAgents`, `viewInvestigation`, `viewRemediation`, `viewDrift`, `viewApprovals`, `viewReports`, `viewCyberAudit`, `viewIntegrations`, `viewSettings`, `viewDocs`) inside isolated `.swa-view` containers.
- **Definitive Bug Fix:** Resolved the known issue where selecting Vulnerabilities displayed Dashboard content. Inactive views are strictly hidden via `.swa-view { display: none !important; }` and `.swa-view.active { display: block !important; }`.
- **Client-Side Hash Router:** Implemented bidirectional URL synchronization (`window.location.hash`, `hashchange`, `popstate`), ensuring direct URL access (e.g. `#/vulnerabilities`, `#/assessments`), browser refresh, and Back/Forward buttons work seamlessly.

### API & Backend Hardening
- **New Finding API:** Added `GET /api/findings` supporting global and scan-filtered finding retrieval.
- **Rate Limiting Refinement:** Preserved loopback exemption (`127.0.0.1`, `::1`, `localhost`) for scanner self-checks while enforcing token-bucket rate limiting on external requests.
- **Database Performance:** Active WAL mode and 15 B-Tree indexes maintained across all 18 relational tables.

### Testing & Verification
- **Automated Navigation Acceptance Suite:** Added `tests/test_gen3_navigation_acceptance.py` validating view existence, isolation, routing tables, and API contracts.
- **100% Pass Rate:** Full test suite executed with 110 passed tests across 17 test modules.
