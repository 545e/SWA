# Repository Architecture Audit

## High-Level Architecture
- **Backend:** FastAPI (Python 3.10+ / 3.12 verified) running on Uvicorn ASGI server.
- **Database:** SQLite 3.49.1 with WAL (Write-Ahead Logging) mode, 27 relational tables.
- **Frontend:** Pure semantic HTML5, CSS3 with responsive glassmorphism dark theme, vanilla ES6+ JavaScript (zero heavy node runtime bloat).
- **Core Security Engines:**
  - `core/agent_registry.py`: Central authority managing all 85 agents across 5 operational tiers.
  - `core/tool_registry.py`: Security tool inventory and CLI/subprocess adapter framework.
  - `core/js_intelligence.py`: JavaScript AST token and secrets extractor.
  - `core/subdomain_engine.py`: Passive and active DNS/subdomain reconnaissance engine.
  - `core/owasp_engine.py`: OWASP Top 10 automated probe suites.
  - `core/post_deployment_checklist.py`: Persistent 10-category deployment verifier.
