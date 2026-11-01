# SWA AI — Agent Web UI Visibility, Search & Pagination Report

**Generated:** 2026-11-01T07:23:49.512323+00:00  
**View ID:** `#viewAgents`  
**Route Hash:** `#/agents`  
**Frontend Controller:** `web/static/app.js::loadAgents()`  

---

## 1. UI Components Verified

1. **Header & View Title:** Displays `Autonomous Multi-Agent Cybersecurity Workforce (85 Agents)`.
2. **KPI Metrics Cards:**
   - Total Agents: **85**
   - Workforce Specialists: **17**
   - Offensive & Recon: **9**
   - OWASP Plugins: **10**
   - Core Engines: **32**
   - Tool Adapters: **17**
3. **Category Filter Toolbar:** 6 clickable filter pills dynamically filter cards without page reload.
4. **Live Search Input:** Client-side search filters 85 agents instantly by name, role, ID, or description.
5. **Pagination Bar:** Paginated view displaying 12 agents per page with Previous/Next controls and page indicators.
6. **Card Actions:** "Run Task" button launches ad-hoc task modal with explicit input parameters and timeout enforcement.

---

## 2. Browser Verification Evidence

- **Initial Load:** Loads all 85 agents via `/api/agents` and `/api/agents/summary`.
- **Filtering:** Clicking "Workforce (17)" shows 17 cards; clicking "Core Engines (32)" shows 32 cards across 3 pages.
- **Search:** Typing "sql" immediately narrows grid to SQL injection engines and adapters.
- **Console Errors:** Zero uncaught JavaScript errors recorded.
