# SWA AI — Master Engineering Decision Log

**Document Version:** 2.2.0-Enterprise  
**Effective Date:** 2026-11-01  
**Architecture Lead:** Principal Software Architect & CTO

---

## 1. Architectural Decisions & Trade-off Analysis

### ADR-001: Relationship-Based Security Knowledge Graph via SQLite Relational Model
- **Context:** The product vision requires mapping complex relationships between Organizations, Projects, Domains, Subdomains, IPs, Network Services, Applications, Endpoints, Findings, Evidence, and Owners.
- **Evaluated Alternatives:** Neo4j (external graph DB), NetworkX (in-memory only), Embedded SQLite Node/Edge model.
- **Decision:** Implement a dual-table `knowledge_nodes` and `knowledge_edges` graph topology directly inside SWA's existing SQLite database.
- **Rationale:** Introduces zero external server dependencies, ensures atomic ACID transactions with scan results, requires zero Docker memory overhead on client machines, and executes sub-10ms graph queries through indexed node lookups.
- **Status:** **APPROVED & IMPLEMENTED**

---

### ADR-002: Modular Multi-Agent Workforce Architecture
- **Context:** 17 specialist agents required clear separation of concerns without circular LLM discussions or uncontrolled shared memory.
- **Decision:** Base all agents on `BaseSpecialistAgent` inheriting a strict `AgentManifest` with input/output schemas, allowed tool adapters, timeout limits, and explicit permission boundaries.
- **Rationale:** Enforces deterministic execution workflows where predictable behavior is required, while permitting LLM enrichment for PoC explanations and code patch synthesis without risking runaway processes.
- **Status:** **APPROVED & IMPLEMENTED**

---

### ADR-003: Isolated REST Router for Enterprise Extensions
- **Context:** `web/server.py` is an established, extensive server file (1890+ lines). Modifying existing routes directly could introduce regressions to existing frontend UI bindings.
- **Decision:** Encapsulate all new enterprise features (Global Context, Specialist Agents, Approvals, Knowledge Graph, EASM Drift, Remediation Tickets, Enterprise Reports, and Diagnostics) into `web/enterprise_api.py` and mount it via `app.include_router(enterprise_router)`.
- **Rationale:** Strict boundary isolation. Eliminates merge conflicts, provides independent unit testing capability, and preserves 100% backward compatibility.
- **Status:** **APPROVED & IMPLEMENTED**

---

### ADR-004: Defensible & Explainable Risk Prioritization Formula
- **Context:** Standard CVSS scores fail to capture perimeter exposure, active exploit availability (CISA KEV), or business asset importance.
- **Decision:** Implement a transparent, documented mathematical formula:
  $$\text{Risk} = [(\text{Base Severity} \times \text{Confidence Multiplier}) + \text{Exploitability Bonus}] \times \text{Exposure} \times \text{Criticality} \times (1 - \text{Mitigation Discount})$$
- **Rationale:** Ensures every risk score displayed on the dashboard has step-by-step mathematical provenance and human-readable explanation, eliminating "black-box" risk scoring.
- **Status:** **APPROVED & IMPLEMENTED**

---

### ADR-005: Automated Retest Verification Engine
- **Context:** Vulnerability lifecycles traditionally depend on manual analyst verification, creating bottlenecked remediation boards.
- **Decision:** Build an active probe verification engine (`remediation_engine.run_retest`) that re-queries the affected endpoint with safe verification requests, evaluates response headers/status/reflection, and automatically transitions tickets to `VERIFIED`.
- **Rationale:** Drastically accelerates remediation velocity while generating cryptographic and HTTP evidentiary records.
- **Status:** **APPROVED & IMPLEMENTED**
