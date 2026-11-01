# Authoritative 85-Agent Inventory Report

## Tier Distribution
- **Tier 1: Specialist Workforce Agents (17)**: High-level autonomous roles (Lead Recon, Exploit Verifier, Blue Team Defender, etc.)
- **Tier 2: Offensive & Reconnaissance Domain Agents (9)**: Surface mappers, fuzzers, parameter probers.
- **Tier 3: OWASP Top 10 Security Plugin Agents (10)**: Dedicated rule checkers for Injection, Broken Access, Cryptographic Failures, etc.
- **Tier 4: Core Autonomous Security & Governance Engines (32)**: EASM drift monitor, approval gatekeeper, posture assessor, etc.
- **Tier 5: External Tool & Scanner Integration Adapters (17)**: Nmap, Nuclei, SQLmap, Nikto, Trivy, Gitleaks, REA, etc.

**Total Registered & Operational:** 85 Agents  
**Registry Authority:** `core/agent_registry.py`  
**Database Table:** `agents_inventory` (85 rows verified)  
**REST API:** `GET /api/agents` and `GET /api/agents/summary`
