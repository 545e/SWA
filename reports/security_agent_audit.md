# SWA AI — Security Agent Workforce Audit
**Document ID:** SEC-AGENT-2026-008  
**Generated:** 2026-11-01T06:13:28.585946+00:00  

---

## 1. Autonomous Workforce Overview
SWA AI deploys 17 specialist agents orchestrated by `agents/orchestrator.py`:

1. **Reconnaissance Specialist Agent:** Passive DNS, WHOIS, certificate transparency queries.
2. **Amass Engine Agent:** Multi-source subdomain enumeration.
3. **Attack Surface Discovery Agent:** Host discovery, open port enumeration, web technology fingerprinting.
4. **Vulnerability Hunter Agent:** Heuristic fuzzing and active OWASP vulnerability probing.
5. **Param Fuzzer Agent:** Parameter tampering, boundary testing, buffer overflow probing.
6. **API Security Specialist Agent:** REST/GraphQL schema audit, broken object level authorization (BOLA) tests.
7. **GhostJS AST Analyst Agent:** Client-side JavaScript bundle deobfuscation and endpoint extraction.
8. **Binary Reverse Engineering Agent:** PE/ELF/Mach-O static reverse engineering.
9. **Blue Team Defense Agent:** Virtual patch generation for WAF, IDS, and reverse proxies.
10. **DFIR Forensics Agent:** Server log parser and intrusion timeline reconstructor.
11. **Threat Hunting Agent:** Proactive IOC querying and hunt script synthesizer.
12. **MITRE ATT&CK Correlator Agent:** Attack technique mapping and kill-chain analysis.
13. **Compliance Auditor Agent:** ISO 27001, SOC 2, PCI-DSS, and NIST CSF checklist validation.
14. **Approval Gatekeeper Agent:** Dual-control gate management for intrusive pentesting.
15. **Remediation Specialist Agent:** Automated fix tracking and re-test verification.
16. **Reporting Specialist Agent:** Multi-format deliverable synthesis (HTML, PDF, JSON, CSV).
17. **Autonomous Master Orchestrator:** Global task DAG resolution, state synchronization, and failure recovery.
