# SWA AI — Threat Intelligence & MITRE ATT&CK Mapping
**Document ID:** SEC-CTI-2026-017  
**Generated:** 2026-11-01T06:13:28.585946+00:00  

---

## 1. Integrated Threat Intelligence
The platform correlates vulnerability discoveries directly against MITRE ATT&CK Enterprise Matrix techniques:
- `T1190`: Exploit Public-Facing Application (correlated with SQLi, RCE, and SSTI findings).
- `T1595`: Active Scanning (correlated with Amass, Port Scanning, and Nuclei probers).
- `T1552`: Unsecured Credentials (correlated with GhostJS secret mining discoveries).
- `T1059`: Command and Scripting Interpreter (correlated with command injection probes).
