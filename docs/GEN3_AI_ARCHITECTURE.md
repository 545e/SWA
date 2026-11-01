# SWA AI — Generation 3 AI Architecture & Intelligence

## 1. Objectives & Principles

SWA AI utilizes Artificial Intelligence to accelerate human security analysts, prioritize vulnerabilities, explain complex exploitation chains, and recommend defensible remediation.

Key principles:
1. **Evidence Grounding:** AI outputs must be strictly grounded in actual scan logs, HTTP headers, response payloads, or verified vulnerability data. The AI must never hallucinate findings.
2. **Untrusted Evidence Isolation:** All scanner outputs and web responses are wrapped in `<untrusted_target_evidence_boundary>` tags to mitigate indirect prompt injection.
3. **Deterministic Governance:** Destructive or high-impact actions (exploits, brute force, active port flooding) require explicit Human-in-the-Loop approval gates.

---

## 2. Autonomous Multi-Agent Workforce

17 specialist agents operate with distinct manifests, toolsets, and scope boundaries:

1. `recon_analyst`: Passive OSINT and subdomain enumeration.
2. `asset_intel_officer`: Infrastructure fingerprinting and service identification.
3. `web_security_auditor`: OWASP Top 10 web application vulnerabilities.
4. `network_security_specialist`: Port auditing, service version analysis, and protocol security.
5. `api_security_assessor`: REST/GraphQL endpoint parameter fuzzing and BOLA analysis.
6. `code_security_reviewer`: SAST rule execution and vulnerable dependency detection.
7. `vulnerability_analyst`: Correlation, CVSS scoring, and false-positive deduplication.
8. `threat_intel_specialist`: Mapping findings to MITRE ATT&CK techniques and threat feeds.
9. `risk_assessment_officer`: Calculation of composite risk indices based on asset criticality.
10. `remediation_engineer`: Generation of tailored patch recipes and security guidance.
11. `reporting_officer`: Synthesis of technical and executive compliance reports.
12. `qa_verification_agent`: Autonomous retesting and validation of resolved vulnerabilities.
13. `fuzzing_specialist`: Boundary testing on parameter handling and encoding.
14. `waf_architect`: Analysis of WAF filtering and evasion defense.
15. `forensics_investigator`: Artifact analysis and IOC identification.
16. `cloud_security_auditor`: Cloud metadata and misconfiguration detection.
17. `container_security_specialist`: Container image vulnerability and privilege analysis.

---

## 3. Machine Learning & Model Evaluation Pipeline

- Evaluated in `core/ai_evaluation.py` and `tests/test_ai_training_and_evaluation.py`.
- Hardware detection identifies CPU, RAM, CUDA GPU availability, and enforces a low-resource profile for constrained environments (e.g. 2 vCPUs, 3 GB RAM).
- Evaluates accuracy, precision, recall, F1 score, confusion matrices, and inference latency.
