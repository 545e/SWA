# SWA AI — Third-Party Tool Evaluation
**Document ID:** SEC-EVAL-2026-004  
**Generated:** 2026-11-01T06:13:28.585946+00:00  

---

## 1. Evaluated Tools & Selection Criteria

1. **Nmap (Network Exploration & Security Auditing)**
   - *License:* Custom (Nmap Public Source License)
   - *Suitability:* Industry standard port scanner.
   - *Platform Integration:* Subprocess adapter with JSON/XML output parser in `core/scanner_integrations.py`.
   - *Fallback:* Built-in native async socket scanner in `core/scanner.py`.

2. **Nuclei (ProjectDiscovery Fast Vulnerability Scanner)**
   - *License:* MIT
   - *Suitability:* Highly community-maintained YAML vulnerability templates.
   - *Platform Integration:* JSON-lines streaming stdout adapter with scope policy enforcement.
   - *Fallback:* Built-in `plugins/owasp_plugins.py` active prober.

3. **Bandit (Python AST Security Linter)**
   - *License:* Apache 2.0
   - *Suitability:* Fast, static AST-based vulnerability detection in Python source.
   - *Platform Integration:* JSON output ingestion into SWA AI unified finding database.

4. **Trivy (Aqua Security Container & Filesystem Scanner)**
   - *License:* Apache 2.0
   - *Suitability:* Detects OS package CVEs and language dependencies in container images and filesystems.
   - *Platform Integration:* CLI subprocess invocation with SARIF/JSON parsing.

5. **OWASP ZAP (Zed Attack Proxy)**
   - *License:* Apache 2.0
   - *Suitability:* Comprehensive web vulnerability scanner.
   - *Platform Integration:* Headless baseline scan script wrapper (`zap-baseline.py`).
