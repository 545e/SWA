# SWA AI — Existing Tools Discovery Report
**Document ID:** SEC-DISC-2026-002  
**Generated:** 2026-11-01T06:13:28.585946+00:00  
**Classification:** Engineering Discovery & Source Inspection  

---

## 1. Discovery Scope & Methodology
A comprehensive codebase discovery was conducted across `core/`, `agents/`, `plugins/`, and `web/` to inventory all operational security algorithms, heuristics, probers, and third-party bindings.

## 2. In-Tree Native Tool Catalog
1. **`core/cyber_tools.py`**:
   - `audit_security_headers(url)`: Inspects HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy with letter-grade scoring (A+ to F).
   - `analyze_ssl_tls(host, port)`: Connects via Python standard `ssl` module, extracts cipher suites, TLS version (TLSv1.2, TLSv1.3), certificate expiration, SANs, and issuer.
   - `dns_lookup(domain)` & `email_spoofing_check(domain)`: Audits MX, TXT, SPF, and DMARC enforcement records.
   - `calculate_subnet(cidr)`: Parses network masks, broadcast addresses, usable hosts, and wildcard masks.
2. **`core/js_intelligence.py`**:
   - `mine_js_secrets(script_content)`: Detects AWS access keys, GitHub PATs, JWT tokens, Stripe API keys, Slack webhooks, and private API keys using optimized entropy algorithms.
   - `find_hidden_endpoints(script_content)`: Extracts hidden REST and GraphQL endpoints from client-side webpack/vite bundles.
3. **`core/rea_engine.py`**:
   - Analyzes raw binaries (Windows Portable Executable, Linux ELF, macOS Mach-O), reading magic numbers, section headers, imported DLLs/symbols, and detecting packing indicators.
4. **`core/blue_team_engine.py`**:
   - Synthesizes automated defenses against discovered CVEs: ModSecurity CRS rules, Cloudflare WAF JSON expressions, AWS WAF rulesets, Nginx rate-limiting directives, and Snort/Suricata signatures.
5. **`core/forensics_engine.py`**:
   - Analyzes Apache/Nginx web logs, Windows Event Logs (XML/CSV), and syslog files for brute force, web shells, and SQL injection patterns with direct MITRE ATT&CK mapping.
