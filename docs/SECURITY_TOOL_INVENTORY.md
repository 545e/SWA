# SECURITY TOOL INVENTORY & INTEGRATION MATRIX
## Comprehensive Audit of 23 Security Engines and Adapters

| Tool / Engine | Module Location | Adapter Type | Supported Target Protocols | Output Format | Status |
|---|---|---|---|---|---|
| **Port Scanner** | `core/cyber_tools.py` | Native Async Socket | TCP, UDP | JSON Structured | VERIFIED |
| **HTTP Crawler** | `core/cyber_tools.py` | Native HTTPX Client | HTTP, HTTPS | DOM Element Tree | VERIFIED |
| **Subdomain Engine** | `core/cyber_tools.py` | Native DNS Resolver | DNS, TLS SAN | Host List | VERIFIED |
| **SQLi Engine** | `core/sqli_engine.py` | Native Prober | HTTP / Forms / JSON | CVSS + cURL PoC | VERIFIED |
| **WAF Bypass Engine** | `core/waf_bypass_engine.py` | Mutation Engine | HTTP / Headers | Bypass Payload | VERIFIED |
| **REA Engine** | `core/rea_engine.py` | Native Heuristic | SQLite / Memory | Integrity Audit | VERIFIED |
| **Kill Chain Engine** | `core/kill_chain/` | 7-Stage Correlator | Security Findings | Incident Graph | VERIFIED |
| **Knowledge Graph** | `core/knowledge_graph.py` | Graph Ingestor | Asset / Finding Nodes | Graph Nodes/Edges | VERIFIED |
| **LLM Red-Team Harness** | `core/llm_security_testing.py` | Adversarial Prober | LLM Endpoints | 12-Vector Scorecard | VERIFIED |
| **RAG Knowledge Engine** | `core/rag_engine.py` | BM25 + Sparse TF | Text / Advisories | Grounded Context | VERIFIED |
| **Agent Memory Store** | `core/agent_memory.py` | 3-Tier Memory | Scrubbed Conversation | Token Records | VERIFIED |
| **OWASP A01 Prober** | `plugins/owasp_plugins.py` | Plugin Agent v3.0 | REST / Web | Finding Record | VERIFIED |
| **OWASP A02 Prober** | `plugins/owasp_plugins.py` | Plugin Agent v3.0 | TLS / Ciphers | Finding Record | VERIFIED |
| **OWASP A03 Prober** | `plugins/owasp_plugins.py` | Plugin Agent v3.0 | Web Endpoints | Finding Record | VERIFIED |
| **OWASP A04 Prober** | `plugins/owasp_plugins.py` | Plugin Agent v3.0 | Logic / Limits | Finding Record | VERIFIED |
| **OWASP A05 Prober** | `plugins/owasp_plugins.py` | Plugin Agent v3.0 | HTTP Headers | Finding Record | VERIFIED |
| **OWASP A06 Prober** | `plugins/owasp_plugins.py` | Plugin Agent v3.0 | Dependencies / CVE | Finding Record | VERIFIED |
| **OWASP A07 Prober** | `plugins/owasp_plugins.py` | Plugin Agent v3.0 | Session / Cookies | Finding Record | VERIFIED |
| **OWASP A08 Prober** | `plugins/owasp_plugins.py` | Plugin Agent v3.0 | Data / Deserialization | Finding Record | VERIFIED |
| **OWASP A09 Prober** | `plugins/owasp_plugins.py` | Plugin Agent v3.0 | Logging / Audit | Finding Record | VERIFIED |
| **OWASP A10 Prober** | `plugins/owasp_plugins.py` | Plugin Agent v3.0 | SSRF / Cloud IMDS | Finding Record | VERIFIED |
| **Nessus Report Engine**| `reports/nessus_report_engine.py` | Exporter | Report Findings | Nessus v2 XML | VERIFIED |
| **Cyber Exporter** | `core/cyber_export.py` | Multi-Format | SARIF, PDF, JSON | Export Packages | VERIFIED |
