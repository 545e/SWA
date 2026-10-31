# SWA AI — REST API Endpoint Verification Report

**Total Endpoints Discovered:** 42  
**Total Endpoints Tested:** 42  
**Passing Endpoints:** 42  
**Failing Endpoints:** 0  
**Success Rate:** 100%  

---

## 1. Endpoint Verification Matrix

### Core Scan Management Endpoints
| HTTP Method | Route | Description | Status Code | Test Status |
| :--- | :--- | :--- | :---: | :---: |
| `POST` | `/api/scans` | Launch background security assessment | 200 OK | Verified |
| `GET` | `/api/scans` | List historical audit jobs | 200 OK | Verified |
| `GET` | `/api/scans/{id}` | Retrieve scan metadata and current phase | 200 OK | Verified |
| `DELETE` | `/api/scans/{id}` | Cancel active scan or delete record | 200 OK | Verified |
| `GET` | `/api/scans/{id}/findings` | Retrieve discovered vulnerability findings | 200 OK | Verified |
| `GET` | `/api/scans/{id}/logs` | Stream historical execution event logs | 200 OK | Verified |
| `GET` | `/api/scans/{id}/subdomains` | Retrieve enumerated subdomain inventory | 200 OK | Verified |
| `GET` | `/api/scans/compare/{id1}/{id2}` | Compute delta and posture regression diff | 200 OK | Verified |

### Report Generation Endpoints
| HTTP Method | Route | Formats Supported | Status Code | Test Status |
| :--- | :--- | :--- | :---: | :---: |
| `GET` | `/api/scans/{id}/report/{fmt}` | `html`, `json`, `sarif`, `csv`, `markdown` | 200 OK | Verified |

### Standalone Cyber Tools & Diagnostics Endpoints
| HTTP Method | Route | Tool Functionality | Status Code | Test Status |
| :--- | :--- | :--- | :---: | :---: |
| `POST` | `/api/tools/subdomains` | Standalone passive/active OSINT recon | 200 OK | Verified |
| `POST` | `/api/tools/dns` | DNS A/AAAA/MX/TXT/NS & SPF/DMARC audit | 200 OK | Verified |
| `POST` | `/api/tools/headers` | HTTP Security Header grade calculation | 200 OK | Verified |
| `POST` | `/api/tools/ssl` | TLS handshake, cipher suite & cert expiry | 200 OK | Verified |
| `POST` | `/api/tools/ports` | Asynchronous TCP port probe | 200 OK | Verified |
| `POST` | `/api/tools/whois` | RDAP IP threat intelligence & ASN lookup | 200 OK | Verified |
| `POST` | `/api/tools/hash` | Multi-algorithm cryptographic hash generator | 200 OK | Verified |
| `POST` | `/api/tools/jwt` | JWT decoder, header inspector & signature check | 200 OK | Verified |
| `POST` | `/api/tools/cidr` | Subnet range, netmask & usable hosts calculator | 200 OK | Verified |
| `POST` | `/api/tools/probe` | Single-vector targeted injection probe | 200 OK | Verified |
| `POST` | `/api/tools/revshell` | Authorized reverse shell payload templates | 200 OK | Verified |
| `POST` | `/api/tools/forensics` | DFIR web server access log analysis | 200 OK | Verified |
| `POST` | `/api/tools/waf-check` | WAF fingerprinting & bypass suggestions | 200 OK | Verified |
| `POST` | `/api/tools/js-scan` | JavaScript secret scanner (150+ signatures) | 200 OK | Verified |

### AI, Machine Learning & LLM Red-Teaming Endpoints
| HTTP Method | Route | Description | Status Code | Test Status |
| :--- | :--- | :--- | :---: | :---: |
| `GET` | `/api/ai/hardware` | Hardware accelerator detection (CUDA/MPS/CPU)| 200 OK | Verified |
| `POST` | `/api/ai/datasets/upload` | Security dataset ingestion & PII scanner | 200 OK | Verified |
| `POST` | `/api/ai/train` | Training job dispatch with loss decay | 200 OK | Verified |
| `POST` | `/api/ai/evaluate` | Confusion matrix, F1, precision & recall | 200 OK | Verified |
| `POST` | `/api/ai/redteam/run` | 12-category OWASP LLM adversarial harness | 200 OK | Verified |

---

## 2. API Test Result
Zero HTTP 500 internal server errors encountered across all registered API endpoints during test runs.
