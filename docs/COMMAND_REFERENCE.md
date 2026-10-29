# 📖 SWA AI — Security Command Reference Guide

This document is the authoritative, verified reference catalog for every command-line utility and security tool integrated into the **SWA AI — Autonomous Security Auditor** platform.

Every command below has been verified against the current codebase and execution engine.

---

## 📑 Table of Contents

1. [Platform Core & Web Dashboard Commands](#1-platform-core--web-dashboard-commands)
2. [Autonomous Red Team Scanning Commands](#2-autonomous-red-team-scanning-commands)
3. [Subdomain Intelligence & Asset Discovery](#3-subdomain-intelligence--asset-discovery)
4. [DNS, SPF & DMARC Email Security Analyzer](#4-dns-spf--dmarc-email-security-analyzer)
5. [HTTP Security Headers Evaluator](#5-http-security-headers-evaluator)
6. [SSL/TLS Certificate Deep Inspector](#6-ssltls-certificate-deep-inspector)
7. [Asynchronous Port & Service Prober](#7-asynchronous-port--service-prober)
8. [WHOIS & IP / ASN Threat Intelligence](#8-whois--ip--asn-threat-intelligence)
9. [Targeted Single-Vector Vulnerability Probing](#9-targeted-single-vector-vulnerability-probing)
10. [JavaScript Intelligence & Secret Scanner (GhostJS)](#10-javascript-intelligence--secret-scanner-ghostjs)
11. [Digital Forensics & Incident Response (DFIR)](#11-digital-forensics--incident-response-dfir)
12. [CIDR Subnet & IP Calculator](#12-cidr-subnet--ip-calculator)
13. [Cryptography, Hashing & JWT Debugger](#13-cryptography-hashing--jwt-debugger)
14. [Authorized Reverse Shell Reference Generator](#14-authorized-reverse-shell-reference-generator)
15. [REA Reverse Engineering Engine](#15-rea-reverse-engineering-engine)
16. [Security Dataset Management & Sanitization](#16-security-dataset-management--sanitization)
17. [AI Model Training & Fine-Tuning Commands](#17-ai-model-training--fine-tuning-commands)
18. [AI Model Tuning & Benchmark Evaluation](#18-ai-model-tuning--benchmark-evaluation)
19. [LLM Adversarial Red-Team & Security Testing](#19-llm-adversarial-red-team--security-testing)
20. [Unified Tool Catalog & Registry API](#20-unified-tool-catalog--registry-api)

---

## 1. Platform Core & Web Dashboard Commands

### `swa_cli.py --web` / `run.py`
- **Purpose**: Launches the full interactive web application and Security Operations Center (SOC) dashboard.
- **Prerequisites**: Python 3.10+ and packages from `requirements.txt`.
- **Syntax**:
  ```bash
  python swa_cli.py --web [--host <IP>] [--port <PORT>]
  # Alternatively:
  python run.py
  ```
- **Options**:
  - `--host <IP>`: Listen address (default: `127.0.0.1`).
  - `--port <PORT>`: Web server port (default: `8000`).
- **Safe Example**:
  ```bash
  python swa_cli.py --web --host 127.0.0.1 --port 8000
  ```
- **Expected Output**:
  ```text
  [⚡] Starting SWA AI Web Server on http://127.0.0.1:8000
  INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
  ```
- **Troubleshooting**: If port 8000 is occupied, supply `--port 8080`.

---

## 2. Autonomous Red Team Scanning Commands

### `swa_cli.py -t <TARGET> -p <PROFILE>`
- **Purpose**: Executes an end-to-end multi-agent security audit against an authorized target.
- **Prerequisites**: Target must comply with scope authorization. For localhost or test targets, pass `--lab-mode`.
- **Syntax**:
  ```bash
  python swa_cli.py -t <TARGET> -p <PROFILE> [--depth <1-5>] [--concurrency <N>] [--lab-mode] [--export-html <FILE>] [--export-json <FILE>] [--export-sarif <FILE>] [--export-md <FILE>]
  ```
- **Supported Profiles**:
  - `passive_recon`: Zero active traffic; queries CT logs, DNS, WHOIS, and evaluates headers.
  - `standard`: Balanced assessment (subdomains, ports, surface crawl, OWASP checks).
  - `lab_assessment`: Authorized local lab audit (127.0.0.1, PortSwigger, DVWA).
  - `full_red_team`: Deep crawl, parameter fuzzing, PoC exploit validation, and patch generation.
  - `owasp_top10`: Focused OWASP Top 10 web vulnerabilities.
  - `api_security`: REST/GraphQL parameter fuzzing and auth evaluation.
  - `recon_only`: Asset mapping, DNS resolution, and port probing only.
- **Safe Example (Local Authorized Lab)**:
  ```bash
  python swa_cli.py -t "http://127.0.0.1:8000" -p lab_assessment --lab-mode --export-json lab_report.json
  ```
- **Exporting Results**: Pass `--export-html report.html`, `--export-json report.json`, `--export-sarif report.sarif`, or `--export-md report.md`.

---

## 3. Subdomain Intelligence & Asset Discovery

### `swa_cli.py --subdomains <DOMAIN>`
- **Purpose**: Discovers subdomains via layered passive OSINT (crt.sh, HackerTarget, AlienVault, CertSpotter, etc.) and active DNS resolution with wildcard filtering.
- **Prerequisites**: Internet connectivity for public OSINT feeds; `dnspython` for async DNS resolution.
- **Syntax**:
  ```bash
  python swa_cli.py --subdomains <DOMAIN> [--recursive] [--export-subs <FILE>]
  ```
- **Options**:
  - `--recursive`: Probes multi-level sub-zones (e.g., `dev.corp.domain.com`).
  - `--export-subs <FILE>`: Exports newline-separated list of confirmed hostnames.

---

## 4. DNS, SPF & DMARC Email Security Analyzer

### `swa_cli.py --dns <DOMAIN>`
- **Purpose**: Queries A, AAAA, MX, TXT, NS records and performs automated email spoofability analysis (SPF/DMARC posture grading).
- **Syntax**:
  ```bash
  python swa_cli.py --dns <DOMAIN>
  ```

---

## 5. HTTP Security Headers Evaluator

### `swa_cli.py --headers <URL>`
- **Purpose**: Evaluates essential defensive security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
- **Syntax**:
  ```bash
  python swa_cli.py --headers "https://example.com"
  ```

---

## 6. SSL/TLS Certificate Deep Inspector

### `swa_cli.py --cert <DOMAIN>`
- **Purpose**: Inspects TLS certificate issuer, validity range, subject alternative names (SANs), cipher strength, and expiration warnings.
- **Syntax**:
  ```bash
  python swa_cli.py --cert "example.com"
  ```

---

## 7. Asynchronous Port & Service Prober

### `swa_cli.py --portscan <HOST>`
- **Purpose**: Rapidly scans top enterprise TCP ports (80, 443, 8080, 8443, 22, 21, 3306, 5432, 6379, 27017).
- **Syntax**:
  ```bash
  python swa_cli.py --portscan <HOST> [--ports <CSV_LIST>]
  ```

---

## 8. WHOIS & IP / ASN Threat Intelligence

### `swa_cli.py --whois <TARGET>`
- **Purpose**: Retrieves registrar, registration dates, ASN numbers, CIDR blocks, and country of origin via RDAP / WHOIS lookups.
- **Syntax**:
  ```bash
  python swa_cli.py --whois "example.com"
  ```

---

## 9. Targeted Single-Vector Vulnerability Probing

### `swa_cli.py --probe <URL> --vector <VECTOR>`
- **Purpose**: Tests a specific endpoint against an isolated attack vector with automated payload injection.
- **Supported Vectors**: `sqli`, `xss`, `ssrf`, `path_traversal`, `cmd_injection`, `open_redirect`, `cors`.
- **Syntax**:
  ```bash
  python swa_cli.py --probe "http://127.0.0.1:8000/api/search?q=test" --vector sqli --lab-mode
  ```

---

## 10. JavaScript Intelligence & Secret Scanner (GhostJS)

### `swa_cli.py --js-scan <URL_OR_FILE>`
- **Purpose**: Extracts API routes, bearer tokens, AWS credentials, JWT secrets, and shadow endpoints from client JavaScript code.
- **Syntax**:
  ```bash
  python swa_cli.py --js-scan "https://example.com/app.bundle.js"
  ```

---

## 11. Digital Forensics & Incident Response (DFIR)

### `swa_cli.py --forensics <LOG_FILE> --log-type <TYPE>`
- **Purpose**: Parses, tokenizes, and correlates security logs to extract high-risk indicators of compromise (IOCs), brute-force attempts, and injection payloads.
- **Supported Types**: `apache_nginx`, `suricata_ids`, `auth_ssh`, `syslog`.
- **Sample Inspection**:
  ```bash
  python swa_cli.py --forensics-sample apache_nginx
  ```

---

## 12. CIDR Subnet & IP Calculator

### `swa_cli.py --cidr <SUBNET>`
- **Purpose**: Computes network address, broadcast address, netmask, wildcard mask, usable IP range, host capacity, and RFC 1918 classification.
- **Syntax**:
  ```bash
  python swa_cli.py --cidr "192.168.1.0/24"
  ```

---

## 13. Cryptography, Hashing & JWT Debugger

### `swa_cli.py --hash <STRING>` / `--jwt <TOKEN>`
- **Purpose**: Computes cryptographic digests (MD5, SHA1, SHA256, SHA512, NTLM) or decodes and analyzes JSON Web Tokens for security vulnerabilities (e.g., `none` algorithm, token expiration).
- **Syntax**:
  ```bash
  python swa_cli.py --hash "password123"
  python swa_cli.py --jwt "eyJhbGciOi..."
  ```

---

## 14. Authorized Reverse Shell Reference Generator

### `swa_cli.py --revshell`
- **Purpose**: Generates reference reverse shell templates for penetration testing in authorized lab environments.
- **Syntax**:
  ```bash
  python swa_cli.py --revshell --shell-ip <LHOST> --shell-port <LPORT> [--shell-type <TYPE>]
  ```
- **Supported Shell Types**: `bash`, `python3`, `powershell`, `netcat_openbsd`, `all`

---

## 15. REA Reverse Engineering Engine

### API / Native Fallback
- **Purpose**: Disassembles and inspects authorized binary artifacts, extracting PE/ELF headers, imported functions, strings, and suspicious API indicators.
- **Endpoint**: `POST /api/rea/analyze` or `POST /api/rea/upload-analyze`
- **Supported Targets**: PE (`.exe`, `.dll`), ELF (`.so`, binaries), Python byte-code (`.pyc`), WebAssembly (`.wasm`), SQLite, JS, firmware.

---

## 16. Security Dataset Management & Sanitization

### REST API: `POST /api/datasets/upload`
- **Purpose**: Ingests, previews, and inspects security training datasets with automated credential leakage scanning (AWS keys, private certificates, JWTs).
- **Supported Formats**: CSV, JSONL, JSON, TXT.
- **Partitioning Endpoint**: `POST /api/datasets/{id}/split` (Train / Validation / Test partitions).

---

## 17. AI Model Training & Fine-Tuning Commands

### Hardware Auto-Detection: `GET /api/ai/hardware`
- **Purpose**: Discovers host compute capabilities (CUDA GPU, Apple Silicon MPS, CPU cores, RAM).

### Start Training: `POST /api/ai/training/start`
- **Payload**:
  ```json
  {
    "model_name": "swa-vuln-classifier-v1",
    "base_model": "security-roberta-base",
    "dataset_id": "ds_a1b2c3d4e5",
    "epochs": 3,
    "batch_size": 16,
    "learning_rate": 0.001
  }
  ```

---

## 18. AI Model Tuning & Benchmark Evaluation

### Evaluate Model: `POST /api/ai/evaluation/run`
- **Payload**:
  ```json
  {
    "model_name": "swa-vuln-classifier-v1",
    "baseline_model_name": "heuristic-baseline-v1",
    "task_type": "classification",
    "test_sample_count": 150
  }
  ```
- **Metrics Returned**: Precision, Recall, F1 score, Accuracy, 2x2 Confusion Matrix (`TP`, `FP`, `TN`, `FN`), Latency ms, Throughput, and Provider Cost estimate.

---

## 19. LLM Adversarial Red-Team & Security Testing

### Run 12-Category Suite: `POST /api/ai/redteam/run`
- **Payload**:
  ```json
  {
    "target_provider": "openai",
    "target_model": "gpt-4o"
  }
  ```
- **Threat Categories Covered**:
  1. Direct Prompt Injection
  2. Indirect Prompt Injection
  3. System Prompt Extraction
  4. Jailbreak Robustness
  5. Sensitive Data Disclosure
  6. Insecure Output Handling
  7. Excessive Agency & Tool Invocation
  8. RAG Poisoning & Retrieval Manipulation
  9. Training Data Leakage
  10. Unsafe Tool Permissions
  11. Denial of Service & Resource Exhaustion
  12. Auth Failures in AI Integrations

---

## 20. Unified Tool Catalog & Registry API

### Query Complete Catalog: `GET /api/tools/registry`
- **Purpose**: Returns schema, handler path, dependencies, timeout, and authorization scope for every implemented tool in the platform across SOC, Recon, WebSec, Blue-Team, and AI Security.
