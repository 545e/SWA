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
- **Expected Output**:
  ```text
  [+] Initializing autonomous red team against: http://127.0.0.1:8000
  [+] Scan Profile: lab_assessment
  [SUCCESS] Scope Verified: Explicit lab mode authorized: http://127.0.0.1:8000
  [INFO] Phase 1/5: Autonomous Reconnaissance & OSINT
  [SUCCESS] Target active: 127.0.0.1 [HTTP 200]
  [✓] Scan Completed Successfully!
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
  - `--export-subs <FILE>`: Saves output to `.txt` (hostlist) or `.json` (full asset objects).
- **Safe Example**:
  ```bash
  python swa_cli.py --subdomains example.com --export-subs example_subs.json
  ```
- **Expected Output**:
  ```text
  [+] Launching Autonomous Multi-Source Subdomain Intelligence on: example.com
  [i] Wildcard DNS check: No wildcard DNS detected.
  [✓] Subdomain Discovery Completed!
  [+] Total Discovered Assets: 4 | Live HTTP/S: 2 | Takeover Risks: 0

  SUBDOMAIN                              IP ADDRESS        STATUS   TITLE                          SOURCES
  -------------------------------------------------------------------------------------------------------------------
  example.com                            93.184.216.34     200      Example Domain                 ApexRoot,crt.sh
  www.example.com                        93.184.216.34     200      Example Domain                 crt.sh,ActiveDNS
  ```
- **Troubleshooting**: If rate-limited by crt.sh, the engine automatically falls back to regex HTML parsing and remaining passive feeds.

---

## 4. DNS, SPF & DMARC Email Security Analyzer

### `swa_cli.py --dns <DOMAIN>`
- **Purpose**: Queries A, AAAA, MX, TXT, NS, CNAME, SOA records and grades domain spoofing posture based on SPF and DMARC enforcement.
- **Prerequisites**: Standard outbound DNS access (UDP port 53).
- **Syntax**:
  ```bash
  python swa_cli.py --dns <DOMAIN>
  ```
- **Safe Example**:
  ```bash
  python swa_cli.py --dns google.com
  ```
- **Expected Output**:
  ```text
  [+] Resolving DNS records for: google.com
  [+] Records:
      A:     142.250.190.46
      MX:    smtp.google.com
  [+] Email Spoofing Defense: EXCELLENT
      SPF Record:   v=spf1 include:_netblocks.google.com ~all
      DMARC Record: v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com
  ```

---

## 5. HTTP Security Headers Evaluator

### `swa_cli.py --headers <URL>`
- **Purpose**: Evaluates 8 defensive HTTP response headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP) and outputs a letter grade from A+ to F.
- **Syntax**:
  ```bash
  python swa_cli.py --headers <URL>
  ```
- **Safe Example**:
  ```bash
  python swa_cli.py --headers https://127.0.0.1:8000
  ```
- **Expected Output**:
  ```text
  [+] Auditing HTTP security headers for: https://127.0.0.1:8000
  [+] Overall Grade: A (Score: 85/100)
  [+] Header Audit:
      [PASS] Strict-Transport-Security: max-age=31536000; includeSubDomains
      [PASS] X-Content-Type-Options: nosniff
      [PASS] X-Frame-Options: SAMEORIGIN
      [MISSING] Content-Security-Policy: Policy absent
  ```

---

## 6. SSL/TLS Certificate Deep Inspector

### `swa_cli.py --ssl <HOST>`
- **Purpose**: Performs TLS handshake, extracts certificate subject, issuer, SANs, cipher suite, active TLS version, and calculates days remaining until expiration.
- **Syntax**:
  ```bash
  python swa_cli.py --ssl <HOST> [--ssl-port <PORT>]
  ```
- **Safe Example**:
  ```bash
  python swa_cli.py --ssl github.com --ssl-port 443
  ```
- **Expected Output**:
  ```text
  [+] Inspecting SSL/TLS Certificate on github.com:443
  [+] Subject:           CN=github.com
  [+] Issuer:            DigiCert Global G2 TLS RSA SHA256 2020 CA1
  [+] Protocol:          TLSv1.3
  [+] Cipher:            TLS_AES_128_GCM_SHA256
  [+] Days to Expiry:    182 days
  ```

---

## 7. Asynchronous Port & Service Prober

### `swa_cli.py --ports <HOST>`
- **Purpose**: Asynchronously probes standard TCP service ports on the target host.
- **Syntax**:
  ```bash
  python swa_cli.py --ports <HOST> [--port-list <PORTS>]
  ```
- **Safe Example**:
  ```bash
  python swa_cli.py --ports 127.0.0.1 --port-list 80,443,8000,8080
  ```
- **Expected Output**:
  ```text
  [+] Probing ports on 127.0.0.1...
  [+] Open Port: 8000/TCP (HTTP) - Active
  ```

---

## 8. WHOIS & IP / ASN Threat Intelligence

### `swa_cli.py --whois <TARGET>`
- **Purpose**: Queries RDAP and IP threat registries to identify ASN, autonomous system owner, network block, and hosting country.
- **Syntax**:
  ```bash
  python swa_cli.py --whois <TARGET>
  ```
- **Safe Example**:
  ```bash
  python swa_cli.py --whois 1.1.1.1
  ```
- **Expected Output**:
  ```text
  [+] Querying RDAP / ASN intelligence for: 1.1.1.1
  [+] ASN:          AS13335
  [+] Organization: Cloudflare, Inc.
  [+] Country:      US
  ```

---

## 9. Targeted Single-Vector Vulnerability Probing

### `swa_cli.py --probe <URL> --probe-vuln <TYPE>`
- **Purpose**: Runs non-destructive, single-vector vulnerability validation on a target endpoint and parameter.
- **Supported Vulnerability Types**: `sqli`, `xss`, `lfi`, `ssrf`, `cors`, `redirect`
- **Syntax**:
  ```bash
  python swa_cli.py --probe <URL> --probe-vuln <TYPE> [--probe-param <PARAM>]
  ```
- **Safe Example**:
  ```bash
  python swa_cli.py --probe "http://127.0.0.1:8000/api/search?q=test" --probe-vuln xss --probe-param q
  ```
- **Expected Output**:
  ```text
  [+] Executing targeted XSS probe on: http://127.0.0.1:8000/api/search
  [✓] Probing Completed: No reflection vulnerability detected in parameter 'q'.
  ```

---

## 10. JavaScript Intelligence & Secret Scanner (GhostJS)

### `swa_cli.py --js-scan <URL>` / `--js-file <PATH>`
- **Purpose**: Inspects client-side JavaScript bundles and HTML documents for exposed secrets, cloud buckets, API routes, and source maps using 150+ high-entropy signatures.
- **Syntax**:
  ```bash
  python swa_cli.py --js-scan <URL> [--export-js <FILE>]
  python swa_cli.py --js-file <LOCAL_FILE> [--export-js <FILE>]
  ```
- **Safe Example**:
  ```bash
  python swa_cli.py --js-file web/static/app.js --export-js app_audit.json
  ```
- **Expected Output**:
  ```text
  [+] Scanning local JavaScript/HTML file: web/static/app.js
  [✓] JavaScript Intelligence Scan Completed!
  [+] Total Scanned Assets: 1
  [!] Discovered Secrets:   0 (Critical: 0, High: 0, Med: 0, Low: 0)
  [+] Discovered Endpoints: 24
  ```

---

## 11. Digital Forensics & Incident Response (DFIR)

### `swa_cli.py --forensics-sample <SCENARIO>` / `--forensics-log <FILE>`
- **Purpose**: Ingests web access logs (Nginx, Apache, Windows IIS), extracts attack footprints (SQLi, path traversal, webshell drops, scanners), correlates threat actors, and outputs firewall isolation commands.
- **Built-in Scenarios**: `apache_nginx`, `windows_iis`, `wordpress_brute`
- **Syntax**:
  ```bash
  python swa_cli.py --forensics-sample apache_nginx
  python swa_cli.py --forensics-log /var/log/nginx/access.log
  ```
- **Safe Example**:
  ```bash
  python swa_cli.py --forensics-sample apache_nginx
  ```
- **Expected Output**:
  ```text
  [+] Running forensic analysis on built-in scenario: apache_nginx
  [✓] Forensic Analysis Completed!
  [!] Threat Posture: CRITICAL - Active multi-vector exploit attempt detected
  [+] Attack Footprints Detected: 14
  [+] Top Threat Actor: 198.51.100.23 (8 incidents)
      Linux Block:   iptables -A INPUT -s 198.51.100.23 -j DROP
      Windows Block: netsh advfirewall firewall add rule name="Block-198.51.100.23" dir=in action=block remoteip=198.51.100.23
  ```

---

## 12. CIDR Subnet & IP Calculator

### `swa_cli.py --cidr <BLOCK>`
- **Purpose**: Computes network details, usable IP address ranges, broadcast addresses, and netmasks for IPv4/IPv6 CIDR blocks.
- **Syntax**:
  ```bash
  python swa_cli.py --cidr 192.168.1.0/24
  ```
- **Expected Output**:
  ```text
  [+] Subnet Calculation for: 192.168.1.0/24
      Network Address: 192.168.1.0
      Broadcast:       192.168.1.255
      Netmask:         255.255.255.0
      Usable Range:    192.168.1.1 - 192.168.1.254
      Usable Hosts:    254
      Private IP:      True
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
- **Safe Example**:
  ```bash
  python swa_cli.py --revshell --shell-ip 10.10.14.5 --shell-port 4444 --shell-type bash
  ```

---

## 15. REA Reverse Engineering Engine

### API / Native Fallback
- **Purpose**: Disassembles and inspects authorized binary artifacts, extracting PE/ELF headers, imported functions, strings, and suspicious API indicators.
- **Endpoint**: `POST /api/rea/analyze` or `POST /api/rea/upload-analyze`
- **Supported Targets**: PE (`.exe`, `.dll`), ELF (`.so`, binaries), Python byte-code (`.pyc`), WebAssembly (`.wasm`), firmware and raw shellcode.
