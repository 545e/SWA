# SWA AI — Centralized Cybersecurity Tool Inventory & Reference

This document provides a comprehensive reference for all cybersecurity tools integrated into the SWA AI platform, including installation instructions, verification procedures, safe command examples, and operating constraints.

---

## 1. Tool Matrix & Integration Status

| Tool | Category | Supported Platforms | Installation Status Check | Native SWA Fallback |
| :--- | :--- | :--- | :--- | :--- |
| **Nmap** | Network Discovery | Windows, Linux, macOS | `nmap --version` | Async TCP Prober + Banner Grabber |
| **Nuclei** | Web App Security | Windows, Linux, macOS | `nuclei -version` | 10 Modular OWASP Plugins |
| **OWASP ZAP** | Web App Security | Windows, Linux, macOS, Docker | `zap.sh -version` | Security Headers & Cookie Auditor |
| **SQLmap** | Specialist Pentesting | Windows, Linux, macOS | `sqlmap --version` | Targeted SQLi Prober (Safe Detection) |
| **Nikto** | Web App Security | Windows, Linux, macOS | `nikto -Version` | Tech Fingerprint & Exposed Route Scanner |
| **TShark** | Network Analysis | Windows, Linux, macOS | `tshark -v` | Async Network Diagnostic Engine |
| **Semgrep** | SAST & Code Security | Windows, Linux, macOS | `semgrep --version` | GhostJS Secret & AST Pattern Engine |
| **Bandit** | SAST (Python) | Windows, Linux, macOS | `bandit --version` | Dependency Manifest & Syntax Auditor |
| **Trivy** | Vulnerability Scanner | Windows, Linux, macOS | `trivy version` | Built-in Manifest Dependency Scanner |
| **Gitleaks** | Secret Detection | Windows, Linux, macOS | `gitleaks version` | GhostJS 150+ Secret Pattern Engine |
| **SWA Native**| Built-in Enterprise | Windows, Linux, macOS | Built-in Python 3.12 | Core Engine (Always Available) |

---

## 2. Tool Details & Safe Command Guidelines

### 1. Nmap Network Scanner
- **Purpose**: Network host discovery, port auditing, and service banner grabbing.
- **Install Commands**:
  - Windows: `choco install nmap`
  - Linux: `sudo apt-get install nmap`
- **Safe Command Example**:
  ```bash
  nmap -sV -T3 -Pn --open 127.0.0.1
  ```
- **Option Explanations**:
  - `-sV`: Attempts service and version banner identification.
  - `-T3`: Normal timing profile (avoids flooding networks or triggering DoS).
  - `-Pn`: Skips ICMP ping discovery and probes ports directly.
  - `--open`: Restricts output to confirmed open ports.

---

### 2. Nuclei Vulnerability Scanner
- **Purpose**: Fast, template-based security checks for CVEs and misconfigurations.
- **Install Commands**:
  - All: `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`
- **Safe Command Example**:
  ```bash
  nuclei -u http://127.0.0.1:8000 -tags cve,misconfig -severity low,medium,high -silent -jsonl
  ```
- **Option Explanations**:
  - `-u`: Specifies the target URL.
  - `-tags cve,misconfig`: Restricts scan to verified configuration flaws and published CVEs.
  - `-exclude-tags dos,fuzz,sqli-exploit`: Prevents disruptive testing.
  - `-jsonl`: Produces machine-readable JSON Lines records.

---

### 3. OWASP ZAP (Zed Attack Proxy)
- **Purpose**: Automated passive web application security baseline scanning.
- **Install Commands**:
  - Docker: `docker pull ghcr.io/zaproxy/zaproxy:stable`
- **Safe Command Example**:
  ```bash
  docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://juice-shop:3000
  ```
- **Option Explanations**:
  - `zap-baseline.py`: Runs non-intrusive passive baseline checks.
  - `-t`: Specifies approved target.

---

### 4. SQLmap (Lab Safe Mode)
- **Purpose**: Non-destructive SQL injection detection on authorized lab targets.
- **Install Commands**:
  - Python: `pip install sqlmap`
- **Safe Command Example**:
  ```bash
  sqlmap -u http://127.0.0.1:8000/api?id=1 --batch --level=1 --risk=1 --technique=BEUST
  ```
- **Safety Constraints**:
  - Strictly omits `--dump`, `--os-shell`, and destructive payloads.
  - Requires explicit `lab_mode=True` authorization.

---

### 5. Bandit Python Security Linter
- **Purpose**: Detects security flaws in Python source code (hardcoded secrets, SQL injection, shell execution).
- **Install Commands**:
  - Python: `pip install bandit`
- **Safe Command Example**:
  ```bash
  bandit -r ./src -f json -o bandit-report.json
  ```

---

### 6. Trivy Vulnerability & Misconfig Scanner
- **Purpose**: Scans project filesystems, dependency lockfiles, and container images for known vulnerabilities.
- **Install Commands**:
  - Windows: `choco install trivy`
  - Linux: `sudo apt-get install trivy`
- **Safe Command Example**:
  ```bash
  trivy fs --scanners vuln,misconfig .
  ```

---

### 7. Gitleaks Secret Scanner
- **Purpose**: Detects hardcoded API keys, tokens, and private keys in code and commit history.
- **Install Commands**:
  - Windows: `choco install gitleaks`
  - Linux: Download release binary from GitHub
- **Safe Command Example**:
  ```bash
  gitleaks detect --no-git -v
  ```

---

### 8. SWA AI Native Security Engines
- **Purpose**: High-speed, zero-dependency autonomous auditing suite pre-installed in the platform:
  - **OWASP Top 10 Suite**: Injection, Broken Access Control, Cryptographic Failures, SSRF, Insecure Design.
  - **GhostJS 150+ Secret Pattern Engine**: Regex and Shannon entropy secret auditing for client-side JavaScript bundles and source files.
  - **Dual-Baseline Fuzzer**: Anomaly-filtered path and parameter discovery.
  - **Defense Center**: Automated WAF (ModSecurity, Cloudflare, Nginx) and SIEM (Sigma, Splunk, Suricata) rule synthesis.
- **Safe Command Example**:
  ```bash
  py swa_cli.py -t http://127.0.0.1:8000 -p quick --lab-mode
  ```
