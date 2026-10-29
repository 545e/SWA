# SWA AI — Troubleshooting & Diagnostics Guide

## 1. Subdomain Discovery Returns Zero Results

### Symptoms:
Running a scan or `/api/tools/subdomains` returns empty host lists or only the root domain.

### Diagnostic Steps & Solutions:
1. **Target is an IP Address:** Subdomain enumeration is intentionally skipped for raw IPv4/IPv6 addresses (e.g. `127.0.0.1` or `192.168.1.1`). Pass an apex domain name instead (e.g. `example.com`).
2. **DNS Resolver Timeout:** By default, SWA AI uses fallback nameservers (`1.1.1.1`, `8.8.8.8`). If your local network or firewall blocks outbound UDP/TCP port 53 to public resolvers, configure custom internal DNS servers in `.env` (`SWA_DNS_RESOLVERS=10.0.0.2,10.0.0.3`).
3. **Passive Provider Rate Limits:** If third-party APIs (such as `crt.sh` or `hackertarget`) rate-limit requests, SWA AI automatically falls back to regex HTML scraping and the local 350+ dictionary brute-force engine. Check logs for provider warnings.
4. **Wildcard DNS:** If the target zone has wildcard DNS (`*.target.com`), SWA AI verifies the baseline IP and suppresses wildcard false positives to protect asset inventory fidelity.

---

## 2. Windows Subprocess Pipe Buffering / Test Runner Hang

### Symptoms:
The web server or test runner hangs when executing `run.py` or running long scans.

### Root Cause:
If Python subprocesses write logs to standard output faster than an unmonitored OS pipe buffer can drain, the OS blocks the process.

### Solution:
When automating SWA AI via scripts, redirect stdout/stderr to `subprocess.DEVNULL` or launch background workers with explicit pipe reading threads.

---

## 3. "Target Scope Refusal: Loopback and Private Networks Blocked"

### Symptoms:
Submitting a scan against `http://127.0.0.1:8000`, `localhost`, or private RFC-1918 IPs (`10.0.0.0/8`, `192.168.0.0/16`) returns HTTP 403 Forbidden.

### Root Cause:
SWA AI incorporates an active SSRF Guard that prevents unauthorized probing of internal networks or cloud metadata services (`169.254.169.254`).

### Solution:
Set `lab_mode=true` in the scan configuration or select the **Authorized Lab Assessment** (`lab_assessment`) profile to explicitly authorize internal testing.

---

## 4. Port Conflict on Startup (`Port 8000 in use`)

### Symptoms:
`run.py` warns that port 8000 is occupied.

### Solution:
SWA AI includes an automatic port negotiation helper `find_available_port(8000)`. If port 8000 is occupied by another process, SWA AI automatically switches to the next available port (e.g. 8001, 8002) and prints the active listening URL in the terminal.

To force a specific port, set the environment variable:
```bash
export SWA_PORT=8888
python run.py
```

---

## 5. Model Training Fails with Dataset Error

### Symptoms:
Model training rejects the job with `Referenced dataset ID does not exist` or `Invalid schema`.

### Solution:
Ensure the dataset was uploaded via **AI Datasets** (`/api/datasets/upload`) and contains at least 5 valid records with text and label columns. Review leakage warnings if the dataset contains unredacted credentials.
