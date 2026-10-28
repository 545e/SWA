# SWA AI — Security Policy & Responsible Scope Controls

## 1. Scope Policy & Authorization Controls

SWA AI enforces strict scope protection on all assessments to prevent unauthorized scanning, lateral movement, and server-side request forgery (SSRF).

### Allowed Target Enforcement
- All target hostnames and IPs are validated by [`core/scope_policy.py`](file:///C:/Users/krish/.gemini/antigravity/scratch/swa-ai/core/scope_policy.py).
- Allowed scopes are configured in `config/targets.json`.
- Targets not present in the allowlist are refused with error code `TARGET_OUT_OF_SCOPE`.

### SSRF & Cloud Metadata Blocking
By default, SWA AI rejects any target resolving to:
1. **Loopback addresses**: `127.0.0.0/8`, `::1`
2. **RFC 1918 Private subnets**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
3. **Link-local addresses**: `169.254.0.0/16`, `fe80::/10`
4. **Cloud Metadata Services (IMDS)**:
   - AWS / GCP / Azure: `169.254.169.254`
   - AWS ECS: `169.254.170.2`
   - AWS IPv6: `fd00:ec2::254`

---

## 2. Authorized Lab Mode

Local assessment targets (`127.0.0.1`, `localhost`, PortSwigger labs, DVWA) require explicit **Lab Mode** authorization:

- **Web UI**: Check the `🧪 Lab Mode` checkbox under Scan Options.
- **REST API**: Pass `"lab_mode": true` in `POST /api/scans`.
- **CLI**: Pass `--lab-mode` flag in `swa_cli.py`.

Without explicit lab mode confirmation, local scans are rejected with HTTP 403:
```json
{
  "detail": "Target Scope Refusal: SSRF Protection: Target resolves to restricted address: 127.0.0.1. Enable Lab Mode for authorized local testing."
}
```

---

## 3. Subprocess Execution Security

All external tool integrations (Nmap, Nuclei, ZAP, SQLmap) follow strict safety guidelines:
1. Commands are passed strictly as immutable argument arrays (`['nmap', '-sV', ...]`).
2. Shell string interpolation (`shell=True`) with user input is forbidden to eliminate command injection.
3. Strict execution timeouts (40s - 60s) prevent resource exhaustion and hanging tasks.
4. Tool exit codes alone are never treated as proof of vulnerability without verifiable response evidence.

---

## 4. Responsible Use Policy

SWA AI is designed exclusively for authorized penetration testing, vulnerability assessments, DevSecOps pipeline automation, and educational cybersecurity research in isolated lab environments. Scanning systems without explicit written consent from the asset owner is illegal in many jurisdictions.
