# SWA AI — API Security & Defensive Controls

## 1. Threat Model & Security Posture
SWA AI functions as an autonomous enterprise offensive and defensive cybersecurity platform. Operating against potentially hostile web applications, cloud infrastructure, and internal networks necessitates stringent defensive controls embedded directly into the API runtime.

---

## 2. Server-Side Request Forgery (SSRF) Protection

### Scope Validation Engine (`core/scope_policy.py`)
Every assessment request, targeted tool run, and PoC verification is strictly evaluated prior to dispatch:
1. **Scheme Validation**: Enforces `http://` or `https://`. Blocks dangerous schemes including `file://`, `gopher://`, `dict://`, and `ftp://`.
2. **DNS Resolution & Rebind Defense**: Target hostnames are resolved to actual IP addresses before execution.
3. **Restricted IP Filtering**:
   - `169.254.169.254` (AWS, GCP, Azure Instance Metadata Services) — **Strictly Blocked**
   - `127.0.0.0/8`, `::1` (Loopback Interfaces) — **Blocked unless explicit Authorized Lab Mode is active**
   - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918 Private Subnets) — **Blocked unless Lab Mode is active**
   - `0.0.0.0`, `255.255.255.255` — **Strictly Blocked**

### Target Scope Dynamic Authorization
Valid public internet targets (e.g. `starasia.org`, `target-enterprise.com`) entered by operators are safely verified and dynamically authorized into `config/targets.json`, preventing false-positive scope lockouts while preserving strict network boundaries.

---

## 3. Cryptographic Secret Management & Redaction

### AES-256 Vault (`core/credentials.py`)
- Third-party API keys (OpenAI, Anthropic, VirusTotal, CrowdStrike, AWS, etc.) are encrypted at rest using Fernet symmetric encryption.
- Encryption keys derive from environment variables or persistent cryptographic keyfiles with strict filesystem permissions (0600).

### Active Secret Redaction
All outgoing API responses, log feeds, and reports pass through automated redaction pipelines:
- Regex redaction of Bearer tokens, private keys, AWS secrets, and database passwords (`[REDACTED_SECRET]`).
- Masking of stored credential fields: `sk-ant-api03-***...***abcd`.

---

## 4. Rate Limiting & Denial-of-Service Defense
- **Token Bucket Rate Limiting (`TokenBucketRateLimiter`)**: Configurable per-IP rate limits with burst allowance (default 120 req/min).
- **Graceful Backoff**: Exceeded thresholds return HTTP `429 Too Many Requests` with `Retry-After` headers.
- **Max Execution Timeouts**: Background scans enforce bounded runtime boundaries (default 600s).

---

## 5. HTTP Security Headers
All API responses automatically carry OWASP-recommended security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy: default-src 'self' ...`
