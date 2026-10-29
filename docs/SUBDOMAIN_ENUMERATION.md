# SWA AI — Layered Subdomain Discovery & Asset Intelligence Engine

## 1. Architecture Overview
The SWA AI Subdomain Engine (`AmassSubdomainEngine`) implements a modular discovery and asset-mapping pipeline combining multi-feed passive OSINT, high-speed asynchronous DNS dictionary resolution, AltDNS contextual mutations, wildcard DNS mitigation, and automated CNAME takeover detection.

```
Target Domain (e.g. example.com)
  │
  ├── 1. Apex Domain Normalization (Public Suffix List extraction)
  │
  ├── 2. Wildcard DNS Baseline Detection (3 pseudo-random probes -> baseline IP isolation)
  │
  ├── 3. Concurrent Multi-Source Passive OSINT (10+ Feeds):
  │       ├── Certificate Transparency (crt.sh JSON + HTML regex fallback)
  │       ├── AlienVault OTX Passive DNS
  │       ├── HackerTarget Host Search
  │       ├── CertSpotter SSLMate CT API
  │       ├── Internet Archive Wayback Machine CDX API
  │       ├── ThreatMiner Threat Intelligence
  │       ├── URLScan.io Global Scan Index
  │       ├── Subdomain Center API
  │       ├── Anubis DB Threat Intelligence
  │       ├── RapidDNS Search
  │       ├── Native OWASP Amass CLI bridge (auto-detected)
  │       └── Native Subfinder CLI bridge (auto-detected)
  │
  ├── 4. Active High-Yield DNS Dictionary Resolution (350+ cloud & microservices wordlist)
  │
  ├── 5. AltDNS Contextual Alteration & Environment Permutation Matrix
  │
  ├── 6. Recursive Multi-Tier Mining (Depth 2 under corp, dev, stage, api)
  │
  ├── 7. Deep Resolution & Alive Probing:
  │       ├── DNS Querying: A, AAAA, and CNAME alias chains
  │       ├── HTTP / HTTPS Alive Probing & HTML <title> extraction
  │       └── Subdomain Takeover Analysis (17+ cloud providers)
  │
  └── 8. Persistent Asset Inventory Storage (SQLite assets table & API export)
```

---

## 2. Why Zero Subdomain Discovery Occurred & How It Was Resolved
Original subdomain enumeration returned zero results or missed subdomains due to:
1. **Blocking DNS Calls:** Reliance on synchronous `socket.gethostbyname` which blocked on non-resolving names, exhausting worker pools on large discovery lists.
2. **Wildcard DNS Collisions:** Wildcard zones (*.target.com) returning identical IP addresses for any arbitrary hostname, flooding asset lists with false positives or causing premature filtering.
3. **Single Point of Failure in Passive Feeds:** If `crt.sh` timed out or returned HTTP 504, the entire passive pipeline failed without fallback.

### SWA AI Engineering Solution:
- **Async dnspython AsyncResolver:** Non-blocking asynchronous DNS queries with fallback to public nameservers (`1.1.1.1`, `8.8.8.8`).
- **Bounded Concurrency:** `asyncio.Semaphore(concurrency)` prevents socket exhaustion and rate limits.
- **Fail-Safe Gather:** `asyncio.gather(*tasks, return_exceptions=True)` guarantees that failure of any individual feed does not disrupt remaining sources.
- **HTML Fallback for CT Logs:** If `crt.sh` JSON endpoint fails, the HTML endpoint is scraped using regex.
- **Strict Wildcard Baseline Detection:** Non-existent random hostnames (`swa-wc-{uuid}.domain.com`) are queried first to detect wildcard IPs. Subsequent hits matching the wildcard IP baseline are filtered from false-positive bloat.
- **TTL Cache:** In-memory caching prevents repeated network roundtrips for previously resolved hosts.

---

## 3. Subdomain Takeover Detection

The engine inspects CNAME chains against signatures for 17 major cloud and SaaS providers:
- **GitHub Pages:** `github.io` (`There isn't a GitHub Pages site here`)
- **Amazon S3:** `s3.amazonaws.com` (`NoSuchBucket`)
- **Heroku:** `herokuapp.com` (`No such app`)
- **Microsoft Azure:** `azurewebsites.net`, `cloudapp.net` (`404 Web Site not found`)
- **Amazon CloudFront:** `cloudfront.net` (`The request could not be satisfied`)
- **Fastly:** `fastly.net` (`Fastly error: unknown domain`)
- **Shopify, Zendesk, Pantheon, Surge.sh, Ghost, Bitbucket, Netlify, Readme.io, WordPress, GitLab Pages, Firebase Hosting**.

When a dangling CNAME record matches an unclaimed cloud resource signature, a **CRITICAL** finding is immediately generated with reproduction steps and remediation zone files.

---

## 4. API & CLI Usage

### REST API:
```bash
curl -X POST http://127.0.0.1:8000/api/tools/subdomains \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "passive_only": false, "concurrency": 20}'
```

### Response Schema:
```json
{
  "domain": "example.com",
  "apex_domain": "example.com",
  "count": 14,
  "discovered_count": 22,
  "resolved_count": 14,
  "wildcard_filtered_count": 0,
  "failed_resolution_count": 8,
  "live_count": 12,
  "wildcard_detected": false,
  "takeover_count": 0,
  "subdomains": [
    {
      "subdomain": "api.example.com",
      "ip": "93.184.216.34",
      "status": 200,
      "http_responsive": true,
      "dns_confirmed": true,
      "validation_status": "confirmed",
      "title": "Example API Gateway",
      "sources": ["crt.sh", "ActiveDNS"],
      "takeover_risk": false
    }
  ]
}
```
