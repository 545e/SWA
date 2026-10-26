"""
SWA AI — Autonomous JavaScript Intelligence & GhostJS Secret Scanner
Autonomous engine for detecting hardcoded API keys, tokens, credentials,
cloud object-storage buckets, and hidden REST/GraphQL endpoints in JavaScript,
HTML, and JSON responses.

Features:
- 150+ Enterprise Secret Detection Signatures across 23 categories
- Shannon Entropy & Multi-Stage False-Positive Suppression
- Endpoint & Cloud Storage Discovery (AWS S3, Google GCS, Azure Blob, Cloudflare R2)
- Source Map (.map) Leakage & Attack Surface Expansion
- Active JS Bundle Fetcher with concurrent asynchronous resolution
"""

import asyncio
import datetime
import html
import json
import math
import os
import re
from typing import Dict, List, Any, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin
import httpx

from core.models import VulnerabilityFinding, Severity

# =====================================================================
# 1. Shannon Entropy & False-Positive Filter
# =====================================================================
class ShannonEntropyFilter:
    KNOWN_EXAMPLE_VALUES = {
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "ASIAIOSFODNN7EXAMPLE",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    }
    
    KNOWN_EXAMPLE_FRAGMENTS = [
        "EXAMPLEKEY",
        "AKIAIOSFODNN7EXAMPLE",
        "0000000000000000",
        "1111111111111111",
        "XXXXXXXXXXXX",
        "YOUR_KEY_HERE",
        "REPLACE_ME",
    ]

    PUBLIC_BY_DESIGN = [
        re.compile(r"^pk_(?:live|test)_[A-Za-z0-9]{8,}$"),
        re.compile(r"^6L[0-9A-Za-z_-]{38}$"),
        re.compile(r"^p(?:k|ub)_[A-Za-z0-9]{8,}$"),
    ]

    COMMON_FP = [
        re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE),
        re.compile(r"^0{20,}$"),
        re.compile(r"^1{20,}$"),
        re.compile(r"^a{20,}$", re.IGNORECASE),
        re.compile(r"^x{10,}$", re.IGNORECASE),
        re.compile(r"^(?:abc|123|test|demo|example|sample|default|changeme|password|secret|admin)", re.IGNORECASE),
        re.compile(r"^(?:undefined|null|none|empty|todo|fixme|placeholder|insert|your)", re.IGNORECASE),
        re.compile(r"^[A-Za-z]+_[A-Za-z]+_[A-Za-z]+$"),
        re.compile(r"^[a-z]{2,}(?:-[a-z]{2,}){1,}$"),
        re.compile(r"^https?://(?:localhost|127\.0\.0\.|0\.0\.0\.0)", re.IGNORECASE),
        re.compile(r"^[a-z]+=[0-9a-f]{32}$", re.IGNORECASE),
        re.compile(r"^(?:session|cookie|token|csrf|nonce|hash|sid|id)=", re.IGNORECASE),
    ]

    HEX32_EXEMPT_NAMES = {
        "Subscription / Access Key", "Algolia Admin API Key", "Twilio Auth Token",
        "Datadog API Key", "Facebook App Secret", "Agora App Certificate",
        "Rollbar Access Token", "Bugsnag API Key", "Fastly API Token", "Plaid Client Secret"
    }

    PLACEHOLDER_MARKERS = [
        "example", "sample", "placeholder", "your_", "yourkey", "your-key",
        "changeme", "change_me", "redacted", "dummy", "test_key", "testkey",
        "lorem", "foobar", "insert_your", "replace_with", "somekey", "fakekey",
        "notreal", "<your", "enter_your", "xxxxx"
    ]

    SLASH_PATH = re.compile(r"^/[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)+$")

    COMMON_WORDS = {
        "the", "a", "an", "is", "are", "was", "were", "be", "been", "being", "have", "has",
        "had", "do", "does", "did", "will", "would", "could", "should", "may", "might",
        "shall", "can", "to", "of", "in", "for", "on", "with", "at", "by", "from", "as",
        "into", "through", "please", "enter", "type", "input", "provide", "must", "field",
        "required", "your", "my", "this", "that", "these", "those", "it", "you", "we",
        "and", "or", "if", "not", "no", "all", "each", "some", "click", "here", "select"
    }

    @staticmethod
    def shannon_entropy(s: str) -> float:
        """Calculates Shannon entropy in bits per character."""
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = len(s)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * (math.log2(p))
        return entropy

    @classmethod
    def is_likely_false_positive(cls, value: str, secret_name: str, min_entropy: float = 0.0) -> bool:
        if not value:
            return True
        v = value.strip()
        if len(v) < 6:
            return True

        # Known example credentials
        if v in cls.KNOWN_EXAMPLE_VALUES:
            return True
        for frag in cls.KNOWN_EXAMPLE_FRAGMENTS:
            if frag in v:
                return True

        # Public by design keys (except Klaviyo private key)
        if secret_name != "Klaviyo Private Key":
            for p in cls.PUBLIC_BY_DESIGN:
                if p.search(v):
                    return True

        # Generic FP patterns
        hex32_exempt = secret_name in cls.HEX32_EXEMPT_NAMES
        for p in cls.COMMON_FP:
            if hex32_exempt and p.pattern == "^[0-9a-f]{32}$":
                continue
            if p.search(v):
                return True

        lower = v.lower()
        if any(marker in lower for marker in ["${", "{{", "%s", "process.env", "import.meta"]):
            return True
        if re.search(r"<[a-zA-Z_]+>", v):
            return True
        for marker in cls.PLACEHOLDER_MARKERS:
            if marker in lower:
                return True

        # Low-variety junk
        if len(v) > 10 and len(set(v)) <= 3:
            return True
        
        # Base Shannon check
        ent = cls.shannon_entropy(v)
        if len(v) >= 16 and ent < 2.0:
            return True

        # Natural language multi-word check
        words = v.split()
        if len(words) >= 4:
            common = sum(1 for w in words if w.lower() in cls.COMMON_WORDS)
            if common / len(words) >= 0.4:
                return True

        # Slash path is an endpoint, not a credential
        if cls.SLASH_PATH.search(v):
            return True

        # Tightened entropy check if specified
        if min_entropy > 0.0:
            if re.search(r"\s", v):
                return True
            core = re.sub(r"^['\"`]+|['\"`]+$", "", v)
            if "_" in core:
                core = core.split("_")[-1]
            if len(core) >= 12 and cls.shannon_entropy(core) < min_entropy:
                return True

        return False


# =====================================================================
# 2. Endpoint & Cloud Storage Extractor
# =====================================================================
class EndpointAndStorageExtractor:
    API_PATH_PATTERN = re.compile(
        r"""["'`]((?:/(?:api|v\d+|rest|graphql|gql|internal|admin|oauth|auth|user|users|account|payment|webhook))[A-Za-z0-9_\-/.{}:]*)["'`]"""
    )

    CLOUD_STORAGE_PATTERN = re.compile(
        r"https?://[A-Za-z0-9.\-]*(?:"
        r"s3[.\-][A-Za-z0-9.\-]*amazonaws\.com|"
        r"[A-Za-z0-9.\-]*\.s3\.amazonaws\.com|"
        r"storage\.googleapis\.com|"
        r"[A-Za-z0-9.\-]*\.blob\.core\.windows\.net|"
        r"[A-Za-z0-9.\-]*\.r2\.cloudflarestorage\.com|"
        r"[A-Za-z0-9.\-]*\.digitaloceanspaces\.com"
        r")(?:/[A-Za-z0-9_\-/.%]*)?",
        re.IGNORECASE
    )

    SOURCE_MAP_PATTERN = re.compile(
        r"""//[#@]\s*sourceMappingURL=([^\s'"]+)"""
    )

    @classmethod
    def extract_endpoints_and_assets(cls, body: str, base_url: str = "") -> Dict[str, List[Dict[str, Any]]]:
        results = {
            "api_endpoints": [],
            "cloud_storage": [],
            "source_maps": [],
        }
        if not body:
            return results

        # Cloud storage URLs
        seen_cloud = set()
        for m in cls.CLOUD_STORAGE_PATTERN.finditer(body):
            url = m.group(0).strip()
            if url not in seen_cloud:
                seen_cloud.add(url)
                results["cloud_storage"].append({
                    "url": url,
                    "provider": cls._classify_provider(url),
                    "found_in": base_url or "inline"
                })

        # Source map references
        seen_maps = set()
        for m in cls.SOURCE_MAP_PATTERN.finditer(body):
            ref = m.group(1).strip()
            if ref not in seen_maps:
                seen_maps.add(ref)
                full_map_url = urljoin(base_url, ref) if base_url else ref
                results["source_maps"].append({
                    "reference": ref,
                    "resolved_url": full_map_url,
                    "found_in": base_url or "inline"
                })

        # API endpoints
        seen_paths = set()
        for m in cls.API_PATH_PATTERN.finditer(body):
            path = m.group(1).strip()
            if path not in seen_paths and len(path) > 3:
                seen_paths.add(path)
                full_endpoint = urljoin(base_url, path) if base_url else path
                results["api_endpoints"].append({
                    "path": path,
                    "resolved_url": full_endpoint,
                    "found_in": base_url or "inline"
                })

        return results

    @staticmethod
    def _classify_provider(url: str) -> str:
        u = url.lower()
        if "amazonaws.com" in u:
            return "AWS S3"
        elif "storage.googleapis.com" in u:
            return "Google Cloud Storage"
        elif "blob.core.windows.net" in u:
            return "Azure Blob Storage"
        elif "cloudflarestorage.com" in u:
            return "Cloudflare R2"
        elif "digitaloceanspaces.com" in u:
            return "DigitalOcean Spaces"
        return "Cloud Storage"


# =====================================================================
# 3. 150+ Enterprise Secret Detection Patterns
# =====================================================================
GHOSTJS_RAW_PATTERNS = [
    {
        'name': "AWS Access Key",
        'category': "Cloud Secrets",
        'regex': "(?<![A-Za-z0-9/+=])(AKIA[0-9A-Z]{16})(?![A-Za-z0-9/+=])",
        'flags': "g",
        'severity': "critical",
        'confidence': 95,
        'impact': "Leaked AWS access key ID enables programmatic access to the associated AWS account. Depending on the IAM policy attached, an attacker can enumerate S3 buckets, read sensitive objects, spin up EC2 instances, exfiltrate RDS snapshots, or pivot through linked services. Pair with the corresponding secret key for full exploitation. Immediate key rotation and CloudTrail audit are necessary.",
        'remediation': "1. Immediately rotate the AWS access key in IAM console\\n2. Revoke the exposed key\\n3. Audit CloudTrail logs for unauthorized access\\n4. Use AWS Secrets Manager or environment variables instead of hardcoding",
    },
    {
        'name': "AWS Secret Access Key",
        'category': "Cloud Secrets",
        'regex': "(?:aws[_\\\\s-]?secret[_\\\\s-]?(?:access[_\\\\s-]?)?key|secret[_\\\\s-]?access[_\\\\s-]?key|aws[_\\\\s-]?secret)\\\\s*[=:\\\"']\\\\s*[\\\"']?([A-Za-z0-9\\\\/+]{38,40}={0,2})[\\\"']?",
        'flags': "gi",
        'severity': "critical",
        'confidence': 80,
        'impact': "Exposed AWS secret access key completes the credential pair required for authenticated API calls. With the corresponding access key ID, an attacker gains the same permissions as the IAM entity \u2014 ranging from read-only data access to full administrative control. This is directly exploitable without any additional authentication factor.",
        'remediation': "1. Rotate the key pair immediately\\n2. Use IAM roles instead of long-term credentials\\n3. Store secrets in AWS Secrets Manager",
    },
    {
        'name': "AWS Session Token",
        'category': "Cloud Secrets",
        'regex': "(?<![A-Za-z0-9\\\\/+=])(ASIA[0-9A-Z]{16})(?![A-Za-z0-9\\\\/+=])",
        'flags': "g",
        'severity': "critical",
        'confidence': 95,
        'impact': "Temporary AWS session credential (STS-issued) provides time-limited access to AWS resources under an assumed role. While the window is finite, an attacker who captures this before expiry inherits the full permission set of the assumed role. Check the associated role's trust policy and CloudTrail for unauthorized AssumeRole calls.",
        'remediation': "1. Wait for token expiration or invalidate the session\\n2. Review IAM policies for the assumed role\\n3. Check CloudTrail for any unauthorized actions",
    },
    {
        'name': "Firebase Configuration Block",
        'category': "Cloud Secrets",
        'regex': "(?:firebaseConfig[\\\\s]*[=:{]|(?:firebase\\\\.)?initializeApp\\\\s*\\\\()[\\\\s\\\\S]{0,500}?apiKey[\\\\s]*[=:]\\\\s*[\\\"']([A-Za-z0-9_\\\\-]{20,})[\\\"'][\\\\s\\\\S]{0,1500}?(?:messagingSenderId|storageBucket|authDomain|databaseURL|projectId)[\\\\s]*[=:]\\\\s*[\\\"'][^\\\"']+[\\\"']",
        'flags': "gi",
        'severity': "medium",
        'confidence': 85,
        'impact': "Complete Firebase configuration block exposed in JavaScript. While Firebase API keys are designed for client use, the full configuration (apiKey, authDomain, databaseURL, projectId, messagingSenderId) combined with misconfigured Firebase Security Rules enables direct Firestore/Realtime Database read/write, Cloud Storage access, user enumeration via Firebase Auth, and abuse of Firebase Cloud Messaging.",
        'remediation': "1. Audit and tighten Firebase Security Rules for Firestore, Realtime Database, and Storage\\n2. Enable Firebase App Check to restrict API access to verified apps\\n3. Restrict the API key in Google Cloud Console to only required APIs\\n4. Review Firebase Authentication settings and disable unused sign-in providers",
    },
    {
        'name': "Google API Key",
        'category': "Cloud Secrets",
        'regex': "AIza[0-9A-Za-z\\\\-_]{35}",
        'flags': "g",
        'severity': "low",
        'confidence': 90,
        'impact': "Unrestricted Google API key can be abused to consume quota-billed services (Maps, Places, Translate) under the owner's billing account. If the key lacks referrer or API restrictions, attackers can also probe enabled APIs for data exposure \u2014 including Firestore, BigQuery, or Cloud Functions \u2014 depending on project configuration.",
        'remediation': "1. Restrict the API key to specific APIs and referrers\\n2. Rotate the key in Google Cloud Console\\n3. Use service accounts instead of API keys for server-side access",
    },
    {
        'name': "Google OAuth Client Secret",
        'category': "Cloud Secrets",
        'regex': "GOCSPX-[A-Za-z0-9_-]{28}",
        'flags': "g",
        'severity': "critical",
        'confidence': 95,
        'impact': "With the OAuth client secret, an attacker can forge authorization callbacks, exchange intercepted auth codes for access tokens, and impersonate the application to harvest user data. This breaks the trust boundary of the OAuth flow and can lead to account takeover for any user who has authorized the application.",
        'remediation': "1. Regenerate the OAuth client secret immediately\\n2. Store secrets server-side only\\n3. Review OAuth consent screen and scopes",
    },
    {
        'name': "Firebase Private Key",
        'category': "Cloud Secrets",
        'regex': "-----BEGIN PRIVATE KEY-----[\\\\s\\\\S]*?-----END PRIVATE KEY-----",
        'flags': "g",
        'severity': "critical",
        'confidence': 95,
        'impact': "Exposed PEM-encoded private key compromises the identity of the service it authenticates \u2014 whether Firebase Admin SDK, a TLS certificate, or a service account. An attacker can sign arbitrary tokens, impersonate the service to downstream APIs, decrypt intercepted traffic if the key is used for TLS, and establish persistent backdoor access.",
        'remediation': "1. Revoke and regenerate the private key immediately\\n2. Audit all actions performed with this key\\n3. Use a secrets manager for key storage",
    },
    {
        'name': "Stripe Live Secret Key",
        'category': "Payment & Financial Secrets",
        'regex': "sk_live_[A-Za-z0-9]{20,}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "Live Stripe secret key provides unrestricted access to the payment infrastructure: create charges against any saved payment method, issue refunds to attacker-controlled accounts, export full customer PII and card fingerprints, and modify webhook endpoints to intercept transaction data. Direct financial loss is immediate and measurable.",
        'remediation': "1. Roll the API key in Stripe Dashboard immediately\\n2. Review recent transactions for unauthorized activity\\n3. Never expose secret keys in client-side code",
    },
    {
        'name': "Stripe Restricted Key",
        'category': "Payment & Financial Secrets",
        'regex': "rk_live_[A-Za-z0-9]{20,}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "Restricted Stripe key operating in live mode grants scoped but production-level access. The actual blast radius depends on the permissions assigned \u2014 which could include reading customer records, creating payment intents, or managing subscriptions. The key should be treated as compromised regardless of scope since permission boundaries are not visible to external parties.",
        'remediation': "1. Delete and recreate the restricted key\\n2. Review permissions assigned to this key\\n3. Audit recent API calls",
    },
    {
        'name': "Razorpay Publishable Key ID",
        'category': "Payment & Financial Secrets",
        'regex': "rzp_live_[A-Za-z0-9]{14,}",
        'flags': "g",
        'severity': "info",
        'confidence': 85,
        'impact': "This is a Razorpay PUBLISHABLE Key ID (the `rzp_live_` value) \u2014 public by design. It ships in client-side checkout code to identify the merchant account and is NOT the Key Secret. On its own it cannot capture payments, issue refunds, or read transaction data \u2014 those require the separate, server-side Key SECRET. No action is needed unless the Key Secret is also exposed.",
        'remediation': "1. No action required for the publishable Key ID alone \u2014 it is meant to be public.\\n2. Ensure the paired Key SECRET never appears in client-side code (server-side only).\\n3. If a Key Secret has leaked, rotate the key pair in the Razorpay Dashboard.",
    },
    {
        'name': "PayPal Secret",
        'category': "Payment & Financial Secrets",
        'regex': "(?:paypal|PAYPAL)[\\\\s_-]*(?:secret|SECRET|key|KEY)[\\\\s:=\\\"']*([A-Za-z0-9_-]{20,})",
        'flags': "g",
        'severity': "critical",
        'confidence': 75,
        'impact': "PayPal API credentials grant the ability to execute transactions, initiate mass payouts, issue refunds, and query account balances and transaction history. An attacker can siphon funds through crafted payment requests or extract customer financial data. The merchant account holder faces direct monetary loss and regulatory exposure.",
        'remediation': "1. Regenerate PayPal API credentials\\n2. Review recent transactions\\n3. Enable PayPal notifications for suspicious activity",
    },
    {
        'name': "GitHub Personal Access Token",
        'category': "Source Control Tokens",
        'regex': "ghp_[A-Za-z0-9]{36}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "Classic GitHub PAT inherits all scopes granted at creation \u2014 commonly repo (full private repo access), admin:org, and write:packages. An attacker can clone private repositories, inject backdoors into CI/CD workflows, read organization secrets, and push malicious commits. Supply chain compromise is the primary escalation vector.",
        'remediation': "1. Revoke the token on GitHub immediately\\n2. Audit repository access logs\\n3. Use fine-grained tokens with minimal scopes",
    },
    {
        'name': "GitHub Fine-Grained PAT",
        'category': "Source Control Tokens",
        'regex': "github_pat_[A-Za-z0-9_]{82}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "Fine-grained GitHub PAT is scoped to specific repositories and permission sets, but the exact access boundary is opaque externally. At minimum, an attacker gains read access to targeted repos. If write permissions are included, they can modify code, tamper with Actions workflows, or exfiltrate repository secrets through crafted workflow dispatches.",
        'remediation': "1. Revoke the token on GitHub\\n2. Review assigned permissions\\n3. Rotate and limit token lifetime",
    },
    {
        'name': "GitLab Personal Access Token",
        'category': "Source Control Tokens",
        'regex': "glpat-[A-Za-z0-9\\\\-_]{20,}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "GitLab PAT can provide API-level access to repositories, CI/CD pipeline configurations, container registries, and project variables (which often contain deployment secrets). An attacker can exfiltrate source code, inject pipeline stages to execute arbitrary commands on runners, or extract secrets stored in CI/CD variables.",
        'remediation': "1. Revoke the token in GitLab settings\\n2. Review access logs\\n3. Use project-scoped tokens instead",
    },
    {
        'name': "Bitbucket Token",
        'category': "Source Control Tokens",
        'regex': "(?:bitbucket|BITBUCKET)[\\\\s_-]*(?:token|TOKEN|secret|SECRET)[\\\\s:=\\\"']*([A-Za-z0-9_-]{20,})",
        'flags': "g",
        'severity': "high",
        'confidence': 65,
        'impact': "Bitbucket app password or token grants access to repositories and Bitbucket Pipelines. An attacker can read private source code, modify pipeline configurations to inject malicious build steps, and access pipeline environment variables that may contain deployment credentials or cloud provider secrets.",
        'remediation': "1. Revoke the app password or token\\n2. Review repository access\\n3. Use OAuth instead of static tokens",
    },
    {
        'name': "Hardcoded Bearer Token",
        'category': "API & Auth Secrets",
        'regex': "[\\\"']Bearer\\\\s+([A-Za-z0-9._~+\\\\/=-]{20,})[\\\"']",
        'flags': "g",
        'severity': "high",
        'confidence': 85,
        'impact': "Bearer token embedded in client-side JavaScript can be extracted and replayed against the target API. The attacker assumes the identity and permissions of the token holder \u2014 whether a service account or end user \u2014 enabling unauthorized data access, state mutation, or privilege escalation depending on the API's authorization model.",
        'remediation': "1. Invalidate the token\\n2. Use dynamic token generation\\n3. Store tokens in secure server-side storage",
    },
    {
        'name': "Hardcoded Authorization Header",
        'category': "API & Auth Secrets",
        'regex': "[\\\"'](?:Authorization|authorization)[\\\"']\\\\s*:\\\\s*[\\\"'](?:Bearer|Basic|Token)\\\\s+([A-Za-z0-9._~+\\\\/=-]{10,})[\\\"']",
        'flags': "g",
        'severity': "high",
        'confidence': 90,
        'impact': "Static authorization header in client code is directly replayable. Whether it contains a Bearer token, Basic credentials, or custom auth scheme, an attacker can copy the header value and issue authenticated requests against the API with no additional effort. This bypasses any client-side access controls entirely.",
        'remediation': "1. Remove hardcoded auth headers\\n2. Use environment variables or a secrets manager\\n3. Implement proper auth token flow",
    },
    {
        'name': "Hardcoded JWT Token",
        'category': "API & Auth Secrets",
        'regex': "eyJ[A-Za-z0-9_-]{10,}\\\\.eyJ[A-Za-z0-9_-]{10,}\\\\.[A-Za-z0-9_-]{10,}",
        'flags': "g",
        'severity': "medium",
        'confidence': 80,
        'impact': "Hardcoded JWT in client code may still be valid if the signing key has not been rotated. The token payload typically reveals user identity, roles, and expiration. An attacker can decode claims to map internal user structures, and if unexpired, replay the token to authenticate as the embedded identity against any service that trusts the issuer.",
        'remediation': "1. Invalidate the JWT by rotating signing keys\\n2. Never hardcode tokens in JavaScript\\n3. Use short-lived tokens with refresh mechanism",
    },
    {
        'name': "Hardcoded API Key",
        'category': "API & Auth Secrets",
        'regex': "(?:api[_-]?key|apikey|api[_-]?secret)[\\\\s]*[=:]\\\\s*[\\\"']([A-Za-z0-9_\\\\-]{20,})[\\\"']",
        'flags': "gi",
        'severity': "high",
        'confidence': 75,
        'impact': "Generic API key hardcoded in JavaScript is extractable by any visitor. The impact scales with the service it authenticates against \u2014 ranging from quota abuse and billing fraud to full data access. Without knowing the target service's authorization model, this should be treated as a high-severity credential leak requiring immediate rotation.",
        'remediation': "1. Rotate the API key immediately\\n2. Use environment variables\\n3. Implement key rotation policies",
    },
    {
        'name': "SendGrid API Key",
        'category': "Email & Messaging Secrets",
        'regex': "SG\\\\.[A-Za-z0-9_-]{22,}\\\\.[A-Za-z0-9_-]{22,}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "SendGrid API key allows an attacker to send emails from the organization's verified sender domains. This enables targeted phishing campaigns that pass SPF/DKIM checks, large-scale spam that damages domain reputation, and exfiltration of email activity logs including recipient addresses and delivery metadata.",
        'remediation': "1. Revoke the key in SendGrid dashboard\\n2. Create a new key with minimal permissions\\n3. Use environment variables for key storage",
    },
    {
        'name': "Mailgun Private Key",
        'category': "Email & Messaging Secrets",
        'regex': "key-[A-Za-z0-9]{32}",
        'flags': "g",
        'severity': "high",
        'confidence': 90,
        'impact': "Mailgun private API key provides full account access: send emails from verified domains, read stored messages and event logs, manage routes and webhooks, and modify domain DNS settings. An attacker can conduct phishing using the organization's legitimate sending infrastructure, making detection significantly harder.",
        'remediation': "1. Regenerate the API key in Mailgun\\n2. Review sent email logs\\n3. Use environment variables",
    },
    {
        'name': "Twilio Auth Token",
        'category': "Email & Messaging Secrets",
        'regex': "(?:twilio|TWILIO)[\\\\s_-]*(?:auth|AUTH)[\\\\s_-]*(?:token|TOKEN)[\\\\s:=\\\"']*([a-f0-9]{32})",
        'flags': "g",
        'severity': "critical",
        'confidence': 85,
        'impact': "Twilio auth token paired with the account SID grants full API access: send SMS/MMS from owned numbers, initiate voice calls, access call recordings, and read message logs. An attacker can use this for SMS phishing (smishing), toll fraud through premium-rate calls, or intercept OTP codes if the account handles 2FA delivery.",
        'remediation': "1. Rotate the auth token in Twilio console\\n2. Review usage logs\\n3. Use API keys instead of the main auth token",
    },
    {
        'name': "Slack Token",
        'category': "SaaS Tokens",
        'regex': "xox[bpors]-[A-Za-z0-9-]{10,}",
        'flags': "g",
        'severity': "critical",
        'confidence': 95,
        'impact': "Slack token (bot or user-level) enables reading channel messages and files, posting as the authenticated identity, listing workspace members, and accessing shared files. In corporate environments, Slack channels frequently contain credentials, internal URLs, deployment procedures, and customer data \u2014 making this a high-value lateral movement vector.",
        'remediation': "1. Revoke the token in Slack app settings\\n2. Audit workspace activity\\n3. Use OAuth with minimal scopes",
    },
    {
        'name': "Discord Bot Token",
        'category': "SaaS Tokens",
        'regex': "[MN][A-Za-z\\\\d]{23,}\\\\.[\\\\w-]{6}\\\\.[\\\\w-]{27,}",
        'flags': "g",
        'severity': "high",
        'confidence': 85,
        'impact': "Discord bot token gives full control over the bot identity: read and send messages in all guilds the bot has joined, manage channels and roles, kick/ban members, and access message history. If the bot has elevated permissions (Administrator), the attacker effectively controls the server. Token does not expire until manually regenerated.",
        'remediation': "1. Regenerate the bot token in Discord Developer Portal\\n2. Review bot permissions\\n3. Store token securely server-side",
    },
    {
        'name': "Notion Token",
        'category': "SaaS Tokens",
        'regex': "(?:secret_|ntn_)[A-Za-z0-9]{43}",
        'flags': "g",
        'severity': "high",
        'confidence': 90,
        'impact': "Notion integration token grants API access to all pages and databases shared with the integration. An attacker can read internal documentation, project plans, and sensitive business data. Write access allows content manipulation, data deletion, or injection of malicious links into shared documents used by the team.",
        'remediation': "1. Revoke and recreate the integration in Notion\\n2. Review shared pages\\n3. Limit integration permissions",
    },
    {
        'name': "MongoDB Connection String",
        'category': "Database Credentials",
        'regex': "mongodb(?:\\\\+srv)?:\\\\/\\\\/[^\\\\s\\\"'<>]{10,}",
        'flags': "g",
        'severity': "critical",
        'confidence': 90,
        'impact': "MongoDB connection URI with embedded credentials provides direct database access. An attacker can dump all collections, modify or delete records, and depending on the user's role, execute administrative commands (dropDatabase, createUser). If the instance is network-accessible, no additional exploitation is needed \u2014 the connection string is a complete attack payload.",
        'remediation': "1. Change database password immediately\\n2. Restrict IP allowlist\\n3. Use environment variables for connection strings",
    },
    {
        'name': "PostgreSQL Connection String",
        'category': "Database Credentials",
        'regex': "postgres(?:ql)?:\\\\/\\\\/[^\\\\s\\\"'<>]{10,}",
        'flags': "g",
        'severity': "critical",
        'confidence': 90,
        'impact': "PostgreSQL connection string contains host, port, database name, username, and password in a directly usable format. An attacker can connect with any standard client (psql, pgAdmin), enumerate schemas, extract user records and application data, and if the role has sufficient privileges, read server-side files or execute OS commands via COPY or extension functions.",
        'remediation': "1. Change database password\\n2. Restrict network access\\n3. Use connection pooling with secrets manager",
    },
    {
        'name': "Redis Auth",
        'category': "Database Credentials",
        'regex': "redis:\\\\/\\\\/[^\\\\s\\\"'<>]{10,}",
        'flags': "g",
        'severity': "high",
        'confidence': 85,
        'impact': "Redis connection URI exposes access to the in-memory data store, which commonly holds session tokens, cached API responses, rate-limit counters, and queued jobs. An attacker can dump active sessions (enabling mass account takeover), flush all keys (denial of service), or in older unpatched versions, leverage Lua scripting for further exploitation.",
        'remediation': "1. Change Redis password\\n2. Enable ACLs\\n3. Restrict network access",
    },
    {
        'name': "Azure Storage Connection String",
        'category': "Cloud Secrets",
        'regex': "DefaultEndpointsProtocol\\\\s*=\\\\s*https?[\\\\s\\\\S]{0,300}?AccountKey\\\\s*=\\\\s*([A-Za-z0-9+\\\\/]{86,88}={1,2})",
        'flags': "gi",
        'severity': "critical",
        'confidence': 95,
        'impact': "Azure Storage account connection string exposes the full primary or secondary account key, granting plenary access to all blobs, queues, tables, and file shares under this storage account. An attacker can read, write, or delete any data, generate their own SAS tokens, and (depending on the account configuration) pivot into networked resources.",
        'remediation': "1. Rotate both primary and secondary keys in Azure Portal immediately\\n2. Replace with Azure Managed Identity or User-Assigned Identity\\n3. If keys must be used, store in Azure Key Vault and inject server-side\\n4. Audit recent storage access logs for unauthorized activity",
    },
    {
        'name': "Azure SharedAccessKey",
        'category': "Cloud Secrets",
        'regex': "SharedAccessKey\\\\s*=\\\\s*([A-Za-z0-9+\\\\/]{40,}={1,2})(?=[;\\\"'\\\\s]|$)",
        'flags': "gi",
        'severity': "critical",
        'confidence': 90,
        'impact': "Azure SharedAccessKey grants access to the associated resource \u2014 typically Service Bus namespace, Event Hubs entity, IoT Hub, or Relay. Depending on the policy scope (Listen / Send / Manage), an attacker can read all messages on a queue/topic, send forged messages, or fully manage the resource. Often part of a connection string that also reveals the endpoint URL and policy name.",
        'remediation': "1. Rotate the SharedAccessKey in Azure Portal under the associated resource\\n2. Move to Azure AD / Managed Identity authentication where supported\\n3. Restrict the policy scope to least-privilege if rotation isn't possible",
    },
    {
        'name': "Azure SAS Token",
        'category': "Cloud Secrets",
        'regex': "[?&]sv=\\\\d{4}-\\\\d{2}-\\\\d{2}[\\\\s\\\\S]{0,500}?[?&]sig=([A-Za-z0-9%]{40,})(?=[&\\\"'\\\\s]|$)",
        'flags': "g",
        'severity': "high",
        'confidence': 85,
        'impact': "Azure SAS (Shared Access Signature) token in a pre-signed URL grants the bearer time-limited but potentially broad access to a storage resource (blob, container, queue, etc.). Even though SAS tokens expire, they may have hours or days of remaining validity and may grant write/delete permissions. If the source IP isn't restricted, the token is fully exploitable from anywhere.",
        'remediation': "1. Revoke the SAS by rotating the associated storage account key (invalidates ALL SAS issued with that key)\\n2. Replace with User Delegation SAS (uses Azure AD credentials) for short-lived, revocable access\\n3. Always set narrow expiry windows and IP restrictions when minting SAS tokens",
    },
    {
        'name': "GCP Service Account Key",
        'category': "Cloud Secrets",
        'regex': "\\\"type\\\"\\\\s*:\\\\s*\\\"service_account\\\"[\\\\s\\\\S]*?\\\"private_key\\\"\\\\s*:\\\\s*\\\"([^\\\"]*-----END (?:RSA )?PRIVATE KEY-----[^\\\"]*)\\\"",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "GCP service account key JSON file enables authentication as the service account with all IAM roles bound to it. An attacker can access Cloud Storage buckets, query BigQuery datasets, invoke Cloud Functions, and manage GCE instances. Service account keys do not expire and remain valid until explicitly deleted, making this a persistent access vector.",
        'remediation': "1. Delete the service account key in GCP Console\\n2. Create a new key if needed\\n3. Use Workload Identity instead of key files",
    },
    {
        'name': "Jenkins Token",
        'category': "CI/CD & DevOps Secrets",
        'regex': "(?:jenkins|JENKINS)[\\\\s_-]*(?:token|TOKEN|secret|SECRET|key|KEY)[\\\\s:=\\\"']*([A-Za-z0-9_-]{20,})",
        'flags': "g",
        'severity': "high",
        'confidence': 70,
        'impact': "Jenkins API token enables remote build triggering, job configuration reads, and access to build artifacts and console output. Since Jenkins agents frequently execute shell commands with elevated privileges, an attacker can craft pipeline scripts that run arbitrary code on build nodes \u2014 effectively achieving remote code execution on the CI infrastructure.",
        'remediation': "1. Regenerate the token in Jenkins\\n2. Review build permissions\\n3. Use scoped API tokens",
    },
    {
        'name': "CircleCI Token",
        'category': "CI/CD & DevOps Secrets",
        'regex': "(?:circle|CIRCLE)[\\\\s_-]*(?:ci|CI)[\\\\s_-]*(?:token|TOKEN)[\\\\s:=\\\"']*([A-Za-z0-9_-]{20,})",
        'flags': "g",
        'severity': "high",
        'confidence': 70,
        'impact': "CircleCI personal API token grants access to pipeline configurations, build logs, and project environment variables \u2014 which commonly store deployment credentials, cloud provider keys, and signing secrets. An attacker can trigger pipelines with modified configurations to execute arbitrary code or extract secrets from the build environment.",
        'remediation': "1. Revoke the token in CircleCI\\n2. Review pipeline configurations\\n3. Use context-restricted tokens",
    },
    {
        'name': "SSH Private Key",
        'category': "Private Keys",
        'regex': "-----BEGIN (?:OPENSSH|DSA|EC|PGP) PRIVATE KEY-----[\\\\s\\\\S]*?-----END (?:OPENSSH|DSA|EC|PGP) PRIVATE KEY-----",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "Exposed SSH private key provides direct shell access to every server where the corresponding public key is authorized. This typically includes production infrastructure, jump hosts, and deployment targets. The attacker gains interactive command execution at the privilege level of the authorized user, and if the key is passwordless, no additional cracking is required.",
        'remediation': "1. Remove the compromised key from all authorized_keys files\\n2. Generate a new key pair\\n3. Never include private keys in client-side code",
    },
    {
        'name': "PEM Encoded Private Key",
        'category': "Private Keys",
        'regex': "-----BEGIN RSA PRIVATE KEY-----[\\\\s\\\\S]*?-----END RSA PRIVATE KEY-----",
        'flags': "g",
        'severity': "critical",
        'confidence': 95,
        'impact': "PEM-encoded private key compromises the cryptographic identity it protects. If used for TLS, an attacker can perform man-in-the-middle attacks on encrypted connections. If used for code signing, they can produce trusted malicious artifacts. If used for service authentication, they inherit the full trust relationship the key establishes.",
        'remediation': "1. Revoke and regenerate the key\\n2. Use a hardware security module (HSM) or key management service\\n3. Never embed keys in source code",
    },
    {
        'name': "PEM Certificate",
        'category': "Private Keys",
        'regex': "-----BEGIN CERTIFICATE-----[\\\\s\\\\S]*?-----END CERTIFICATE-----",
        'flags': "g",
        'severity': "low",
        'confidence': 75,
        'impact': "An embedded X.509 certificate. Certificates are public by design, so on its own this is low risk \u2014 but it can disclose internal hostnames, Subject Alternative Names, the issuing CA and validity window (useful for reconnaissance), and it is a critical finding when the matching private key is exposed alongside it.",
        'remediation': "1. Confirm no private key is exposed with it\\n2. Remove unnecessary certificates from client-side bundles\\n3. Review SANs/CN for leaked internal hostnames",
    },
    {
        'name': "Encrypted Private Key",
        'category': "Private Keys",
        'regex': "-----BEGIN ENCRYPTED PRIVATE KEY-----[\\\\s\\\\S]*?-----END ENCRYPTED PRIVATE KEY-----",
        'flags': "g",
        'severity': "high",
        'confidence': 90,
        'impact': "A PKCS#8 encrypted private key. It is passphrase-protected, so it is not immediately usable \u2014 but exposing it lets an attacker crack the passphrase offline (weak passphrases fall quickly), and the passphrase is frequently hardcoded nearby or reused. Once decrypted it grants the full trust the key establishes (TLS identity, code signing, or service authentication).",
        'remediation': "1. Treat the key as compromised \u2014 revoke and regenerate it\\n2. Never ship private keys (even encrypted) in client-side code\\n3. Use an HSM/KMS and store the passphrase separately from the key",
    },
    {
        'name': "RSA/EC Public Key Exposure",
        'category': "Cryptographic Material",
        'regex': "-----BEGIN (?:RSA |EC )?PUBLIC KEY-----[\\\\s\\\\S]*?-----END (?:RSA |EC )?PUBLIC KEY-----",
        'flags': "g",
        'severity': "info",
        'confidence': 60,
        'impact': "A hardcoded RSA/EC public key embedded in client-side JavaScript. A public key is meant to be public, so this is not a credential leak \u2014 but it is useful reconnaissance: it exposes the client-side encryption scheme (commonly used to encrypt the password/PII before it reaches the server), the algorithm and key size, and lets you identify weak, undersized, or reused keys and reason about the surrounding auth flow.",
        'remediation': "1. No action needed if the key is intentionally public and adequately sized (RSA >= 2048-bit)\\n2. Confirm the matching PRIVATE key is not exposed anywhere\\n3. Rotate if the key is undersized or was meant to be internal",
    },
    {
        'name': "OAuth Access Token",
        'category': "API & Auth Secrets",
        'regex': "(?:access_token|oauth_token)[\\\\s]*[=:]\\\\s*[\\\"']([A-Za-z0-9._~+\\\\/=-]{20,})[\\\"']",
        'flags': "gi",
        'severity': "high",
        'confidence': 80,
        'impact': "OAuth access token provides authenticated API access scoped to the granted permissions. An attacker can perform actions as the token holder \u2014 read profile data, access protected resources, or modify account settings. While typically short-lived, tokens embedded in JavaScript may be refreshed automatically by the application, extending the exploitation window.",
        'remediation': "1. Revoke the token\\n2. Use token refresh flows with short-lived tokens\\n3. Never hardcode tokens in client code",
    },
    {
        'name': "OAuth Refresh Token",
        'category': "API & Auth Secrets",
        'regex': "(?:refresh_token)[\\\\s]*[=:]\\\\s*[\\\"']([A-Za-z0-9._~+\\\\/=-]{20,})[\\\"']",
        'flags': "gi",
        'severity': "critical",
        'confidence': 80,
        'impact': "OAuth refresh token is a long-lived credential that generates new access tokens without user interaction. Unlike access tokens that expire in minutes, a refresh token provides persistent access until explicitly revoked. An attacker who captures this can maintain continuous authenticated access to the user's account and data, surviving password changes in many OAuth implementations.",
        'remediation': "1. Revoke the refresh token\\n2. Implement token rotation\\n3. Store refresh tokens server-side only",
    },
    {
        'name': "Hardcoded Password",
        'category': "Hardcoded Credentials",
        'regex': "(?<![a-zA-Z0-9_$])(?:[a-zA-Z0-9_$]*)(?:password|passwd|pwd)[\\\\s]*[=:]\\\\s*[\\\"']([^\\\"']{4,})[\\\"']",
        'flags': "gi",
        'severity': "high",
        'confidence': 70,
        'impact': "Password exposed in client-side JavaScript is visible to every visitor via browser DevTools or source inspection. If this credential corresponds to an administrative account, database user, or third-party service, the attacker gains direct login access. Users who reuse passwords across services face additional exposure beyond the immediate target.",
        'remediation': "1. Remove hardcoded password immediately\\n2. Rotate the compromised password\\n3. Use environment variables or a secrets manager\\n4. Implement proper authentication flow",
    },
    {
        'name': "Hardcoded Username+Password",
        'category': "Hardcoded Credentials",
        'regex': "(?<![a-zA-Z0-9_$])(?:[a-zA-Z0-9_$]*)(?:username|user|login)[\\\\s]*[=:]\\\\s*[\\\"'][^\\\"']+[\\\"'][\\\\s\\\\S]{0,50}(?<![a-zA-Z0-9_$])(?:[a-zA-Z0-9_$]*)(?:password|passwd|pwd)[\\\\s]*[=:]\\\\s*[\\\"']([^\\\"']{6,})[\\\"']",
        'flags': "gi",
        'severity': "critical",
        'confidence': 80,
        'impact': "Full credential pair (username and password) in client-side code eliminates any reconnaissance effort for an attacker. This is a ready-to-use login that can be tested against the application itself, its admin interfaces, associated databases, and any third-party services where the same credentials may be reused. No brute-forcing or social engineering required.",
        'remediation': "1. Remove all hardcoded credentials\\n2. Rotate both username and password\\n3. Implement proper authentication with a backend service",
    },
    {
        'name': "Internal API Endpoint",
        'category': "Internal Endpoints",
        'regex': "[\\\"'](https?:\\\\/\\\\/(?:internal|staging|dev|test|admin|api-internal|backend|private|corp|intranet|vpn)[^\\\"'\\\\s]{5,})[\\\"']",
        'flags': "gi",
        'severity': "low",
        'confidence': 75,
        'impact': "Internal API endpoint leaked in client-side code reveals backend infrastructure topology \u2014 hostnames, ports, path conventions, and naming patterns. An attacker can use this to map internal services, identify unauthenticated endpoints behind the perimeter, and craft SSRF payloads. Even if the endpoint is not directly reachable, the information aids targeted attacks against the internal network.",
        'remediation': "1. Remove internal endpoints from client-side code\\n2. Use environment-based configuration\\n3. Implement API gateway to prevent direct internal access",
    },
    {
        'name': "Admin Panel URL",
        'category': "Internal Endpoints",
        'regex': "[\\\"'](https?:\\\\/\\\\/[^\\\"'\\\\s]*\\\\/(?:admin|dashboard|panel|backoffice|cms|control|manage)[^\\\"'\\\\s]*)[\\\"']",
        'flags': "gi",
        'severity': "low",
        'confidence': 65,
        'impact': "Admin panel URL disclosed in client code gives attackers a direct target for authentication bypass, credential stuffing, and brute-force attacks. Administrative interfaces typically have elevated privileges \u2014 user management, configuration changes, data export \u2014 and are often protected only by a login form without rate limiting or MFA at the path level.",
        'remediation': "1. Remove admin URLs from client-side code\\n2. Implement IP-based access control\\n3. Add multi-factor authentication to admin panels",
    },
    {
        'name': "Debug/Dev Endpoint",
        'category': "Internal Endpoints",
        'regex': "[\\\"'](https?:\\\\/\\\\/[^\\\"'\\\\s]*\\\\/(?:debug|_debug|__debug|phpinfo|server-status|server-info|health|_health|metrics|_metrics|graphql|graphiql|playground)[^\\\"'\\\\s]*)[\\\"']",
        'flags': "gi",
        'severity': "medium",
        'confidence': 70,
        'impact': "Debug or diagnostic endpoint referenced in production JavaScript typically exposes server environment variables, framework versions, stack traces, database connection details, and internal routing configuration. Endpoints like /graphiql or /playground may allow arbitrary query execution. Health and metrics endpoints can leak infrastructure topology useful for lateral movement planning.",
        'remediation': "1. Disable debug endpoints in production\\n2. Implement proper access controls\\n3. Remove references from client-side code",
    },
    {
        'name': "Hardcoded Database URL",
        'category': "Database Credentials",
        'regex': "[\\\"']((?:mysql|mariadb|mssql|sqlserver):\\\\/\\\\/[^\\\\s\\\"'<>]{10,})[\\\"']",
        'flags': "gi",
        'severity': "critical",
        'confidence': 90,
        'impact': "Database connection string (MySQL/MariaDB/MSSQL) with embedded credentials provides direct data-plane access if the database host is network-reachable. An attacker can enumerate databases and tables, extract sensitive records (user data, financial records, PII), and depending on grants, execute administrative operations including user creation and data destruction.",
        'remediation': "1. Change database password immediately\\n2. Restrict network access\\n3. Use environment variables for connection strings",
    },
    {
        'name': "Algolia Admin API Key",
        'category': "SaaS Tokens",
        'regex': "(?:algolia|ALGOLIA)[\\\\s_-]*(?:admin|ADMIN)[\\\\s_-]*(?:api[_\\\\s-]?key|key|KEY|api|API)[\\\\s:=\\\"']*([a-f0-9]{32})",
        'flags': "gi",
        'severity': "critical",
        'confidence': 80,
        'impact': "Algolia admin API key provides unrestricted access to all indices: read, write, delete records, configure relevance settings, and manage API keys. An attacker can exfiltrate indexed data (which often mirrors production database content), inject poisoned search results, or delete indices to cause application-wide search outage.",
        'remediation': "1. Regenerate the API key in Algolia dashboard\\n2. Use search-only API keys for client-side code\\n3. Restrict key permissions",
    },
    {
        'name': "Supabase Service Role Key",
        'category': "Cloud Secrets",
        'regex': "eyJ[A-Za-z0-9_-]*\\\\.eyJ[A-Za-z0-9_-]*\\\\.[\\\\w-]*",
        'flags': "gi",
        'severity': "critical",
        'confidence': 85,
        'impact': "Supabase service role key bypasses all Row Level Security policies, granting unrestricted read/write access to every table in the database. An attacker can extract all user data, modify authentication records, escalate privileges, and access storage buckets. This key is equivalent to a database superuser and should never appear in client-side code.",
        'remediation': "1. Rotate the service role key\\n2. Never expose service role keys in client code\\n3. Use anon key for client-side and service role only server-side",
    },
    {
        'name': "Vercel Token",
        'category': "CI/CD & DevOps Secrets",
        'regex': "(?:vercel|VERCEL)[\\\\s_-]*(?:token|TOKEN|key|KEY)[\\\\s:=\\\"']*([A-Za-z0-9_-]{24,})",
        'flags': "gi",
        'severity': "high",
        'confidence': 70,
        'impact': "Vercel personal access token enables deployment management (deploy, promote, rollback), project environment variable access, and domain configuration. An attacker can deploy malicious code to production, read secrets stored in environment variables, or redirect domains \u2014 effectively achieving full control over the hosted application's supply chain.",
        'remediation': "1. Revoke the token in Vercel dashboard\\n2. Create a new scoped token\\n3. Use environment variables",
    },
    {
        'name': "Netlify Token",
        'category': "CI/CD & DevOps Secrets",
        'regex': "(?:netlify|NETLIFY)[\\\\s_-]*(?:token|TOKEN|key|KEY|auth|AUTH)[\\\\s:=\\\"']*([A-Za-z0-9_-]{40,})",
        'flags': "gi",
        'severity': "high",
        'confidence': 70,
        'impact': "Netlify access token grants deployment control (publish arbitrary builds to production), environment variable access (which stores API keys and secrets), DNS record management, and webhook configuration. An attacker can replace the live site with a phishing page, extract stored secrets, or redirect the domain to attacker-controlled infrastructure.",
        'remediation': "1. Revoke the token in Netlify settings\\n2. Create a new personal access token\\n3. Store tokens server-side only",
    },
    {
        'name': "Datadog API Key",
        'category': "SaaS Tokens",
        'regex': "(?:datadog|DD)[\\\\s_-]*(?:api|API)[\\\\s_-]*(?:key|KEY)[\\\\s:=\\\"']*([a-f0-9]{32})",
        'flags': "gi",
        'severity': "high",
        'confidence': 75,
        'impact': "Datadog API key enables submission of metrics, events, and logs to the organization's monitoring account. An attacker can inject false metrics to mask malicious activity, flood the account to increase billing, or submit crafted log entries. If combined with an application key (check for co-located secrets), full dashboard and alert configuration access is possible.",
        'remediation': "1. Rotate the API key\\n2. Use scoped API keys\\n3. Store keys server-side only",
    },
    {
        'name': "Sentry DSN",
        'category': "SaaS Tokens",
        'regex': "https:\\\\/\\\\/[a-f0-9]{32}@[a-z0-9]+\\\\.ingest\\\\.sentry\\\\.io\\\\/[0-9]+",
        'flags': "g",
        'severity': "info",
        'confidence': 85,
        'impact': "A Sentry DSN is public by design \u2014 it ships in client-side code so the browser can send error events, and it is a write-only ingest key (it cannot read your error data). Exposure is expected for client-side Sentry, so no rotation is normally required. The only residual risk is event-quota abuse (an attacker flooding fabricated events), mitigated by configuring allowed domains / rate limits.",
        'remediation': "1. No action required for a normally client-side DSN \u2014 it is meant to be public.\\n2. Configure allowed domains and rate limits on the Sentry project to limit quota abuse.\\n3. Rotate the DSN only if you intended it to be private.",
    },
    {
        'name': "Mapbox Token",
        'category': "SaaS Tokens",
        'regex': "pk\\\\.eyJ[A-Za-z0-9_-]{50,}\\\\.[A-Za-z0-9_-]{20,}",
        'flags': "g",
        'severity': "medium",
        'confidence': 90,
        'impact': "Mapbox public access token without URL restrictions can be abused for high-volume tile requests, geocoding, and directions API calls \u2014 all billed to the token owner's account. While Mapbox tokens are designed for client-side use, unrestricted tokens enable cost-amplification attacks and usage quota exhaustion that can disrupt the legitimate application's map functionality.",
        'remediation': "1. Rotate the token in Mapbox dashboard\\n2. Set URL restrictions on the token\\n3. Use scoped tokens for production",
    },
    {
        'name': "Cloudflare API Token",
        'category': "Cloud Secrets",
        'regex': "(?:cloudflare|CF)[\\\\s_-]*(?:api|API)[\\\\s_-]*(?:token|TOKEN|key|KEY)[\\\\s:=\\\"']*([A-Za-z0-9_-]{40,})",
        'flags': "gi",
        'severity': "critical",
        'confidence': 75,
        'impact': "Cloudflare API token scope determines impact but may include DNS record management (enabling domain hijacking), firewall rule modification (disabling WAF protections), Workers script deployment (injecting malicious edge code), and SSL certificate management. A zone-scoped token can redirect all traffic through attacker infrastructure via DNS manipulation.",
        'remediation': "1. Revoke the token in Cloudflare dashboard\\n2. Create a new scoped API token\\n3. Use environment variables for storage",
    },
    {
        'name': "OpenAI API Key",
        'category': "AI & ML Secrets",
        'regex': "sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "OpenAI API key grants access to GPT models, DALL-E, Whisper, and embeddings APIs. An attacker can run unlimited inference at the key owner's expense, exfiltrate fine-tuned model data, access conversation history via the Assistants API, and generate harmful content attributed to the victim's account. API usage costs can escalate to thousands of dollars rapidly.",
        'remediation': "1. Revoke the key in OpenAI dashboard immediately\\n2. Create a new key with usage limits\\n3. Never expose API keys in client-side code",
    },
    {
        'name': "OpenAI API Key (New Format)",
        'category': "AI & ML Secrets",
        'regex': "sk-proj-[A-Za-z0-9_-]{40,}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "OpenAI project-scoped API key provides access to all enabled models within the project. An attacker can consume API credits, access fine-tuned models, and potentially read assistant configurations. Project keys may have usage limits but still represent significant financial and data exposure.",
        'remediation': "1. Revoke the key in OpenAI dashboard\\n2. Create a new project key\\n3. Set strict usage limits and monitor usage",
    },
    {
        'name': "OpenAI API Key (Generic)",
        'category': "AI & ML Secrets",
        'regex': "(?:openai|OPENAI)[\\\\s_-]*(?:api|API)[\\\\s_-]*(?:key|KEY)[\\\\s:=\\\"']*[\\\"']?(sk-[A-Za-z0-9_-]{20,})[\\\"']?",
        'flags': "gi",
        'severity': "critical",
        'confidence': 90,
        'impact': "OpenAI API key enables access to all GPT models, code generation, image creation, and audio transcription. Exposed keys lead to unauthorized usage charges and potential data exposure through API conversations and fine-tuning data.",
        'remediation': "1. Revoke and regenerate the API key\\n2. Use environment variables\\n3. Set spending limits on the OpenAI account",
    },
    {
        'name': "Anthropic API Key",
        'category': "AI & ML Secrets",
        'regex': "sk-ant-[A-Za-z0-9_-]{80,}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "Anthropic API key provides access to Claude models for conversation, analysis, and code generation. An attacker can exhaust the account's usage quota, generate harmful content under the victim's identity, and access any custom system prompts or conversations stored via the API.",
        'remediation': "1. Revoke the key in Anthropic Console\\n2. Generate a new API key\\n3. Implement usage monitoring and alerts",
    },
    {
        'name': "Cohere API Key",
        'category': "AI & ML Secrets",
        'regex': "(?:cohere|COHERE)[\\\\s_-]*(?:api|API)[\\\\s_-]*(?:key|KEY)[\\\\s:=\\\"']*[\\\"']?([A-Za-z0-9]{40})[\\\"']?",
        'flags': "gi",
        'severity': "high",
        'confidence': 75,
        'impact': "Cohere API key enables access to language models for text generation, embeddings, classification, and reranking. An attacker can consume API credits and potentially access custom fine-tuned models or datasets associated with the account.",
        'remediation': "1. Regenerate the API key in Cohere dashboard\\n2. Use environment variables\\n3. Set usage limits",
    },
    {
        'name': "HuggingFace Token",
        'category': "AI & ML Secrets",
        'regex': "hf_[A-Za-z0-9]{34,}",
        'flags': "g",
        'severity': "high",
        'confidence': 95,
        'impact': "HuggingFace access token provides access to private models, datasets, and Inference API endpoints. An attacker can download proprietary models, access private datasets, deploy models to Inference Endpoints at the owner's expense, and push malicious model versions to the owner's repositories.",
        'remediation': "1. Revoke the token in HuggingFace settings\\n2. Create a new fine-grained token\\n3. Use read-only tokens for client-side access",
    },
    {
        'name': "Replicate API Token",
        'category': "AI & ML Secrets",
        'regex': "r8_[A-Za-z0-9]{40}",
        'flags': "g",
        'severity': "high",
        'confidence': 95,
        'impact': "Replicate API token allows running AI models including image generation, language models, and audio processing. An attacker can consume GPU credits running expensive models, access private model versions, and potentially view prediction history.",
        'remediation': "1. Revoke the token in Replicate settings\\n2. Generate a new API token\\n3. Monitor usage for anomalies",
    },
    {
        'name': "DigitalOcean Token",
        'category': "Cloud Secrets",
        'regex': "dop_v1_[a-f0-9]{64}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "DigitalOcean personal access token provides full API access to manage droplets, databases, Kubernetes clusters, and DNS. An attacker can create resources for cryptomining, access database backups, modify DNS records for domain hijacking, and delete infrastructure.",
        'remediation': "1. Revoke the token in DigitalOcean dashboard\\n2. Create a new scoped token\\n3. Use environment variables",
    },
    {
        'name': "DigitalOcean OAuth Token",
        'category': "Cloud Secrets",
        'regex': "doo_v1_[a-f0-9]{64}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "DigitalOcean OAuth token grants API access scoped to the authorized permissions. Depending on scopes, an attacker may manage infrastructure, access databases, or modify networking configurations.",
        'remediation': "1. Revoke the OAuth token\\n2. Review authorized applications\\n3. Reduce token scopes",
    },
    {
        'name': "Heroku API Key",
        'category': "Cloud Secrets",
        'regex': "(?:heroku|HEROKU)[\\\\s_-]*(?:api|API)[\\\\s_-]*(?:key|KEY)[\\\\s:=\\\"']*[\\\"']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})[\\\"']?",
        'flags': "gi",
        'severity': "critical",
        'confidence': 85,
        'impact': "Heroku API key provides full account access: deploy code, manage dynos, access config vars (which store database URLs and API keys), and manage add-ons. An attacker can deploy malicious code, extract all stored secrets from config vars, access databases, and pivot to connected services.",
        'remediation': "1. Regenerate the API key in Heroku dashboard\\n2. Review config vars for exposed secrets\\n3. Use OAuth tokens instead of API keys",
    },
    {
        'name': "Supabase Anon Key",
        'category': "Cloud Secrets",
        'regex': "eyJ[A-Za-z0-9_-]{20,}\\\\.eyJ[A-Za-z0-9_-]{20,}\\\\.[\\\\w-]{20,}",
        'flags': "gi",
        'severity': "info",
        'confidence': 60,
        'impact': "A Supabase ANON (anonymous) key is public by design \u2014 it is meant to ship in client-side code, and access is governed by Row-Level Security (RLS). Exposure is expected; data is only at risk if RLS policies are missing or misconfigured. This is NOT the service_role key (which bypasses RLS and is detected separately as critical). Review your RLS policies; rotate only if RLS is misconfigured.",
        'remediation': "1. No action required for the anon key itself \u2014 it is meant to be public.\\n2. Verify Row-Level Security is enabled and correct on all tables.\\n3. Never expose the service_role key client-side; rotate it if it ever appears in client code.",
    },
    {
        'name': "Vercel Access Token (Bearer)",
        'category': "CI/CD & DevOps Secrets",
        'regex': "(?<![A-Za-z0-9])(?:vercel_|VERCEL_)(?:TOKEN|ACCESS_TOKEN|API_TOKEN)[\\\\s:=\\\"']*[\\\"']?([A-Za-z0-9]{24,})[\\\"']?",
        'flags': "gi",
        'severity': "high",
        'confidence': 80,
        'impact': "Vercel access token enables deployment control, environment variable access, and project management. An attacker can deploy malicious builds, read production secrets, and modify domain configurations.",
        'remediation': "1. Revoke the token in Vercel dashboard\\n2. Create a new scoped token\\n3. Use environment variables for storage",
    },
    {
        'name': "Datadog Application Key",
        'category': "Monitoring Secrets",
        'regex': "(?:datadog|DD)[\\\\s_-]*(?:app|APP|application|APPLICATION)[\\\\s_-]*(?:key|KEY)[\\\\s:=\\\"']*([a-f0-9]{40})",
        'flags': "gi",
        'severity': "critical",
        'confidence': 80,
        'impact': "Datadog application key combined with an API key provides full dashboard, monitor, and alerting management access. An attacker can disable critical alerts to mask incidents, modify dashboards to hide malicious activity, and access sensitive log data including environment variables and request payloads.",
        'remediation': "1. Revoke the application key\\n2. Create a new scoped key\\n3. Audit recent dashboard and monitor changes",
    },
    {
        'name': "New Relic License Key",
        'category': "Monitoring Secrets",
        'regex': "(?:new[_\\\\s-]?relic|NEWRELIC|NR)[\\\\s_-]*(?:license(?:[_\\\\s-]?key)?|key)[\\\\s:=\\\"']*[\\\"']?([a-f0-9]{40})[\\\"']?",
        'flags': "gi",
        'severity': "high",
        'confidence': 75,
        'impact': "New Relic license key enables telemetry data submission. An attacker can inject false metrics, pollute APM data, and flood the account to increase costs. Combined with the API key, they can access application performance data revealing infrastructure details, error patterns, and database query performance.",
        'remediation': "1. Rotate the license key in New Relic\\n2. Use environment variables\\n3. Monitor for unusual data ingestion",
    },
    {
        'name': "New Relic API Key",
        'category': "Monitoring Secrets",
        'regex': "NRAK-[A-Z0-9]{27}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "New Relic user API key provides full account access including NRQL queries (which can expose application data), alert policy management, and synthetic monitoring configuration. An attacker can query sensitive telemetry data, disable critical alerts, and access deployment markers.",
        'remediation': "1. Revoke the key in New Relic API Keys page\\n2. Create a new key with minimal permissions\\n3. Store server-side only",
    },
    {
        'name': "PagerDuty API Key",
        'category': "Monitoring Secrets",
        'regex': "(?:pagerduty|PAGERDUTY|PD)[\\\\s_-]*(?:api|API|integration|INTEGRATION)[\\\\s_-]*(?:key|KEY|token|TOKEN)[\\\\s:=\\\"']*[\\\"']?([A-Za-z0-9_+-]{20,})[\\\"']?",
        'flags': "gi",
        'severity': "high",
        'confidence': 70,
        'impact': "PagerDuty API or integration key enables incident management, on-call schedule access, and alert routing. An attacker can create false incidents to cause alert fatigue, suppress real incidents, access on-call schedules for social engineering, and trigger unnecessary escalations.",
        'remediation': "1. Regenerate the API key\\n2. Use scoped API keys\\n3. Review integration permissions",
    },
    {
        'name': "npm Access Token",
        'category': "Package Registry Secrets",
        'regex': "npm_[A-Za-z0-9]{36}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "npm access token enables publishing packages, modifying published packages, and accessing private packages. An attacker can publish malicious versions of owned packages (supply chain attack), read private package source code, and access organization-level package management. This is a high-value target for software supply chain attacks.",
        'remediation': "1. Revoke the token on npmjs.com\\n2. Audit recently published package versions\\n3. Enable 2FA for publishing",
    },
    {
        'name': "PyPI API Token",
        'category': "Package Registry Secrets",
        'regex': "pypi-[A-Za-z0-9_-]{100,}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "PyPI API token enables publishing Python packages. An attacker can upload malicious package versions affecting all downstream users, access private packages, and compromise the Python supply chain. Depending on token scope, they may target specific projects or the entire account.",
        'remediation': "1. Revoke the token on pypi.org\\n2. Audit recent package uploads\\n3. Use project-scoped tokens",
    },
    {
        'name': "NuGet API Key",
        'category': "Package Registry Secrets",
        'regex': "(?<![A-Za-z0-9])oy2[A-Za-z0-9]{43}(?![A-Za-z0-9])",
        'flags': "g",
        'severity': "critical",
        'confidence': 90,
        'impact': "NuGet API key enables publishing .NET packages. An attacker can upload malicious package versions to nuget.org, affecting all .NET applications that depend on the compromised packages. This enables supply chain attacks against the .NET ecosystem.",
        'remediation': "1. Revoke the key on nuget.org\\n2. Audit recently published packages\\n3. Use scoped API keys",
    },
    {
        'name': "Artifactory Token",
        'category': "Package Registry Secrets",
        'regex': "(?:artifactory|ARTIFACTORY|jfrog|JFROG)[\\\\s_-]*(?:token|TOKEN|key|KEY|password|PASSWORD)[\\\\s:=\\\"']*[\\\"']?([A-Za-z0-9_-]{40,})[\\\"']?",
        'flags': "gi",
        'severity': "high",
        'confidence': 70,
        'impact': "JFrog Artifactory token enables access to artifact repositories including Docker images, npm packages, Maven artifacts, and more. An attacker can upload malicious artifacts, access proprietary build outputs, and compromise the software supply chain across multiple package ecosystems.",
        'remediation': "1. Revoke the token in Artifactory\\n2. Create a new scoped token\\n3. Review artifact repository access logs",
    },
    {
        'name': "RubyGems API Key",
        'category': "Package Registry Secrets",
        'regex': "rubygems_[a-f0-9]{48}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "RubyGems API key enables publishing Ruby gems. An attacker can upload malicious gem versions affecting Ruby applications globally. This represents a significant supply chain risk as gems are auto-updated in many Ruby projects.",
        'remediation': "1. Revoke the key on rubygems.org\\n2. Audit recently pushed gem versions\\n3. Enable MFA for gem publishing",
    },
    {
        'name': "Shopify Access Token",
        'category': "E-commerce Secrets",
        'regex': "shpat_[a-f0-9]{32}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "Shopify Admin API access token grants access to store data including orders, customers, products, and financial information. An attacker can read customer PII, modify product listings, access payment details, and potentially process refunds or modify checkout flows.",
        'remediation': "1. Revoke the token in Shopify Partners\\n2. Create a new app with minimal scopes\\n3. Audit store activity logs",
    },
    {
        'name': "Shopify Shared Secret",
        'category': "E-commerce Secrets",
        'regex': "shpss_[a-f0-9]{32}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "Shopify app shared secret is used for verifying webhooks and HMAC signatures. An attacker can forge webhook payloads to trigger arbitrary actions in the app, bypass webhook verification, and potentially inject malicious data into the store's backend processing.",
        'remediation': "1. Regenerate the shared secret\\n2. Update webhook verification code\\n3. Validate all incoming webhooks",
    },
    {
        'name': "Shopify Custom App Token",
        'category': "E-commerce Secrets",
        'regex': "shpca_[a-f0-9]{32}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "Shopify custom app access token provides Admin API access scoped to the custom app's permissions. Depending on scopes, an attacker can read/write orders, customers, inventory, and financial data.",
        'remediation': "1. Recreate the custom app token\\n2. Review and minimize scopes\\n3. Store tokens server-side only",
    },
    {
        'name': "Square Access Token",
        'category': "E-commerce Secrets",
        'regex': "sq0atp-[A-Za-z0-9_-]{22,}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "Square OAuth access token provides access to payment processing, customer management, inventory, and transaction data. An attacker can process payments, issue refunds, access customer PII, and view financial reports. Direct financial impact is possible through unauthorized transactions.",
        'remediation': "1. Revoke the access token\\n2. Reauthorize with minimal scopes\\n3. Monitor for unauthorized transactions",
    },
    {
        'name': "Square Application Secret",
        'category': "E-commerce Secrets",
        'regex': "sq0csp-[A-Za-z0-9_-]{43,}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "Square application secret enables OAuth token generation and webhook verification. An attacker can impersonate the application, generate access tokens for connected merchants, and forge webhook payloads to trigger malicious actions.",
        'remediation': "1. Rotate the application secret\\n2. Update OAuth integration\\n3. Verify all webhook signatures",
    },
    {
        'name': "WooCommerce Consumer Key",
        'category': "E-commerce Secrets",
        'regex': "ck_[a-f0-9]{40}",
        'flags': "g",
        'severity': "critical",
        'confidence': 95,
        'impact': "WooCommerce REST API consumer key enables authenticated access to the store's backend data. An attacker can read and modify orders, customer PII, product inventory, shipping details, and coupon configurations. Combined with the consumer secret, full read/write API access is granted depending on the key's permission scope.",
        'remediation': "1. Revoke the API key in WooCommerce Settings > Advanced > REST API\\n2. Generate a new key pair with minimal permissions\\n3. Never expose consumer keys in client-side code",
    },
    {
        'name': "WooCommerce Consumer Secret",
        'category': "E-commerce Secrets",
        'regex': "cs_[a-f0-9]{40}",
        'flags': "g",
        'severity': "critical",
        'confidence': 95,
        'impact': "WooCommerce REST API consumer secret completes the credential pair for authenticated API access. With the corresponding consumer key, an attacker gains full access to the store's REST API \u2014 reading customer records, modifying orders, adjusting pricing, and exporting sensitive financial data. Direct business impact through unauthorized order manipulation.",
        'remediation': "1. Revoke the API key pair in WooCommerce Settings > Advanced > REST API\\n2. Generate new credentials\\n3. Store secrets server-side only using environment variables",
    },
    {
        'name': "BigCommerce Access Token",
        'category': "E-commerce Secrets",
        'regex': "(?:bigcommerce|BIGCOMMERCE|X-Auth-Token)[\\\\s:=\\\"']*[\\\"']?([a-z0-9]{48,})[\\\"']?",
        'flags': "gi",
        'severity': "critical",
        'confidence': 75,
        'impact': "BigCommerce API access token provides authenticated access to the store's REST API. Depending on OAuth scopes, an attacker can read and modify catalog products, process orders, access customer PII, manage store settings, and export financial reports. The token cannot be regenerated \u2014 only revoked and recreated.",
        'remediation': "1. Delete the compromised API account in BigCommerce Settings > Store-level API Accounts\\n2. Create a new API account with minimal OAuth scopes\\n3. Never expose access tokens in client-side code",
    },
    {
        'name': "BigCommerce Client Secret",
        'category': "E-commerce Secrets",
        'regex': "(?:bigcommerce|BIGCOMMERCE)[\\\\s_-]*(?:client|CLIENT)[\\\\s_-]*(?:secret|SECRET)[\\\\s:=\\\"']*[\\\"']?([a-z0-9]{48,})[\\\"']?",
        'flags': "gi",
        'severity': "critical",
        'confidence': 75,
        'impact': "BigCommerce client secret is used in the OAuth flow for app-level authentication. An attacker can complete OAuth token exchanges, impersonate the application, and gain access to any stores that have installed the app. This enables reading store data, customer information, and order details across multiple merchant accounts.",
        'remediation': "1. Regenerate the client secret in BigCommerce Developer Portal\\n2. Update all OAuth integration endpoints\\n3. Store secrets server-side only",
    },
    {
        'name': "Auth0 Client Secret",
        'category': "Auth & Identity Secrets",
        'regex': "(?:auth0|AUTH0)[\\\\s_-]*(?:client|CLIENT)[\\\\s_-]*(?:secret|SECRET)[\\\\s:=\\\"']*[\\\"']?([A-Za-z0-9_-]{32,})[\\\"']?",
        'flags': "gi",
        'severity': "critical",
        'confidence': 80,
        'impact': "Auth0 client secret enables token exchange and client credentials flow. An attacker can generate access tokens, impersonate the application in authentication flows, and potentially access user data through the Management API if the client has appropriate grants.",
        'remediation': "1. Rotate the client secret in Auth0\\n2. Update all integration endpoints\\n3. Use Auth0 Actions for additional validation",
    },
    {
        'name': "Auth0 Management API Token",
        'category': "Auth & Identity Secrets",
        'regex': "(?:auth0|AUTH0)[\\\\s_-]*(?:management|MANAGEMENT|mgmt|MGMT)[\\\\s_-]*(?:token|TOKEN)[\\\\s:=\\\"']*[\\\"']?([A-Za-z0-9._-]{100,})[\\\"']?",
        'flags': "gi",
        'severity': "critical",
        'confidence': 80,
        'impact': "Auth0 Management API token provides administrative control over the tenant: create/delete users, modify roles and permissions, configure authentication flows, and access user data. An attacker can create backdoor admin accounts, modify authentication rules, and exfiltrate all user information.",
        'remediation': "1. Revoke the token (it may auto-expire)\\n2. Audit tenant logs for unauthorized changes\\n3. Use short-lived tokens with minimal scopes",
    },
    {
        'name': "Okta API Token",
        'category': "Auth & Identity Secrets",
        'regex': "(?:okta|OKTA)[\\\\s_-]*(?:api|API)[\\\\s_-]*(?:token|TOKEN|key|KEY)[\\\\s:=\\\"']*[\\\"']?([A-Za-z0-9_-]{40,})[\\\"']?",
        'flags': "gi",
        'severity': "critical",
        'confidence': 80,
        'impact': "Okta API token provides access to user management, application configuration, and policy administration. An attacker can enumerate all users, reset passwords, modify MFA settings, assign applications, and create new admin accounts \u2014 effectively taking over the organization's identity infrastructure.",
        'remediation': "1. Revoke the token in Okta Admin Console\\n2. Create a new scoped API token\\n3. Review admin audit logs",
    },
    {
        'name': "Firebase Config",
        'category': "Auth & Identity Secrets",
        'regex': "(?:firebase|FIREBASE)[\\\\s_-]*(?:config|CONFIG|key|KEY|secret|SECRET)[\\\\s:=\\\"']*[\\\"']?([A-Za-z0-9_-]{20,})[\\\"']?",
        'flags': "gi",
        'severity': "low",
        'confidence': 60,
        'impact': "Firebase configuration value exposed in client code. While Firebase API keys are designed for client use, combined with misconfigured security rules, an attacker can directly read/write Firestore collections, access Realtime Database, upload files to Cloud Storage, and enumerate user accounts.",
        'remediation': "1. Review and tighten Firebase Security Rules\\n2. Enable App Check for API verification\\n3. Restrict API key usage in Google Cloud Console",
    },
    {
        'name': "Terraform Cloud Token",
        'category': "CI/CD & DevOps Secrets",
        'regex': "(?:terraform|TF)[\\\\s_-]*(?:cloud|CLOUD)?[\\\\s_-]*(?:token|TOKEN)[\\\\s:=\\\"']*[\\\"']?([A-Za-z0-9._-]{40,})[\\\"']?",
        'flags': "gi",
        'severity': "critical",
        'confidence': 70,
        'impact': "Terraform Cloud API token enables infrastructure management: view and modify state files (which contain all resource details and often secrets), trigger plan/apply operations, and access workspace variables. An attacker can destroy infrastructure, extract secrets from state, or inject backdoors into IaC configurations.",
        'remediation': "1. Revoke the token in Terraform Cloud\\n2. Create a new team or user token\\n3. Audit recent runs and state changes",
    },
    {
        'name': "Terraform Cloud Team Token",
        'category': "CI/CD & DevOps Secrets",
        'regex': "atlasv1\\\\.[A-Za-z0-9_-]{60,}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "Terraform Cloud/Enterprise team-level API token provides access to all workspaces the team can manage. An attacker can modify infrastructure-as-code, trigger deployments, read state files containing secrets, and potentially destroy cloud resources across all managed environments.",
        'remediation': "1. Revoke the team token immediately\\n2. Generate a new team token\\n3. Review workspace access policies",
    },
    {
        'name': "Vault Token",
        'category': "CI/CD & DevOps Secrets",
        'regex': "(?:vault|VAULT)[\\\\s_-]*(?:token|TOKEN)[\\\\s:=\\\"']*[\\\"']?(hvs\\\\.[A-Za-z0-9_-]{24,})[\\\"']?",
        'flags': "gi",
        'severity': "critical",
        'confidence': 95,
        'impact': "HashiCorp Vault token provides access to the secrets management system. Depending on policies attached, an attacker can read all stored secrets (database credentials, API keys, certificates), write new secrets, and configure authentication backends. Root tokens provide unrestricted access to the entire Vault cluster.",
        'remediation': "1. Revoke the token via vault token revoke\\n2. Audit access logs for unauthorized secret reads\\n3. Use short-lived tokens with minimal policies",
    },
    {
        'name': "Docker Hub Token",
        'category': "CI/CD & DevOps Secrets",
        'regex': "dckr_pat_[A-Za-z0-9_-]{27,}",
        'flags': "g",
        'severity': "high",
        'confidence': 98,
        'impact': "Docker Hub personal access token enables pushing/pulling container images. An attacker can push malicious image tags to public or private repositories, pull proprietary container images, and potentially access automated build configurations containing source code references.",
        'remediation': "1. Revoke the token in Docker Hub settings\\n2. Create a new scoped access token\\n3. Enable 2FA on Docker Hub account",
    },
    {
        'name': "GitHub Actions Secret",
        'category': "CI/CD & DevOps Secrets",
        'regex': "ghs_[A-Za-z0-9]{36}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "GitHub Actions installation token provides repository access scoped to the GitHub App's permissions. An attacker can trigger workflows, access repository contents, manage issues/PRs, and potentially read secrets exposed to Actions runs.",
        'remediation': "1. Tokens auto-expire but review the associated GitHub App\\n2. Reduce app permissions\\n3. Audit workflow run history",
    },
    {
        'name': "Intercom Access Token",
        'category': "Communication Secrets",
        'regex': "(?:intercom|INTERCOM)[\\\\s_-]*(?:access|ACCESS)?[\\\\s_-]*(?:token|TOKEN|key|KEY)[\\\\s:=\\\"']*[\\\"']?([A-Za-z0-9=_-]{40,})[\\\"']?",
        'flags': "gi",
        'severity': "high",
        'confidence': 70,
        'impact': "Intercom access token enables reading and sending messages to customers, accessing user data (emails, custom attributes, event history), and managing conversations. An attacker can impersonate support staff, access customer PII, and send phishing messages through trusted channels.",
        'remediation': "1. Revoke the token in Intercom Developer Hub\\n2. Create a new token with minimal scopes\\n3. Audit recent message and data access",
    },
    {
        'name': "Zendesk API Token",
        'category': "Communication Secrets",
        'regex': "(?:zendesk|ZENDESK)[\\\\s_-]*(?:api|API)?[\\\\s_-]*(?:token|TOKEN|key|KEY)[\\\\s:=\\\"']*[\\\"']?([A-Za-z0-9]{40,})[\\\"']?",
        'flags': "gi",
        'severity': "high",
        'confidence': 70,
        'impact': "Zendesk API token provides access to support ticket data, customer information, knowledge base content, and agent configurations. An attacker can read sensitive support conversations, access customer PII, modify ticket statuses, and impersonate agents.",
        'remediation': "1. Regenerate the API token in Zendesk Admin\\n2. Create tokens with minimal scopes\\n3. Review recent API activity",
    },
    {
        'name': "Atlassian API Token",
        'category': "Communication Secrets",
        'regex': "(?:atlassian|ATLASSIAN|jira|JIRA|confluence|CONFLUENCE)[\\\\s_-]*(?:api|API)?[\\\\s_-]*(?:token|TOKEN|key|KEY)[\\\\s:=\\\"']*[\\\"']?([A-Za-z0-9]{24,})[\\\"']?",
        'flags': "gi",
        'severity': "high",
        'confidence': 70,
        'impact': "Atlassian API token provides access to Jira, Confluence, and other Atlassian products. An attacker can read project tickets (potentially containing security vulnerability details), access Confluence documentation with internal procedures, and modify project configurations.",
        'remediation': "1. Revoke the token in Atlassian account settings\\n2. Create a new API token\\n3. Review connected application permissions",
    },
    {
        'name': "Telegram Bot Token",
        'category': "Communication Secrets",
        'regex': "(?<![0-9])[0-9]{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])",
        'flags': "g",
        'severity': "high",
        'confidence': 80,
        'impact': "Telegram bot token provides full control over the bot: read and send messages, manage groups, access file uploads, and view chat member information. An attacker can impersonate the bot, read sensitive conversations, and use the bot for phishing or spam campaigns.",
        'remediation': "1. Revoke the token via @BotFather\\n2. Create a new bot token\\n3. Never expose bot tokens in client code",
    },
    {
        'name': "Twilio Account SID",
        'category': "Email & Messaging Secrets",
        'regex': "AC[a-f0-9]{32}",
        'flags': "g",
        'severity': "low",
        'confidence': 90,
        'impact': "Twilio Account SID identifies the account and when combined with the auth token enables full API access. Even alone, the SID reveals account structure and can be used for social engineering. Combined with the auth token (check co-located secrets), it enables SMS sending, call initiation, and recording access.",
        'remediation': "1. Review if auth token is also exposed\\n2. Use API keys instead of account credentials\\n3. Enable request validation",
    },
    {
        'name': "Linear API Key",
        'category': "SaaS Tokens",
        'regex': "lin_api_[A-Za-z0-9]{40,}",
        'flags': "g",
        'severity': "high",
        'confidence': 98,
        'impact': "Linear API key provides access to project management data including issues, cycles, and team information. An attacker can read potentially sensitive issue descriptions (security vulnerabilities, customer complaints), modify project data, and access internal roadmap information.",
        'remediation': "1. Revoke the key in Linear settings\\n2. Create a new API key\\n3. Use OAuth for integrations",
    },
    {
        'name': "Airtable API Key",
        'category': "SaaS Tokens",
        'regex': "(?:airtable|AIRTABLE)[\\\\s_-]*(?:api|API)[\\\\s_-]*(?:key|KEY)[\\\\s:=\\\"']*[\\\"']?(key[A-Za-z0-9]{14})[\\\"']?",
        'flags': "gi",
        'severity': "high",
        'confidence': 85,
        'impact': "Airtable API key provides access to all bases the user can access. An attacker can read, modify, and delete records across all accessible bases. Airtable bases frequently contain business-critical data, customer lists, project plans, and sometimes credentials.",
        'remediation': "1. Regenerate the API key in Airtable account\\n2. Use personal access tokens instead\\n3. Review base sharing settings",
    },
    {
        'name': "Airtable Personal Access Token",
        'category': "SaaS Tokens",
        'regex': "pat[A-Za-z0-9]{14}\\\\.[a-f0-9]{64}",
        'flags': "g",
        'severity': "high",
        'confidence': 95,
        'impact': "Airtable personal access token provides scoped API access. Depending on permissions, an attacker can read/write data, manage bases, and access shared views. Business-critical data in Airtable bases is at risk.",
        'remediation': "1. Revoke the token in Airtable settings\\n2. Create a new scoped token\\n3. Minimize permissions",
    },
    {
        'name': "Doppler Service Token",
        'category': "CI/CD & DevOps Secrets",
        'regex': "dp\\\\.st\\\\.[a-zA-Z0-9_-]{40,}",
        'flags': "g",
        'severity': "critical",
        'confidence': 98,
        'impact': "Doppler service token provides access to project secrets. An attacker can read all environment secrets for the scoped project and environment, potentially gaining access to database credentials, API keys, and other sensitive configuration stored in Doppler.",
        'remediation': "1. Revoke the token in Doppler dashboard\\n2. Create a new service token\\n3. Rotate all secrets in the affected environment",
    },
    {
        'name': "Postman API Key",
        'category': "SaaS Tokens",
        'regex': "PMAK-[A-Za-z0-9]{24}-[a-f0-9]{34}",
        'flags': "g",
        'severity': "high",
        'confidence': 98,
        'impact': "Postman API key provides access to collections, environments, and workspace data. An attacker can read API documentation, access environment variables (which often contain production credentials), and view request/response history that may contain sensitive data.",
        'remediation': "1. Regenerate the API key in Postman\\n2. Review shared collections for sensitive data\\n3. Remove credentials from Postman environments",
    },
    {
        'name': "Livekit API Key",
        'category': "Communication Secrets",
        'regex': "(?:livekit|LIVEKIT)[\\\\s_-]*(?:api|API)?[\\\\s_-]*(?:key|KEY|secret|SECRET)[\\\\s:=\\\"']*[\\\"']?([A-Za-z0-9]{20,})[\\\"']?",
        'flags': "gi",
        'severity': "high",
        'confidence': 70,
        'impact': "LiveKit API key/secret enables creating rooms, generating access tokens, and managing real-time video/audio sessions. An attacker can join or create rooms, record conversations, and access participant data.",
        'remediation': "1. Rotate the API key and secret\\n2. Use environment variables\\n3. Implement server-side token generation only",
    },
    {
        'name': "Resend API Key",
        'category': "Email & Messaging Secrets",
        'regex': "re_[A-Za-z0-9]{30,}",
        'flags': "g",
        'severity': "high",
        'confidence': 90,
        'impact': "Resend API key enables sending emails from verified domains. An attacker can send phishing emails that pass SPF/DKIM checks, exhaust email sending quota, and access email sending logs. The trusted sender domain makes phishing attacks significantly more effective.",
        'remediation': "1. Revoke the key in Resend dashboard\\n2. Create a new API key\\n3. Set domain sending restrictions",
    },
    {
        'name': "Plaid Client Secret",
        'category': "Payment & Financial Secrets",
        'regex': "(?:plaid|PLAID)[\\\\s_-]*(?:client|CLIENT)?[\\\\s_-]*(?:secret|SECRET)[\\\\s:=\\\"']*[\\\"']?([a-f0-9]{30,})[\\\"']?",
        'flags': "gi",
        'severity': "critical",
        'confidence': 75,
        'impact': "Plaid client secret enables access to bank account data, transaction history, and financial information for connected users. An attacker can retrieve sensitive financial data, access balance information, and potentially initiate transfers depending on the Plaid product configuration.",
        'remediation': "1. Rotate the client secret in Plaid dashboard\\n2. Review connected accounts\\n3. Use environment variables for storage",
    },
    {
        'name': "Generic Client Secret",
        'category': "Sensitive Configuration",
        'regex': "(?:client[_\\\\s-]?secret|consumer[_\\\\s-]?secret|app[_\\\\s-]?secret)[\\\\s]*[=:]\\\\s*[\\\"']([A-Za-z0-9_\\\\-]{8,}(?:-[A-Za-z0-9_\\\\-]{2,})*)[\\\"']",
        'flags': "gi",
        'severity': "critical",
        'confidence': 80,
        'impact': "Generic client secret exposed in JavaScript enables an attacker to impersonate the application in OAuth flows, exchange authorization codes for access tokens, and potentially access user data or perform actions on behalf of users. The secret completes the credential pair needed for authenticated API access.",
        'remediation': "1. Rotate the client secret immediately\\n2. Store secrets server-side only \u2014 never in client-side JavaScript\\n3. Use environment variables or a secrets manager\\n4. Review OAuth scopes and permissions",
    },
    {
        'name': "Generic Client ID",
        'category': "Sensitive Configuration",
        'regex': "(?:client[_\\\\s-]?id|app[_\\\\s-]?id|consumer[_\\\\s-]?id)[\\\\s]*[=:]\\\\s*[\\\"']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\\\"']",
        'flags': "gi",
        'severity': "low",
        'confidence': 60,
        'impact': "OAuth client ID exposed in JavaScript identifies the application to the authorization server. While client IDs alone are less dangerous than secrets, they enable targeted phishing (crafting fake OAuth consent screens), application enumeration, and when combined with a leaked client secret, full OAuth flow impersonation.",
        'remediation': "1. Review if the corresponding client secret is also exposed\\n2. Restrict OAuth redirect URIs to known domains\\n3. Consider using dynamic client registration if supported",
    },
    {
        'name': "Subscription / Access Key",
        'category': "API & Auth Secrets",
        'regex': "(?:subscription[_\\\\s-]?key|ocp-apim-subscription-key)[\\\\s]*[=:]\\\\s*[\\\"']([A-Za-z0-9]{16,})[\\\"']",
        'flags': "gi",
        'severity': "high",
        'confidence': 75,
        'impact': "API subscription or access key exposed in JavaScript grants authenticated access to the associated API service. Depending on the provider (Azure API Management, custom gateways), an attacker can consume API quota, access protected endpoints, exfiltrate data, and potentially escalate access to backend services behind the API gateway.",
        'remediation': "1. Rotate the subscription key immediately\\n2. Use backend proxy calls instead of exposing keys in client code\\n3. Implement key restrictions (IP allowlisting, referrer checks)\\n4. Monitor API usage for anomalies",
    },
    {
        'name': "Analytics / Tracking ID",
        'category': "Analytics & Tracking",
        'regex': "(?:clevertap[_\\\\s-]?id|clevertapId|mixpanel[_\\\\s-]?token|mixpanelToken|amplitude[_\\\\s-]?(?:key|api[_\\\\s-]?key)|amplitudeKey|segment[_\\\\s-]?(?:key|write[_\\\\s-]?key)|segmentKey|heap[_\\\\s-]?id|heapId|hotjar[_\\\\s-]?id|hotjarId|intercom[_\\\\s-]?(?:app[_\\\\s-]?id|appId)|ga[_\\\\s-]?(?:tracking[_\\\\s-]?id|trackingId)|posthog[_\\\\s-]?(?:key|api[_\\\\s-]?key)|posthogKey|logrocket[_\\\\s-]?(?:id|appId))[\\\\s]*[=:]\\\\s*[\\\"']([A-Za-z0-9_\\\\-]{4,})[\\\"']",
        'flags': "gi",
        'severity': "low",
        'confidence': 70,
        'impact': "Analytics or tracking service identifier exposed in JavaScript. While these are often intended for client-side use, exposure reveals the organization's analytics infrastructure and enables data poisoning (injecting false events), session replay access (if the service supports it), and mapping of internal project structure. Some tracking IDs grant write access to analytics dashboards.",
        'remediation': "1. Review if the tracking ID grants write or admin access\\n2. Enable domain allowlisting on the analytics platform\\n3. Use server-side event tracking for sensitive data\\n4. Monitor analytics dashboards for anomalous event injection",
    },
    {
        'name': "Hardcoded Config Credentials",
        'category': "Hardcoded Credentials",
        'regex': "(?<![a-zA-Z0-9_$])(?:[a-zA-Z0-9_$]*)(?:password|passwd|pwd|passphrase)[\\\\s]*:\\\\s*[\\\"']([^\\\"']{4,})[\\\"']",
        'flags': "gi",
        'severity': "high",
        'confidence': 65,
        'impact': "Password or passphrase hardcoded in a JavaScript configuration object. This credential is visible to every visitor through browser DevTools or source inspection. If it corresponds to a database, API service, WebSocket endpoint, or admin panel, an attacker gains direct authenticated access without any brute-force effort.",
        'remediation': "1. Remove hardcoded credentials from client-side code immediately\\n2. Rotate the compromised password\\n3. Move authentication to server-side with environment variables\\n4. Use token-based authentication instead of static passwords",
    },
    {
        'name': "Cloudinary URL",
        'category': "Cloud Secrets",
        'regex': "cloudinary:\\\\/\\\\/[0-9]{12,}:[A-Za-z0-9_-]{20,}@[a-z0-9_-]+",
        'flags': "g",
        'severity': "critical",
        'confidence': 95,
        'impact': "A Cloudinary connection URL embeds the API key and API secret directly (cloudinary://<key>:<secret>@<cloud>). With these, an attacker gains full management access to the media account: upload, overwrite and delete assets, generate signed URLs, exfiltrate private/originals, and rack up transformation/bandwidth costs on the owner's plan.",
        'remediation': "1. Rotate the API secret in the Cloudinary console immediately\\n2. Keep the cloudinary:// URL server-side only; never ship it to the browser\\n3. Use unsigned upload presets with strict folder/format limits for client uploads",
    },
    {
        'name': "Slack Incoming Webhook URL",
        'category': "SaaS Tokens",
        'regex': "https:\\\\/\\\\/hooks\\\\.slack\\\\.com\\\\/services\\\\/T[A-Za-z0-9_]+\\\\/B[A-Za-z0-9_]+\\\\/[A-Za-z0-9]{20,}",
        'flags': "g",
        'severity': "medium",
        'confidence': 95,
        'impact': "A Slack incoming webhook URL lets anyone post arbitrary messages into the connected channel without authentication. Attackers use this for convincing internal phishing, social-engineering, and spam \u2014 messages appear to originate from a trusted integration.",
        'remediation': "1. Revoke the webhook in the Slack app configuration\\n2. Generate a new webhook and store it server-side\\n3. Proxy posts through your backend instead of exposing the URL client-side",
    },
    {
        'name': "Discord Webhook URL",
        'category': "SaaS Tokens",
        'regex': "https:\\\\/\\\\/(?:ptb\\\\.|canary\\\\.)?discord(?:app)?\\\\.com\\\\/api\\\\/webhooks\\\\/[0-9]{17,20}\\\\/[A-Za-z0-9_-]{60,}",
        'flags': "g",
        'severity': "medium",
        'confidence': 95,
        'impact': "A Discord webhook URL allows unauthenticated posting of messages (and @everyone pings) to the target channel. It is commonly abused for spam, phishing and raid attacks, and the channel/server context it leaks can aid further reconnaissance.",
        'remediation': "1. Delete the webhook in Discord channel settings\\n2. Recreate it and keep the URL server-side\\n3. Route notifications through a backend endpoint rather than the raw webhook",
    },
    {
        'name': "Stripe Webhook Secret",
        'category': "Payment & Financial Secrets",
        'regex': "whsec_[A-Za-z0-9]{32,}",
        'flags': "g",
        'severity': "high",
        'confidence': 90,
        'impact': "The Stripe webhook signing secret (whsec_) is used to verify that incoming webhook events genuinely originate from Stripe. Leaked, an attacker can forge validly-signed webhook events \u2014 faking successful payments, subscription upgrades or refunds \u2014 to trick the application into granting goods, services or account state for free.",
        'remediation': "1. Roll the webhook signing secret in the Stripe Dashboard\\n2. Keep the secret server-side only\\n3. Additionally validate event data against the Stripe API before acting on it",
    },
    {
        'name': "GitHub OAuth / App Token",
        'category': "Source Control Tokens",
        'regex': "(?<![A-Za-z0-9])(gh[ousr]_[A-Za-z0-9]{36,255})(?![A-Za-z0-9])",
        'flags': "g",
        'severity': "critical",
        'confidence': 90,
        'impact': "GitHub OAuth (gho_), user-to-server (ghu_), server-to-server (ghs_) and refresh (ghr_) tokens grant API access scoped to a user or GitHub App installation. Depending on scope, an attacker can read private repositories, push commits, modify Actions workflows, and exfiltrate source and secrets \u2014 a frequent supply-chain entry point.",
        'remediation': "1. Revoke the token (GitHub App installation or OAuth authorization) immediately\\n2. Audit repository and Actions logs for unauthorized access\\n3. Issue short-lived installation tokens server-side instead of embedding tokens",
    },
    {
        'name': "Mailchimp API Key",
        'category': "Email & Messaging Secrets",
        'regex': "(?<![A-Za-z0-9])[0-9a-f]{32}-us[0-9]{1,2}(?![A-Za-z0-9])",
        'flags': "g",
        'severity': "high",
        'confidence': 90,
        'impact': "A Mailchimp API key (hex string suffixed with the datacenter, e.g. -us21) grants full account access: export entire audience lists with subscriber PII, send campaigns from the owner's verified domain (brand-damaging phishing), and alter automations. High data-protection and reputational impact.",
        'remediation': "1. Revoke the API key in Mailchimp account settings\\n2. Generate a new key and store it server-side\\n3. Review recent campaign and export activity",
    },
    {
        'name': "Facebook Access Token",
        'category': "Social & Marketing Secrets",
        'regex': "EAA[A-Za-z0-9]{60,}",
        'flags': "g",
        'severity': "high",
        'confidence': 80,
        'impact': "A Facebook/Meta Graph API access token (EAA\u2026) can act on behalf of a user, page or app \u2014 reading profile/page data, posting content, managing ads, and spending the connected ad account's budget. Page and Business Manager tokens carry significant financial and reputational risk.",
        'remediation': "1. Invalidate the token via the Meta Graph API / app dashboard\\n2. Reduce granted permissions (scopes) to the minimum required\\n3. Keep long-lived tokens server-side and exchange short-lived tokens client-side",
    },
    {
        'name': "Dropbox Access Token",
        'category': "Cloud Secrets",
        'regex': "(?<![A-Za-z0-9])sl\\\\.[A-Za-z0-9_-]{100,}(?![A-Za-z0-9_-])",
        'flags': "g",
        'severity': "high",
        'confidence': 85,
        'impact': "A Dropbox access token (sl.\u2026) provides API access to the linked account or team folder. Depending on scope, an attacker can list and download all files (data exfiltration), upload or delete content, and enumerate shared links \u2014 exposing potentially sensitive business documents.",
        'remediation': "1. Revoke the token in the Dropbox App Console / connected apps\\n2. Issue scoped, short-lived tokens server-side\\n3. Audit file access and sharing activity",
    },
    {
        'name': "Braintree Access Token",
        'category': "Payment & Financial Secrets",
        'regex': "access_token\\\\$production\\\\$[0-9a-z]{16}\\\\$[0-9a-f]{32}",
        'flags': "g",
        'severity': "critical",
        'confidence': 95,
        'impact': "A Braintree production access token grants API control over the payment gateway: create and refund transactions, read customer vault data and payment-method tokens, and manage subscriptions. Direct financial loss and exposure of stored customer payment data result.",
        'remediation': "1. Revoke the access token in the Braintree Control Panel\\n2. Review recent transactions and refunds\\n3. Use server-side-only credentials and tokenize payments client-side",
    },
    {
        'name': "Adyen API Key",
        'category': "Payment & Financial Secrets",
        'regex': "(?<![A-Za-z0-9/+=])AQE[A-Za-z0-9+/]{40,}=*",
        'flags': "g",
        'severity': "high",
        'confidence': 70,
        'impact': "An Adyen API key (AQE\u2026) authenticates calls to the Adyen payment platform \u2014 initiating payments, modifications (capture/refund/cancel) and querying transaction data. Depending on the associated web-service user's roles, this enables financial manipulation and exposure of transaction details.",
        'remediation': "1. Disable/regenerate the API key for the web-service user in the Adyen Customer Area\\n2. Restrict the key by allowed origins/IP where supported\\n3. Keep the key server-side only",
    },
    {
        'name': "Pusher App Secret",
        'category': "Communication Secrets",
        'regex': "pusher[_\\\\s-]?(?:app[_\\\\s-]?)?secret[\\\\s]*[=:]\\\\s*[\\\"']([a-z0-9]{20,})[\\\"']",
        'flags': "gi",
        'severity': "high",
        'confidence': 70,
        'impact': "The Pusher Channels app secret allows signing of authentication tokens for private and presence channels. An attacker can subscribe to private channels (eavesdropping on real-time data), impersonate users in presence channels, and trigger events to all connected clients.",
        'remediation': "1. Roll the app secret in the Pusher dashboard\\n2. Keep the secret server-side and authenticate channel subscriptions via your backend\\n3. Audit channel activity for abuse",
    },
    {
        'name': "LaunchDarkly SDK Key",
        'category': "SaaS Tokens",
        'regex': "(?:sdk|api|mob)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
        'flags': "g",
        'severity': "high",
        'confidence': 80,
        'impact': "A LaunchDarkly key \u2014 especially the server-side SDK key (sdk-) or API token (api-) \u2014 exposes feature-flag configuration and, for API tokens, the ability to read and toggle flags. An attacker can enable hidden/unreleased features, disable kill-switches, or manipulate rollouts affecting application behaviour.",
        'remediation': "1. Reset the SDK key / revoke the API token in LaunchDarkly account settings\\n2. Use only client-side IDs in browser code, never server SDK keys\\n3. Review flag change history",
    },
    {
        'name': "Twitter/X Bearer Token",
        'category': "Social & Marketing Secrets",
        'regex': "(?<![A-Za-z0-9])AAAAAAAAAA[A-Za-z0-9%]{40,}",
        'flags': "g",
        'severity': "high",
        'confidence': 75,
        'impact': "A Twitter/X API v2 bearer token authenticates app-level API calls \u2014 reading tweets, user data and analytics, and (depending on app permissions) posting or deleting content. Abuse leads to data scraping, spam, and reputational damage to the connected account.",
        'remediation': "1. Regenerate the bearer token in the X developer portal\\n2. Keep app credentials server-side only\\n3. Scope app permissions to the minimum required",
    },
    {
        'name': "Twitter/X API Secret",
        'category': "Social & Marketing Secrets",
        'regex': "(?:twitter|x)[_\\\\s-]?(?:api|consumer)[_\\\\s-]?secret[\\\\s]*[=:]\\\\s*[\\\"']([A-Za-z0-9]{40,50})[\\\"']",
        'flags': "gi",
        'severity': "high",
        'confidence': 65,
        'impact': "The Twitter/X API (consumer) secret, paired with the API key, lets an attacker authenticate as the application, mint tokens, and act on behalf of authorizing users \u2014 enabling content posting, DM access and data harvesting.",
        'remediation': "1. Regenerate the API key/secret pair in the X developer portal\\n2. Store secrets server-side\\n3. Audit recent API activity",
    },
    {
        'name': "Facebook App Secret",
        'category': "Social & Marketing Secrets",
        'regex': "(?:fb|facebook)[_\\\\s-]?app[_\\\\s-]?secret[\\\\s]*[=:]\\\\s*[\\\"']([a-f0-9]{32})[\\\"']",
        'flags': "gi",
        'severity': "critical",
        'confidence': 70,
        'impact': "The Facebook/Meta app secret authenticates the application to the Graph API. With it, an attacker can generate app access tokens, impersonate the app, exchange user login codes for tokens, and access the connected ad account \u2014 direct account-takeover and financial risk.",
        'remediation': "1. Reset the app secret in the Meta App Dashboard\\n2. Enable 'Require App Secret' for API calls\\n3. Keep the secret server-side only",
    },
    {
        'name': "LinkedIn Client Secret",
        'category': "Social & Marketing Secrets",
        'regex': "linkedin[_\\\\s-]?(?:client[_\\\\s-]?)?secret[\\\\s]*[=:]\\\\s*[\\\"']([A-Za-z0-9]{16,})[\\\"']",
        'flags': "gi",
        'severity': "high",
        'confidence': 65,
        'impact': "The LinkedIn OAuth client secret allows an attacker to complete the authorization-code exchange and obtain access tokens for users who authorize the app, enabling profile data access and posting on their behalf.",
        'remediation': "1. Regenerate the client secret in the LinkedIn developer console\\n2. Store it server-side only\\n3. Review authorized members and scopes",
    },
    {
        'name': "Klaviyo Private Key",
        'category': "Email & Messaging Secrets",
        'regex': "(?<![A-Za-z0-9_])pk_[a-f0-9]{34}(?![A-Za-z0-9])",
        'flags': "g",
        'severity': "high",
        'confidence': 85,
        'impact': "A Klaviyo private API key (pk_\u2026) grants full account access: export subscriber profiles and PII, send or schedule campaigns and flows from the verified sending domain, and modify lists. High data-protection and brand-phishing impact.",
        'remediation': "1. Revoke the private API key in Klaviyo account settings\\n2. Use scoped/public keys client-side; keep private keys server-side\\n3. Review recent exports and campaigns",
    },
    {
        'name': "Coinbase API Key",
        'category': "Payment & Financial Secrets",
        'regex': "coinbase[_\\\\s-]?(?:api[_\\\\s-]?)?(?:key|secret)[\\\\s]*[=:]\\\\s*[\\\"']([A-Za-z0-9]{16,})[\\\"']",
        'flags': "gi",
        'severity': "critical",
        'confidence': 70,
        'impact': "Coinbase API credentials can authorize cryptocurrency operations \u2014 reading balances and transaction history, and depending on scope, initiating transfers/withdrawals. Crypto transactions are irreversible, so leakage can cause direct, unrecoverable financial loss.",
        'remediation': "1. Delete the API key in Coinbase settings immediately\\n2. Enable IP allowlisting and disable withdrawal scopes where possible\\n3. Review account activity and enable 2FA",
    },
    {
        'name': "Klarna API Credential",
        'category': "Payment & Financial Secrets",
        'regex': "klarna[_\\\\s-]?(?:api[_\\\\s-]?)?(?:key|secret|password|username)[\\\\s]*[=:]\\\\s*[\\\"']([A-Za-z0-9_:-]{16,})[\\\"']",
        'flags': "gi",
        'severity': "high",
        'confidence': 65,
        'impact': "Klarna API credentials (username/password pair) authorize payment-session creation, order management, captures and refunds. An attacker can manipulate orders and refunds, causing financial loss and exposing customer order data.",
        'remediation': "1. Rotate the Klarna API credentials in the merchant portal\\n2. Keep credentials server-side only\\n3. Review recent orders and refunds",
    },
    {
        'name': "PubNub Key",
        'category': "Communication Secrets",
        'regex': "(?:pub|sub)-c-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        'flags': "gi",
        'severity': "high",
        'confidence': 90,
        'impact': "PubNub publish/subscribe keys allow joining channels to read real-time messages and, with the publish key, broadcasting messages to all subscribers. Exposure enables eavesdropping on real-time data streams and message injection.",
        'remediation': "1. Rotate the keyset in the PubNub admin dashboard\\n2. Enable PubNub Access Manager (PAM) to require grant tokens\\n3. Restrict the subscribe key's permissions",
    },
    {
        'name': "Ably API Key",
        'category': "Communication Secrets",
        'regex': "(?<![A-Za-z0-9._-])[A-Za-z0-9_-]{4,16}\\\\.[A-Za-z0-9_-]{4,16}:[A-Za-z0-9+/]{30,46}={0,2}(?![A-Za-z0-9_+/=])",
        'flags': "g",
        'severity': "high",
        'confidence': 65,
        'impact': "An Ably API key (appId.keyId:keySecret) grants the capabilities assigned to it \u2014 typically publish/subscribe to channels and presence. An attacker can read real-time data, publish messages, and enter presence sets, depending on the key's permissions.",
        'remediation': "1. Revoke the API key in the Ably dashboard\\n2. Issue short-lived token requests from your server instead of embedding API keys\\n3. Restrict key capabilities and channels",
    },
    {
        'name': "Agora App Certificate",
        'category': "Communication Secrets",
        'regex': "agora[_\\\\s-]?(?:app[_\\\\s-]?)?(?:certificate|cert|secret)[\\\\s]*[=:]\\\\s*[\\\"']([a-f0-9]{32})[\\\"']",
        'flags': "gi",
        'severity': "high",
        'confidence': 65,
        'impact': "The Agora app certificate is used to generate authentication tokens for real-time voice/video channels. Leaked, an attacker can mint valid tokens to join any channel \u2014 eavesdropping on calls and consuming the owner's billable minutes.",
        'remediation': "1. Rotate the app certificate in the Agora console\\n2. Generate tokens server-side only\\n3. Review usage for anomalous minutes",
    },
    {
        'name': "GetStream API Secret",
        'category': "Communication Secrets",
        'regex': "(?:getstream|stream)[_\\\\s-]?(?:api[_\\\\s-]?)?secret[\\\\s]*[=:]\\\\s*[\\\"']([A-Za-z0-9]{40,})[\\\"']",
        'flags': "gi",
        'severity': "high",
        'confidence': 65,
        'impact': "A Stream (getstream.io) API secret grants server-side access to chat/feeds: read and write messages and activities, generate user tokens, and impersonate any user. Full compromise of the chat/feed data and identity layer.",
        'remediation': "1. Rotate the API secret in the Stream dashboard\\n2. Keep the secret server-side; mint user tokens on the backend\\n3. Review app activity",
    },
    {
        'name': "MessageBird API Key",
        'category': "Communication Secrets",
        'regex': "messagebird[_\\\\s-]?(?:api[_\\\\s-]?)?key[\\\\s]*[=:]\\\\s*[\\\"']([A-Za-z0-9]{25})[\\\"']",
        'flags': "gi",
        'severity': "high",
        'confidence': 70,
        'impact': "A MessageBird (Bird) API key authorizes sending SMS/voice/messaging on the owner's account. An attacker can send messages at the owner's expense (toll fraud), run smishing campaigns from a trusted sender, and read message logs.",
        'remediation': "1. Revoke the API key in the MessageBird dashboard\\n2. Keep keys server-side\\n3. Review messaging and billing activity",
    },
    {
        'name': "Vonage / Nexmo API Secret",
        'category': "Communication Secrets",
        'regex': "(?:nexmo|vonage)[_\\\\s-]?(?:api[_\\\\s-]?)?secret[\\\\s]*[=:]\\\\s*[\\\"']([A-Za-z0-9]{16})[\\\"']",
        'flags': "gi",
        'severity': "high",
        'confidence': 65,
        'impact': "Vonage/Nexmo API key+secret authorize SMS and voice APIs. An attacker can send messages and place calls billed to the account (toll fraud), send phishing SMS from a trusted number, and access communication logs.",
        'remediation': "1. Rotate the API secret in the Vonage dashboard\\n2. Keep credentials server-side\\n3. Set spending limits and review usage",
    },
    {
        'name': "Contentful Personal Access Token",
        'category': "CMS & Content Secrets",
        'regex': "CFPAT-[A-Za-z0-9_-]{40,}",
        'flags': "g",
        'severity': "high",
        'confidence': 90,
        'impact': "A Contentful Management personal access token (CFPAT-) grants full content-management access: read, create, update and delete entries, assets and content models across spaces the user can access. Enables content defacement and data exfiltration.",
        'remediation': "1. Revoke the token in Contentful account settings\\n2. Use the read-only Delivery API token client-side, never the management token\\n3. Review space activity logs",
    },
    {
        'name': "Sanity API Token",
        'category': "CMS & Content Secrets",
        'regex': "sanity[_\\\\s-]?(?:api[_\\\\s-]?)?token[\\\\s]*[=:]\\\\s*[\\\"']([A-Za-z0-9]{40,})[\\\"']",
        'flags': "gi",
        'severity': "high",
        'confidence': 65,
        'impact': "A Sanity API token (especially with write/deploy permissions) allows reading and modifying dataset documents and assets. An attacker can exfiltrate content, deface published data, and depending on scope, alter the project configuration.",
        'remediation': "1. Revoke the token in the Sanity project's API settings\\n2. Use read-only tokens client-side\\n3. Review dataset history",
    },
    {
        'name': "Strapi API Token",
        'category': "CMS & Content Secrets",
        'regex': "strapi[_\\\\s-]?(?:api[_\\\\s-]?)?token[\\\\s]*[=:]\\\\s*[\\\"']([A-Za-z0-9]{40,})[\\\"']",
        'flags': "gi",
        'severity': "high",
        'confidence': 60,
        'impact': "A Strapi API token authenticates against the headless CMS REST/GraphQL API. Depending on its access level (read-only / full access / custom), an attacker can read protected content types and, at higher levels, create, update or delete content.",
        'remediation': "1. Revoke the token in the Strapi admin (Settings \u2192 API Tokens)\\n2. Issue read-only, time-limited tokens for client use\\n3. Review content changes",
    },
    {
        'name': "Rollbar Access Token",
        'category': "Monitoring Secrets",
        'regex': "rollbar[_\\\\s-]?(?:access[_\\\\s-]?)?token[\\\\s]*[=:]\\\\s*[\\\"']([a-f0-9]{32})[\\\"']",
        'flags': "gi",
        'severity': "high",
        'confidence': 65,
        'impact': "A Rollbar access token can read or write error data depending on scope. A write/admin token lets attackers inject fake items or read error payloads, which often contain sensitive request data, stack traces and internal context useful for further attacks.",
        'remediation': "1. Rotate the project access token in Rollbar settings\\n2. Use post_client_item (scoped) tokens client-side only\\n3. Review item data for leaked sensitive context",
    },
    {
        'name': "Bugsnag API Key",
        'category': "Monitoring Secrets",
        'regex': "bugsnag[_\\\\s-]?(?:api[_\\\\s-]?)?key[\\\\s]*[=:]\\\\s*[\\\"']([a-f0-9]{32})[\\\"']",
        'flags': "gi",
        'severity': "high",
        'confidence': 65,
        'impact': "A Bugsnag/Insight Hub API key (notifier or personal auth token) allows reporting errors and, for personal tokens, reading error data and project configuration. Error payloads frequently leak sensitive request and environment data.",
        'remediation': "1. Regenerate the API key / revoke the personal token in Bugsnag settings\\n2. Treat notifier keys as public but personal auth tokens as secret (server-side)\\n3. Review error payloads for sensitive data",
    },
    {
        'name': "Grafana Service Account Token",
        'category': "Monitoring Secrets",
        'regex': "glsa_[A-Za-z0-9]{32}_[0-9a-f]{8}",
        'flags': "g",
        'severity': "high",
        'confidence': 95,
        'impact': "A Grafana service account token (glsa_) grants API access to dashboards, data sources and, with admin scope, user and org management. An attacker can read internal metrics/dashboards (infrastructure reconnaissance) and modify configuration.",
        'remediation': "1. Revoke the service account token in Grafana\\n2. Scope the service account to least privilege\\n3. Review dashboard and data-source access",
    },
    {
        'name': "Elastic Cloud Credential",
        'category': "Infrastructure & Data Secrets",
        'regex': "(?:elastic|elasticsearch)[_\\\\s-]?(?:cloud[_\\\\s-]?)?(?:api[_\\\\s-]?key|password)[\\\\s]*[=:]\\\\s*[\\\"']([A-Za-z0-9=+\\\\/_-]{20,})[\\\"']",
        'flags': "gi",
        'severity': "high",
        'confidence': 65,
        'impact': "Elasticsearch/Elastic Cloud credentials (API key or elastic superuser password) grant access to the cluster: read and search all indexed data (often PII, logs and business records), and at high privilege, modify or delete indices.",
        'remediation': "1. Rotate the API key / reset the elastic password\\n2. Use scoped, role-based API keys instead of the superuser\\n3. Restrict cluster network access and review audit logs",
    },
    {
        'name': "Snowflake Credential",
        'category': "Infrastructure & Data Secrets",
        'regex': "snowflake[_\\\\s-]?(?:password|pwd|private[_\\\\s-]?key)[\\\\s]*[=:]\\\\s*[\\\"']([^\\\"']{8,})[\\\"']",
        'flags': "gi",
        'severity': "critical",
        'confidence': 65,
        'impact': "Snowflake account credentials provide access to the data warehouse. Depending on the role, an attacker can query and exfiltrate large volumes of analytical data (often containing PII and business-critical records) and run compute that incurs cost.",
        'remediation': "1. Rotate the user's password / key-pair in Snowflake\\n2. Enforce MFA and network policies\\n3. Review query history for unauthorized access",
    },
    {
        'name': "Fastly API Token",
        'category': "Infrastructure & Data Secrets",
        'regex': "fastly[_\\\\s-]?(?:api[_\\\\s-]?)?(?:key|token)[\\\\s]*[=:]\\\\s*[\\\"']([A-Za-z0-9_-]{32})[\\\"']",
        'flags': "gi",
        'severity': "high",
        'confidence': 70,
        'impact': "A Fastly API token allows management of CDN configuration: edit VCL/services, purge cache, and reconfigure routing. An attacker can cause outages, redirect or poison cached traffic, and exfiltrate service configuration.",
        'remediation': "1. Revoke the token in the Fastly account\\n2. Scope tokens to specific services and least privilege\\n3. Review configuration change history",
    },
    {
        'name': "Pulumi Access Token",
        'category': "CI/CD & DevOps Secrets",
        'regex': "pul-[0-9a-f]{40}",
        'flags': "g",
        'severity': "critical",
        'confidence': 90,
        'impact': "A Pulumi access token grants API access to infrastructure-as-code state and stacks. An attacker can read stack state (which frequently contains plaintext secrets and resource details) and, with write access, run deployments that modify cloud infrastructure.",
        'remediation': "1. Revoke the token in the Pulumi Cloud console\\n2. Treat stack state as sensitive; use a secrets provider for encryption\\n3. Review stack update history",
    },
    {
        'name': "Box Developer Token",
        'category': "Cloud Secrets",
        'regex': "box[_\\\\s-]?(?:developer[_\\\\s-]?)?(?:token|access[_\\\\s-]?token)[\\\\s]*[=:]\\\\s*[\\\"']([A-Za-z0-9]{32,})[\\\"']",
        'flags': "gi",
        'severity': "high",
        'confidence': 65,
        'impact': "A Box access/developer token authorizes API access to the Box account's files and folders. An attacker can download (exfiltrate), upload, share and delete content \u2014 exposing potentially sensitive business documents.",
        'remediation': "1. Revoke the token / app authorization in the Box admin console\\n2. Use short-lived OAuth tokens issued server-side\\n3. Review file access and sharing activity",
    },
    {
        'name': "crates.io API Token",
        'category': "Package Registry Secrets",
        'regex': "(?<![A-Za-z0-9])cio[A-Za-z0-9]{32}(?![A-Za-z0-9])",
        'flags': "g",
        'severity': "critical",
        'confidence': 80,
        'impact': "A crates.io API token (cio\u2026) allows publishing and yanking Rust crates for the owner's account. An attacker can push malicious versions of packages, compromising every downstream project that depends on them \u2014 a supply-chain attack.",
        'remediation': "1. Revoke the token in crates.io account settings\\n2. Use scoped tokens with expiry where possible\\n3. Audit recently published crate versions",
    },
    {
        'name': "Packagist / Composer Token",
        'category': "Package Registry Secrets",
        'regex': "(?:packagist|composer)[_\\\\s-]?(?:api[_\\\\s-]?)?(?:token|key)[\\\\s]*[=:]\\\\s*[\\\"']([A-Za-z0-9]{20,})[\\\"']",
        'flags': "gi",
        'severity': "high",
        'confidence': 60,
        'impact': "A Packagist/Composer API token allows managing PHP package metadata and triggering updates for the owner's packages. Depending on scope, an attacker could redirect or tamper with package sources \u2014 a PHP supply-chain risk.",
        'remediation': "1. Regenerate the token in Packagist account settings\\n2. Keep tokens out of client-side and committed code\\n3. Review package update activity",
    },
]


# =====================================================================
# 4. JavaScript Secret Scanner Engine
# =====================================================================
class JavaScriptSecretScanner:
    def __init__(self):
        self.compiled_patterns = []
        for p in GHOSTJS_RAW_PATTERNS:
            try:
                # Unescape Java string escape sequences to raw regex
                raw_re = p["regex"].encode().decode("unicode_escape")
                flags = 0
                if "i" in p["flags"]:
                    flags |= re.IGNORECASE
                if "s" in p["flags"]:
                    flags |= re.DOTALL
                if "m" in p["flags"]:
                    flags |= re.MULTILINE

                compiled = re.compile(raw_re, flags)
                self.compiled_patterns.append({
                    "meta": p,
                    "compiled": compiled,
                    "needs_entropy": p["confidence"] < 85
                })
            except Exception as e:
                pass

    def scan(self, text: str, source_url: str = "") -> List[Dict[str, Any]]:
        """Scans input string against 150+ patterns with Shannon entropy suppression."""
        findings = []
        if not text:
            return findings

        lines = text.splitlines()
        seen_matches = set()

        for pat in self.compiled_patterns:
            meta = pat["meta"]
            compiled = pat["compiled"]
            needs_entropy = pat["needs_entropy"]
            min_ent = 3.0 if needs_entropy else 0.0

            try:
                for match in compiled.finditer(text):
                    # Pick capturing group 1 if present, else full match
                    val = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                    if not val:
                        continue
                    val = val.strip()

                    # Deduplication key
                    key = (meta["name"], val)
                    if key in seen_matches:
                        continue

                    # False-positive filtering
                    if ShannonEntropyFilter.is_likely_false_positive(val, meta["name"], min_entropy=min_ent):
                        continue

                    seen_matches.add(key)

                    # Compute approximate line number and snippet
                    start_pos = match.start()
                    line_num = text.count("\n", 0, start_pos) + 1
                    line_text = lines[line_num - 1] if line_num - 1 < len(lines) else ""
                    snippet = line_text.strip()[:180]

                    # Mask sensitive value for display
                    if len(val) > 8:
                        masked = val[:4] + "*" * (len(val) - 8) + val[-4:]
                    else:
                        masked = "***REDACTED***"

                    findings.append({
                        "name": meta["name"],
                        "category": meta["category"],
                        "severity": meta["severity"].upper(),
                        "confidence": meta["confidence"],
                        "raw_value": val,
                        "masked_value": masked,
                        "source_url": source_url or "inline",
                        "line": line_num,
                        "snippet": snippet,
                        "entropy": round(ShannonEntropyFilter.shannon_entropy(val), 2),
                        "impact": meta["impact"],
                        "remediation": meta["remediation"]
                    })
            except Exception:
                continue

        return findings


# =====================================================================
# 5. Autonomous GhostJS Web & Bundle Analyzer
# =====================================================================
class GhostJsAnalyzer:
    SCRIPT_TAG_REGEX = re.compile(r"""<script[^>]+src\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
    JS_BUNDLE_REF_REGEX = re.compile(r"""['"]((?:https?://|\.{0,2}/)[^'"\s]+?\.m?js(?:\?[^'"]*)?)['"]""", re.IGNORECASE)

    def __init__(self, concurrency: int = 10, timeout: float = 6.0):
        self.scanner = JavaScriptSecretScanner()
        self.concurrency = concurrency
        self.timeout = timeout

    def scan_content(self, content: str, source_url: str = "") -> Dict[str, Any]:
        """Scans raw JS/JSON/HTML string and extracts secrets, endpoints, and storage URLs."""
        secrets = self.scanner.scan(content, source_url=source_url)
        discovery = EndpointAndStorageExtractor.extract_endpoints_and_assets(content, base_url=source_url)
        
        return {
            "source": source_url or "inline",
            "secrets_count": len(secrets),
            "secrets": secrets,
            "api_endpoints": discovery["api_endpoints"],
            "cloud_storage": discovery["cloud_storage"],
            "source_maps": discovery["source_maps"],
            "summary": {
                "critical": sum(1 for s in secrets if s["severity"] == "CRITICAL"),
                "high": sum(1 for s in secrets if s["severity"] == "HIGH"),
                "medium": sum(1 for s in secrets if s["severity"] == "MEDIUM"),
                "low": sum(1 for s in secrets if s["severity"] == "LOW"),
                "endpoints": len(discovery["api_endpoints"]),
                "cloud_buckets": len(discovery["cloud_storage"]),
                "source_maps": len(discovery["source_maps"]),
            }
        }

    def scan_file(self, filepath: str) -> Dict[str, Any]:
        """Scans local JavaScript, JSON, or HTML file."""
        if not os.path.exists(filepath):
            return {"error": f"File not found: {filepath}", "secrets": []}
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return self.scan_content(content, source_url=filepath)
        except Exception as e:
            return {"error": str(e), "secrets": []}

    async def scan_url(self, target_url: str, active_fetch_bundles: bool = True) -> Dict[str, Any]:
        """
        Fetches the target URL, inspects page content, extracts all linked JavaScript
        bundles (<script src="...">), downloads and scans each bundle concurrently.
        """
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 SWA-GhostJS/2.1",
            "Accept": "*/*"
        }

        all_secrets = []
        all_endpoints = []
        all_cloud_storage = []
        all_source_maps = []
        scanned_assets = []

        async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=True, headers=headers) as client:
            # 1. Fetch initial target
            try:
                resp = await client.get(target_url)
                body = resp.text
                scanned_assets.append(target_url)
            except Exception as e:
                return {
                    "target_url": target_url,
                    "error": f"Failed to fetch initial target: {e}",
                    "secrets": [],
                    "api_endpoints": [],
                    "cloud_storage": [],
                    "source_maps": [],
                }

            # Scan main page content
            main_res = self.scan_content(body, source_url=target_url)
            all_secrets.extend(main_res["secrets"])
            all_endpoints.extend(main_res["api_endpoints"])
            all_cloud_storage.extend(main_res["cloud_storage"])
            all_source_maps.extend(main_res["source_maps"])

            # 2. Discover referenced JavaScript bundles
            discovered_bundle_urls = set()
            if active_fetch_bundles:
                # Script src attributes
                for m in self.SCRIPT_TAG_REGEX.finditer(body):
                    raw_src = m.group(1).strip()
                    if raw_src and not raw_src.startswith("data:"):
                        abs_url = urljoin(target_url, raw_src)
                        discovered_bundle_urls.add(abs_url)

                # Relative/absolute JS paths in code
                for m in self.JS_BUNDLE_REF_REGEX.finditer(body):
                    raw_ref = m.group(1).strip()
                    if raw_ref and not raw_ref.startswith("data:"):
                        abs_url = urljoin(target_url, raw_ref)
                        discovered_bundle_urls.add(abs_url)

                # Filter to max 25 bundles to prevent DOS/delays
                bundle_list = list(discovered_bundle_urls)[:25]
                sem = asyncio.Semaphore(self.concurrency)

                async def fetch_and_scan_bundle(b_url: str):
                    async with sem:
                        try:
                            b_resp = await client.get(b_url)
                            if b_resp.status_code == 200 and b_resp.text:
                                scanned_assets.append(b_url)
                                b_res = self.scan_content(b_resp.text, source_url=b_url)
                                return b_res
                        except Exception:
                            pass
                        return None

                if bundle_list:
                    bundle_tasks = [fetch_and_scan_bundle(u) for u in bundle_list]
                    bundle_results = await asyncio.gather(*bundle_tasks)

                    for b_res in bundle_results:
                        if b_res:
                            all_secrets.extend(b_res["secrets"])
                            all_endpoints.extend(b_res["api_endpoints"])
                            all_cloud_storage.extend(b_res["cloud_storage"])
                            all_source_maps.extend(b_res["source_maps"])

        # Deduplicate endpoints & storage
        unique_endpoints = {e["path"]: e for e in all_endpoints}.values()
        unique_cloud = {c["url"]: c for c in all_cloud_storage}.values()
        unique_maps = {m["resolved_url"]: m for m in all_source_maps}.values()

        return {
            "target_url": target_url,
            "scanned_assets_count": len(scanned_assets),
            "scanned_assets": scanned_assets,
            "secrets_count": len(all_secrets),
            "secrets": all_secrets,
            "api_endpoints": list(unique_endpoints),
            "cloud_storage": list(unique_cloud),
            "source_maps": list(unique_maps),
            "summary": {
                "critical": sum(1 for s in all_secrets if s["severity"] == "CRITICAL"),
                "high": sum(1 for s in all_secrets if s["severity"] == "HIGH"),
                "medium": sum(1 for s in all_secrets if s["severity"] == "MEDIUM"),
                "low": sum(1 for s in all_secrets if s["severity"] == "LOW"),
                "total_secrets": len(all_secrets),
                "endpoints_discovered": len(unique_endpoints),
                "cloud_buckets": len(unique_cloud),
                "source_maps": len(unique_maps),
            }
        }
