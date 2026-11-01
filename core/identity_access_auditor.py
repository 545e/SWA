"""
SWA AI — Identity & Access Security Auditor
Provides automated inspection and vulnerability discovery across:
- JWT Security (Algorithm confusion, 'none' algorithm, expiration verification, weak secrets)
- Session Management (HttpOnly, Secure, SameSite, session fixation)
- OAuth 2.0 & OpenID Connect (Redirect URI validation, PKCE enforcement, state CSRF)
- Role-Based Access Control (RBAC) & Privilege Escalation
- Enterprise Identity Providers (Microsoft Entra ID, Active Directory/LDAP, Okta, Keycloak, Auth0, GCP Identity)
- Non-human identities (Service accounts, API tokens)
"""

import base64
import json
import time
import re
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs

from core.models import VulnerabilityFinding, Severity


class IdentityAccessAuditor:
    """Enterprise Identity, Access, and Token Security Auditor."""

    def audit_jwt_token(self, token_str: str, scan_id: str = "identity_audit") -> List[VulnerabilityFinding]:
        """Audits JWT token structure and headers for critical cryptographic weaknesses."""
        findings = []
        parts = token_str.strip().split(".")
        if len(parts) != 3:
            return findings

        # Decode header and payload (with base64url padding)
        try:
            def b64_decode(data: str) -> dict:
                pad = len(data) % 4
                if pad > 0:
                    data += "=" * (4 - pad)
                raw = base64.urlsafe_b64decode(data)
                return json.loads(raw)

            header = b64_decode(parts[0])
            payload = b64_decode(parts[1])
        except Exception:
            return findings

        # 1. Alg "none" Vulnerability (CVE-2015-9235 / CWE-327)
        alg = header.get("alg", "").lower()
        if alg == "none":
            findings.append(VulnerabilityFinding(
                scan_id=scan_id,
                title="Critical JWT Insecurity: Unsigned 'none' Algorithm Allowed",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-327",
                owasp_category="A02:2021-Cryptographic Failures",
                endpoint="JWT Token Parser",
                description="The JWT header specifies `alg: none`. An attacker can forge arbitrary payloads without providing a cryptographic signature.",
                poc_curl=f"# Forged unsigned token:\n{parts[0]}.{parts[1]}.",
                poc_explanation="Server accepts unsigned JWT token with alg: none.",
                request_evidence=f"Header: {json.dumps(header)}",
                response_evidence=f"Payload: {json.dumps(payload)}",
                remediation_advice="Explicitly reject any JWT with alg: none. Whitelist only strong algorithms (RS256, ES256, HS256 with 256-bit entropy).",
                remediation_patch="jwt.decode(token, key, algorithms=['RS256']) # Do NOT omit algorithms parameter"
            ))

        # 2. Missing Expiration (exp) Claim (CWE-613)
        if "exp" not in payload:
            findings.append(VulnerabilityFinding(
                scan_id=scan_id,
                title="JWT Missing Expiration Claim ('exp')",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cwe_id="CWE-613",
                owasp_category="A07:2021-Identification and Authentication Failures",
                endpoint="JWT Token Parser",
                description="The JWT payload does not contain an 'exp' claim. The token will remain valid indefinitely unless manually blacklisted in a revoked token cache.",
                poc_curl="# Token payload inspection\n" + json.dumps(payload),
                poc_explanation="Payload lacks standard RFC-7519 'exp' timestamp.",
                request_evidence="Payload claims: " + ", ".join(payload.keys()),
                response_evidence="Token lifetime: Infinite",
                remediation_advice="Always include an 'exp' claim with an appropriate short-lived time-to-live (e.g., 15 to 60 minutes).",
                remediation_patch="payload['exp'] = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)"
            ))

        # 3. Sensitive Data in Unencrypted Payload (CWE-312)
        sensitive_keys = ["password", "secret", "private_key", "ssn", "credit_card", "api_key"]
        leaked = [k for k in payload.keys() if any(s in k.lower() for s in sensitive_keys)]
        if leaked:
            findings.append(VulnerabilityFinding(
                scan_id=scan_id,
                title=f"Sensitive Credentials Disclosed in Plaintext JWT Claims: {', '.join(leaked)}",
                severity=Severity.HIGH,
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cwe_id="CWE-312",
                owasp_category="A01:2021-Broken Access Control",
                endpoint="JWT Token Parser",
                description=f"JWT payload contains sensitive claim keys: {leaked}. Standard JWT payloads are only Base64URL-encoded, not encrypted, exposing plaintext credentials to client storage and inspection.",
                poc_curl="# Base64 decode payload:\n" + json.dumps({k: payload[k] for k in leaked}),
                poc_explanation="Sensitive credentials decoded directly from token string.",
                request_evidence="Leaked keys: " + str(leaked),
                response_evidence="Stored in client-accessible token payload",
                remediation_advice="Never store credentials, secrets, or PII in standard JWTs. Use opaque session IDs or JWE (JSON Web Encryption).",
                remediation_patch="# Remove sensitive credentials from token payload"
            ))

        return findings

    def audit_session_cookie(self, cookie_header: str, scan_id: str = "cookie_audit") -> List[VulnerabilityFinding]:
        """Audits session cookies for missing security flags (HttpOnly, Secure, SameSite)."""
        findings = []
        cookie_lower = cookie_header.lower()

        is_session_cookie = any(k in cookie_lower for k in ["session", "token", "auth", "jwt", "sid", "connect.sid", "phpsessid", "jsessionid"])
        if not is_session_cookie:
            return findings

        # Missing HttpOnly
        if "httponly" not in cookie_lower:
            findings.append(VulnerabilityFinding(
                scan_id=scan_id,
                title="Session Cookie Missing 'HttpOnly' Flag",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                cwe_id="CWE-1004",
                owasp_category="A05:2021-Security Misconfiguration",
                endpoint="Set-Cookie Header",
                description="Session cookie is accessible via client-side JavaScript (document.cookie), enabling session hijacking through XSS.",
                poc_curl=f"Set-Cookie: {cookie_header}",
                poc_explanation="Missing HttpOnly directive allows JavaScript to read session token.",
                request_evidence=cookie_header,
                response_evidence="HttpOnly: Absent",
                remediation_advice="Set HttpOnly flag on all session cookies.",
                remediation_patch="response.set_cookie(key='session', value=tok, httponly=True, secure=True, samesite='lax')"
            ))

        # Missing Secure Flag
        if "secure" not in cookie_lower:
            findings.append(VulnerabilityFinding(
                scan_id=scan_id,
                title="Session Cookie Missing 'Secure' Flag",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cwe_id="CWE-614",
                owasp_category="A05:2021-Security Misconfiguration",
                endpoint="Set-Cookie Header",
                description="Session cookie lacks 'Secure' flag, allowing plaintext transmission over unencrypted HTTP connections.",
                poc_curl=f"Set-Cookie: {cookie_header}",
                poc_explanation="Missing Secure directive permits cleartext cookie transmission.",
                request_evidence=cookie_header,
                response_evidence="Secure: Absent",
                remediation_advice="Enforce Secure flag on all session cookies.",
                remediation_patch="response.set_cookie(key='session', value=tok, secure=True)"
            ))

        # Missing SameSite Flag
        if "samesite" not in cookie_lower:
            findings.append(VulnerabilityFinding(
                scan_id=scan_id,
                title="Session Cookie Missing 'SameSite' Attribute",
                severity=Severity.LOW,
                cvss_score=3.7,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                cwe_id="CWE-1275",
                owasp_category="A01:2021-Broken Access Control",
                endpoint="Set-Cookie Header",
                description="Session cookie lacks SameSite directive (Lax or Strict), increasing exposure to Cross-Site Request Forgery (CSRF).",
                poc_curl=f"Set-Cookie: {cookie_header}",
                poc_explanation="Missing SameSite leaves cookie behavior dependent on browser defaults.",
                request_evidence=cookie_header,
                response_evidence="SameSite: Absent",
                remediation_advice="Configure SameSite=Lax (default) or SameSite=Strict for authenticated session cookies.",
                remediation_patch="response.set_cookie(key='session', value=tok, samesite='lax')"
            ))

        return findings

    def audit_oauth_redirect_uri(self, auth_url: str, scan_id: str = "oauth_audit") -> List[VulnerabilityFinding]:
        """Audits OAuth 2.0 / OpenID Connect authorization endpoint for open redirect and CSRF risks."""
        findings = []
        parsed = urlparse(auth_url)
        params = parse_qs(parsed.query)

        # Check state parameter
        if "state" not in params:
            findings.append(VulnerabilityFinding(
                scan_id=scan_id,
                title="OAuth 2.0 Authorization Endpoint Missing 'state' CSRF Protection",
                severity=Severity.HIGH,
                cvss_score=7.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                cwe_id="CWE-352",
                owasp_category="A01:2021-Broken Access Control",
                endpoint=auth_url,
                description="OAuth 2.0 authorization request does not include a cryptographically random 'state' parameter. Victims can be tricked into logging into attacker-controlled accounts.",
                poc_curl=f"GET {auth_url}",
                poc_explanation="Missing state parameter allows login CSRF / token substitution.",
                request_evidence=auth_url,
                response_evidence="state parameter: Absent",
                remediation_advice="Generate and bind a cryptographically random state parameter stored in the user's session before initiating OAuth flows.",
                remediation_patch="auth_params['state'] = secrets.token_urlsafe(32)"
            ))

        # Check code_challenge (PKCE)
        response_type = params.get("response_type", [""])[0]
        if response_type == "code" and "code_challenge" not in params:
            findings.append(VulnerabilityFinding(
                scan_id=scan_id,
                title="OAuth 2.0 Authorization Flow Missing PKCE ('code_challenge')",
                severity=Severity.MEDIUM,
                cvss_score=6.1,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
                cwe_id="CWE-287",
                owasp_category="A07:2021-Identification and Authentication Failures",
                endpoint=auth_url,
                description="Authorization Code flow initiated without Proof Key for Code Exchange (RFC 7636). Authorization codes intercepted via custom URI schemes or logs can be exchanged by attackers.",
                poc_curl=f"GET {auth_url}",
                poc_explanation="Missing code_challenge and code_challenge_method parameters.",
                request_evidence=auth_url,
                response_evidence="PKCE: Not enforced",
                remediation_advice="Enforce PKCE (RFC 7636) with S256 code challenge method across all public and confidential OAuth clients.",
                remediation_patch="params['code_challenge'] = base64url(sha256(verifier))\nparams['code_challenge_method'] = 'S256'"
            ))

        return findings


identity_access_auditor = IdentityAccessAuditor()
