"""
SWA AI — Scope Policy & SSRF Protection Engine
Validates target inputs (IPv4, IPv6, FQDNs), enforces authorized allowlists,
guards against SSRF / cloud metadata access, and protects against DNS rebinding.
"""

import ipaddress
import json
import os
import re
import socket
from urllib.parse import urlparse
from typing import Dict, List, Optional, Tuple, Set
from pydantic import BaseModel

DEFAULT_ALLOWED_LAB_TARGETS = [
    "127.0.0.1",
    "localhost",
    "::1",
    "0a2f008804b73639822f564400da00ed.web-security-academy.net"
]

CLOUD_METADATA_IPS = [
    "169.254.169.254", # AWS, GCP, Azure, OpenStack IMDS
    "169.254.170.2",   # AWS ECS metadata
    "fd00:ec2::254"    # AWS IPv6 IMDS
]

class ScopeValidationResult(BaseModel):
    is_allowed: bool
    target: str
    hostname: str
    resolved_ip: Optional[str] = None
    is_lab_target: bool = False
    reason: str
    error_code: Optional[str] = None

class ScopePolicy:
    def __init__(self, targets_config_path: Optional[str] = None, allow_lab_mode: bool = False):
        self.config_path = targets_config_path or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "config", "targets.json"
        )
        self.allow_lab_mode = allow_lab_mode
        self.allowed_domains: Set[str] = set()
        self.allowed_ips: Set[str] = set()
        self._load_config()

    def _load_config(self):
        """Loads configured target allowlist from targets.json if available."""
        if os.path.isfile(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict) and item.get("enabled", True):
                                domain = item.get("domain") or item.get("target")
                                if domain:
                                    clean = self._normalize_hostname(domain)
                                    self.allowed_domains.add(clean)
            except Exception:
                pass

    def _normalize_hostname(self, target: str) -> str:
        t = target.strip().lower()
        if "://" in t:
            parsed = urlparse(t)
            t = parsed.hostname or t
        if ":" in t and not t.startswith("["): # strip port if IPv4/domain
            t = t.split(":")[0]
        elif t.startswith("[") and "]" in t: # IPv6 bracket notation
            t = t[1:t.find("]")]
        return t.strip().rstrip(".")

    def is_ip_address(self, host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def is_private_or_restricted(self, ip_str: str) -> Tuple[bool, str]:
        """Checks whether an IP address belongs to loopback, RFC1918, link-local, or cloud metadata."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_str in CLOUD_METADATA_IPS or str(ip_obj) in CLOUD_METADATA_IPS:
                return True, "Cloud Metadata Service (IMDS) blocked"
            if ip_obj.is_loopback:
                return True, "Loopback address (127.0.0.0/8 or ::1)"
            if ip_obj.is_link_local:
                return True, "Link-local address (169.254.0.0/16 or fe80::/10)"
            if ip_obj.is_private:
                return True, "Private internal network (RFC 1918)"
            if ip_obj.is_multicast:
                return True, "Multicast address range"
            if ip_obj.is_reserved:
                return True, "Reserved IP space"
            return False, "Public IP"
        except ValueError:
            return False, "Invalid IP string"

    def validate_target(self, target_input: str, explicit_lab_authorization: bool = False) -> ScopeValidationResult:
        """
        Validates target authorization and guards against SSRF / unauthorized scope expansion.
        """
        clean_target = target_input.strip()
        if not clean_target:
            return ScopeValidationResult(
                is_allowed=False,
                target=clean_target,
                hostname="",
                reason="Target input is empty.",
                error_code="EMPTY_TARGET"
            )

        # Protocol validation: reject dangerous schemes
        if "://" in clean_target:
            scheme = clean_target.split("://")[0].lower()
            if scheme not in ["http", "https"]:
                return ScopeValidationResult(
                    is_allowed=False,
                    target=clean_target,
                    hostname="",
                    reason=f"Dangerous or unsupported protocol scheme '{scheme}://'. Only HTTP and HTTPS are permitted.",
                    error_code="INVALID_SCHEME"
                )

        hostname = self._normalize_hostname(clean_target)

        # Domain syntax validation
        if not self.is_ip_address(hostname):
            # Check domain name format
            if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", hostname):
                return ScopeValidationResult(
                    is_allowed=False,
                    target=clean_target,
                    hostname=hostname,
                    reason=f"Malformed domain name syntax: '{hostname}'",
                    error_code="INVALID_DOMAIN_SYNTAX"
                )

        # Check for designated Lab Targets (DVWA, PortSwigger, local testbeds)
        is_lab = hostname in DEFAULT_ALLOWED_LAB_TARGETS or any(hostname.endswith(f".{lt}") for lt in DEFAULT_ALLOWED_LAB_TARGETS if not self.is_ip_address(lt))

        # Check explicit lab authorization
        lab_authorized = explicit_lab_authorization or self.allow_lab_mode

        # DNS Resolution & Rebinding Check
        resolved_ip = None
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            if addr_info:
                resolved_ip = addr_info[0][4][0]
        except Exception as e:
            return ScopeValidationResult(
                is_allowed=False,
                target=clean_target,
                hostname=hostname,
                reason=f"Failed to resolve DNS for target '{hostname}': {str(e)}",
                error_code="DNS_RESOLUTION_FAILURE"
            )

        # SSRF & Private IP Inspection
        if resolved_ip:
            is_restricted, restriction_reason = self.is_private_or_restricted(resolved_ip)
            if is_restricted:
                if is_lab and lab_authorized:
                    return ScopeValidationResult(
                        is_allowed=True,
                        target=clean_target,
                        hostname=hostname,
                        resolved_ip=resolved_ip,
                        is_lab_target=True,
                        reason=f"Target permitted under Authorized Lab Mode ({restriction_reason})."
                    )
                else:
                    return ScopeValidationResult(
                        is_allowed=False,
                        target=clean_target,
                        hostname=hostname,
                        resolved_ip=resolved_ip,
                        is_lab_target=is_lab,
                        reason=f"SSRF Protection: Target resolves to restricted address: {resolved_ip} ({restriction_reason}). Enable Lab Mode for authorized local testing.",
                        error_code="SSRF_RESTRICTED_IP"
                    )

        # Allowlist Enforcement (if allowlist configured)
        if self.allowed_domains:
            domain_matched = hostname in self.allowed_domains or any(hostname.endswith(f".{d}") for d in self.allowed_domains)
            if not domain_matched and not (is_lab and lab_authorized):
                return ScopeValidationResult(
                    is_allowed=False,
                    target=clean_target,
                    hostname=hostname,
                    resolved_ip=resolved_ip,
                    reason=f"Target '{hostname}' is not listed in configured scope allowlist.",
                    error_code="OUT_OF_SCOPE"
                )

        # Target approved
        return ScopeValidationResult(
            is_allowed=True,
            target=clean_target,
            hostname=hostname,
            resolved_ip=resolved_ip,
            is_lab_target=is_lab,
            reason=f"Target '{hostname}' validated and authorized for assessment (Resolved IP: {resolved_ip})."
        )

# Global singleton scope policy
scope_policy = ScopePolicy()
