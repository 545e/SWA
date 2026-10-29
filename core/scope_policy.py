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
    "0.0.0.0",
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
        self._last_mtime: float = 0.0
        self._load_config()

    def _load_config(self):
        """Loads configured target allowlist from targets.json if available."""
        if os.path.isfile(self.config_path):
            try:
                mtime = os.path.getmtime(self.config_path)
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        new_domains = set()
                        for item in data:
                            if isinstance(item, dict) and item.get("enabled", True):
                                domain = item.get("domain") or item.get("target")
                                if domain:
                                    clean = self._normalize_hostname(domain)
                                    new_domains.add(clean)
                        self.allowed_domains = new_domains
                self._last_mtime = mtime
            except Exception:
                pass

    def check_reload(self):
        """Reloads targets.json if the file was modified on disk."""
        try:
            if os.path.isfile(self.config_path):
                mtime = os.path.getmtime(self.config_path)
                if mtime != self._last_mtime:
                    self._load_config()
        except Exception:
            pass

    def add_target(self, domain: str, description: str = "Authorized target domain", profile: str = "standard") -> bool:
        """Dynamically authorizes a domain and persists it to targets.json."""
        clean = self._normalize_hostname(domain)
        if not clean:
            return False
        self.allowed_domains.add(clean)
        try:
            records = []
            if os.path.isfile(self.config_path):
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        records = data
            exists = any(r.get("domain") == clean for r in records if isinstance(r, dict))
            if not exists:
                records.append({
                    "domain": clean,
                    "profile": profile,
                    "enabled": True,
                    "description": description
                })
                with open(self.config_path, "w", encoding="utf-8") as f:
                    json.dump(records, f, indent=2)
                self._last_mtime = os.path.getmtime(self.config_path)
        except Exception:
            pass
        return True

    def _normalize_hostname(self, target: str) -> str:
        t = target.strip().lower()
        try:
            ip = ipaddress.ip_address(t)
            return str(ip)
        except ValueError:
            pass

        if "://" in t:
            parsed = urlparse(t)
            t = parsed.hostname or t
        elif t.startswith("//"):
            parsed = urlparse(t)
            t = parsed.hostname or t
        else:
            if t.startswith("[") and "]" in t:
                end_bracket = t.find("]")
                t = t[1:end_bracket]
            elif ":" in t and t.count(":") == 1:
                t = t.split(":")[0]
            else:
                parsed = urlparse("//" + t)
                if parsed.hostname:
                    t = parsed.hostname
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
            mapped = getattr(ip_obj, "ipv4_mapped", None)
            if mapped:
                is_restr, reason = self.is_private_or_restricted(str(mapped))
                if is_restr:
                    return True, f"IPv4-mapped restricted address ({reason})"

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
            if ip_obj.is_reserved or ip_obj.is_unspecified:
                return True, "Reserved or Unspecified IP space"
            return False, "Public IP"
        except ValueError:
            return False, "Invalid IP string"

    def validate_target(self, target_input: str, explicit_lab_authorization: bool = False) -> ScopeValidationResult:
        """
        Validates target authorization and guards against SSRF / unauthorized scope expansion.
        """
        self.check_reload()
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
        is_loopback = False
        if self.is_ip_address(hostname):
            try:
                is_loopback = ipaddress.ip_address(hostname).is_loopback or hostname == "0.0.0.0"
            except ValueError:
                pass

        is_lab = (
            hostname in DEFAULT_ALLOWED_LAB_TARGETS
            or is_loopback
            or any(hostname.endswith(f".{lt}") for lt in DEFAULT_ALLOWED_LAB_TARGETS if not self.is_ip_address(lt))
        )

        # Check explicit lab authorization
        lab_authorized = explicit_lab_authorization or self.allow_lab_mode

        # DNS Resolution & Rebinding Check (Evaluate all returned IPs)
        resolved_ips = []
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            for item in addr_info:
                ip_cand = item[4][0]
                if ip_cand not in resolved_ips:
                    resolved_ips.append(ip_cand)
        except Exception as e:
            return ScopeValidationResult(
                is_allowed=False,
                target=clean_target,
                hostname=hostname,
                reason=f"Failed to resolve DNS for target '{hostname}': {str(e)}",
                error_code="DNS_RESOLUTION_FAILURE"
            )

        # SSRF & Private IP Inspection across all resolved IPs
        for ip in resolved_ips:
            is_restricted, restriction_reason = self.is_private_or_restricted(ip)
            if is_restricted:
                if is_lab and lab_authorized:
                    return ScopeValidationResult(
                        is_allowed=True,
                        target=clean_target,
                        hostname=hostname,
                        resolved_ip=ip,
                        is_lab_target=True,
                        reason=f"Target permitted under Authorized Lab Mode ({restriction_reason})."
                    )
                else:
                    return ScopeValidationResult(
                        is_allowed=False,
                        target=clean_target,
                        hostname=hostname,
                        resolved_ip=ip,
                        is_lab_target=is_lab,
                        reason=f"SSRF Protection: Target resolves to restricted address: {ip} ({restriction_reason}). Enable Lab Mode for authorized local testing.",
                        error_code="SSRF_RESTRICTED_IP"
                    )
        resolved_ip = resolved_ips[0] if resolved_ips else None

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
