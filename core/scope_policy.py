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

    @property
    def allowed(self) -> bool:
        return self.is_allowed

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

    def validate_target(self, target_input: str, explicit_lab_authorization: bool = False, lab_mode: Optional[bool] = None, auto_authorize: bool = False) -> ScopeValidationResult:
        if lab_mode is not None:
            explicit_lab_authorization = lab_mode
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
                if auto_authorize:
                    self.add_target(hostname, description="Operator authorized assessment target")
                    return ScopeValidationResult(
                        is_allowed=True,
                        target=clean_target,
                        hostname=hostname,
                        resolved_ip=resolved_ip,
                        is_lab_target=is_lab,
                        reason=f"Target '{hostname}' validated and dynamically authorized for operator assessment."
                    )
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


# --- Tool-Execution Layer Scope Enforcement ---
class ScopeViolation(Exception):
    """Raised when a tool invocation targets an unauthorised or SSRF-unsafe host."""
    def __init__(self, result: "ScopeValidationResult"):
        super().__init__(result.reason)
        self.result = result


# Enforcement modes:
#   "strict"  - every tool target must be allowlisted or an authorised lab target.
#   "passive" - intrusive tools require authorisation; passive read-only lookups
#               only have to clear the SSRF / restricted-address guard.
#   "off"     - legacy behaviour: SSRF guard only (NOT recommended).
SWA_TOOL_SCOPE_ENFORCEMENT = os.getenv("SWA_TOOL_SCOPE_ENFORCEMENT", "passive").strip().lower()

# Tools that actively touch the target (ports, fuzzing, crawling, templated
# exploits). These are gated strictly because they generate real traffic.
INTRUSIVE_TOOL_IDS = {
    "ports", "probe", "subdomains", "amass", "js-scan", "waf-check",
    "dependency-check", "scan-file", "fuzz",
}


def _restricted_reason(hostname: str) -> Optional[str]:
    """Return a reason string when *hostname* resolves to a restricted address."""
    if not hostname:
        return "Empty target."
    candidate = hostname.strip().lower()
    if candidate in {"localhost", "localhost.localdomain"}:
        return "Loopback hostnames are restricted for this operation."
    try:
        ip_obj = ipaddress.ip_address(candidate)
    except ValueError:
        try:
            infos = socket.getaddrinfo(candidate, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return None  # Unresolvable; let the caller surface the DNS failure.
        if not infos:
            return None
        candidate = infos[0][4][0]
        try:
            ip_obj = ipaddress.ip_address(candidate)
        except ValueError:
            return None
    blocked, reason = scope_policy.is_private_or_restricted(candidate)
    return reason if blocked else None


def _is_builtin_lab_host(hostname: str) -> bool:
    """True when *hostname* is one of the pre-authorised local lab targets."""
    clean = (hostname or "").strip().lower()
    if not clean:
        return False
    if clean in {h.lower() for h in DEFAULT_ALLOWED_LAB_TARGETS}:
        return True
    try:
        if ipaddress.ip_address(clean).is_loopback:
            return True
    except ValueError:
        pass
    return any(clean.endswith(f".{lt.lower()}") for lt in DEFAULT_ALLOWED_LAB_TARGETS
               if not _looks_like_ip(lt))


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_tool_target(target: str, *, tool_id: str) -> ScopeValidationResult:
    """
    Scope gate for ad-hoc security-tool endpoints and tool adapters.

    Every call must clear the SSRF / restricted-address guard and pass basic
    input validation. Intrusive tools additionally require the target to be
    explicitly authorised (allowlist entry or a pre-authorised lab target)
    unless enforcement is relaxed via SWA_TOOL_SCOPE_ENFORCEMENT.
    """
    clean = (target or "").strip()
    if not clean:
        return ScopeValidationResult(
            is_allowed=False, target="", hostname="",
            reason="Target is required.", error_code="EMPTY_TARGET",
        )

    probe_host = scope_policy._normalize_hostname(clean)
    is_builtin_lab = _is_builtin_lab_host(probe_host)

    # 1. Scheme validation for URL-shaped inputs (rejects file://, gopher://, ftp://).
    if "://" in clean:
        scheme = clean.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            return ScopeValidationResult(
                is_allowed=False, target=clean, hostname=probe_host,
                reason=f"Unsupported protocol scheme '{scheme}://'. Only HTTP and HTTPS are permitted.",
                error_code="INVALID_SCHEME",
            )

    # 2. Basic hostname syntax validation (catches shell metacharacters and junk).
    if not _looks_like_ip(probe_host):
        if not _DOMAIN_RE.match(probe_host):
            return ScopeValidationResult(
                is_allowed=False, target=clean, hostname=probe_host,
                reason=f"Malformed target '{probe_host}'. Expected a valid hostname or IP address.",
                error_code="INVALID_TARGET_SYNTAX",
            )

    # 3. Unconditional SSRF / restricted-address guard. Pre-authorised lab
    #    targets (loopback, localhost, the PortSwigger academy host) are exempt.
    if not is_builtin_lab:
        restricted = _restricted_reason(probe_host)
        if restricted:
            return ScopeValidationResult(
                is_allowed=False, target=clean, hostname=probe_host,
                reason=f"Target refused by SSRF guard: {restricted}",
                error_code="SSRF_BLOCKED",
            )

    # 4. Authorisation gate.
    mode = SWA_TOOL_SCOPE_ENFORCEMENT
    if mode == "off":
        return ScopeValidationResult(
            is_allowed=True, target=clean, hostname=probe_host,
            reason="Scope enforcement disabled by configuration (SSRF guard still applied).",
        )

    must_authorise = mode == "strict" or tool_id in INTRUSIVE_TOOL_IDS
    if not must_authorise:
        return ScopeValidationResult(
            is_allowed=True, target=clean, hostname=probe_host,
            reason=f"Passive tool '{tool_id}': validation and SSRF guard passed.",
        )

    result = scope_policy.validate_target(
        clean, explicit_lab_authorization=is_builtin_lab
    )
    if not result.is_allowed:
        result.reason = (
            f"Target '{clean}' is outside the authorised scope for intrusive tool "
            f"'{tool_id}'. {result.reason} Add it to config/targets.json or enable "
            f"lab mode to authorise it."
        )
    return result


def enforce_tool_scope(target: str, *, tool_id: str) -> str:
    """Validate *target* for *tool_id*; raise :class:`ScopeViolation` when refused."""
    result = validate_tool_target(target, tool_id=tool_id)
    if not result.is_allowed:
        raise ScopeViolation(result)
    return result.hostname or target.strip()
