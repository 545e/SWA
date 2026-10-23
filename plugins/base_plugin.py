"""
SWA AI Security Plugin Architecture
Base class and interfaces for modular, extensible OWASP Top 10 and security plugins.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import httpx

from core.models import DiscoveredEndpoint, VulnerabilityFinding, Severity

class BaseSecurityPlugin(ABC):
    """Abstract base class for all SWA AI security auditing plugins."""

    def __init__(
        self,
        plugin_id: str,
        name: str,
        owasp_category: str,
        description: str,
        cwe_id: str = "CWE-699",
        default_severity: Severity = Severity.MEDIUM,
        enabled: bool = True
    ):
        self.plugin_id = plugin_id
        self.name = name
        self.owasp_category = owasp_category
        self.description = description
        self.cwe_id = cwe_id
        self.default_severity = default_severity
        self.enabled = enabled

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.plugin_id,
            "name": self.name,
            "owasp_category": self.owasp_category,
            "description": self.description,
            "cwe_id": self.cwe_id,
            "default_severity": self.default_severity.value,
            "enabled": self.enabled
        }

    @abstractmethod
    async def run(
        self,
        scan_id: str,
        client: httpx.AsyncClient,
        endpoints: List[DiscoveredEndpoint],
        recon_data: Any,
        log_callback: Any = None
    ) -> List[VulnerabilityFinding]:
        """
        Execute security verification tests against target endpoints.
        Must return a list of verified VulnerabilityFinding objects.
        """
        pass
