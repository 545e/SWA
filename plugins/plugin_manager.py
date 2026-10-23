"""
SWA AI Security Plugin Manager
Central registry and execution manager for modular security audit plugins.
"""

import asyncio
from typing import List, Dict, Any, Optional
import httpx

from core.models import DiscoveredEndpoint, VulnerabilityFinding
from plugins.base_plugin import BaseSecurityPlugin
from plugins.owasp_plugins import (
    PluginA01_BrokenAccessControl,
    PluginA02_CryptographicFailures,
    PluginA03_Injection,
    PluginA04_InsecureDesign,
    PluginA05_SecurityMisconfiguration,
    PluginA06_VulnerableComponents,
    PluginA07_AuthFailures,
    PluginA08_IntegrityFailures,
    PluginA09_LoggingMonitoring,
    PluginA10_SSRF,
)

class SecurityPluginManager:
    """Manages lifecycle, registration, and parallel execution of audit plugins."""

    def __init__(self):
        self.plugins: Dict[str, BaseSecurityPlugin] = {}
        self._register_default_plugins()

    def _register_default_plugins(self):
        default_classes = [
            PluginA01_BrokenAccessControl,
            PluginA02_CryptographicFailures,
            PluginA03_Injection,
            PluginA04_InsecureDesign,
            PluginA05_SecurityMisconfiguration,
            PluginA06_VulnerableComponents,
            PluginA07_AuthFailures,
            PluginA08_IntegrityFailures,
            PluginA09_LoggingMonitoring,
            PluginA10_SSRF,
        ]
        for cls in default_classes:
            instance = cls()
            self.plugins[instance.plugin_id] = instance

    def list_plugins(self) -> List[Dict[str, Any]]:
        return [p.to_dict() for p in self.plugins.values()]

    def get_plugin(self, plugin_id: str) -> Optional[BaseSecurityPlugin]:
        return self.plugins.get(plugin_id)

    def toggle_plugin(self, plugin_id: str, enabled: Optional[bool] = None) -> bool:
        p = self.plugins.get(plugin_id)
        if not p:
            return False
        if enabled is None:
            p.enabled = not p.enabled
        else:
            p.enabled = enabled
        return p.enabled

    def get_owasp_matrix(self) -> List[Dict[str, Any]]:
        matrix = []
        for p in self.plugins.values():
            matrix.append({
                "owasp_code": p.owasp_category.split("-")[0].strip(),
                "category_name": p.owasp_category,
                "plugin_name": p.name,
                "plugin_id": p.plugin_id,
                "cwe": p.cwe_id,
                "default_severity": p.default_severity.value,
                "status": "Active" if p.enabled else "Disabled"
            })
        return matrix

    async def execute_all(
        self,
        scan_id: str,
        endpoints: List[DiscoveredEndpoint],
        recon_data: Any,
        log_callback=None,
        active_plugins: Optional[List[str]] = None
    ) -> List[VulnerabilityFinding]:
        """Run all enabled security plugins concurrently."""
        findings: List[VulnerabilityFinding] = []
        enabled_plugins = [
            p for p in self.plugins.values()
            if p.enabled and (active_plugins is None or p.plugin_id in active_plugins)
        ]

        if log_callback:
            await log_callback(f"Dispatching {len(enabled_plugins)} OWASP security plugins across {len(endpoints)} target endpoints...", "INFO")

        async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True) as client:
            async def run_single_plugin(plugin: BaseSecurityPlugin):
                try:
                    res = await plugin.run(scan_id, client, endpoints, recon_data, log_callback)
                    return res or []
                except Exception as e:
                    if log_callback:
                        await log_callback(f"Plugin {plugin.name} error: {str(e)}", "WARN")
                    return []

            tasks = [run_single_plugin(p) for p in enabled_plugins]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in results:
                if isinstance(r, list):
                    findings.extend(r)

        return findings

# Singleton plugin manager instance
plugin_manager = SecurityPluginManager()
