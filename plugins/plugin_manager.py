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

        limits = httpx.Limits(max_keepalive_connections=30, max_connections=60)
        async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True, limits=limits) as client:
            async def run_single_plugin(plugin: BaseSecurityPlugin):
                try:
                    res = await asyncio.wait_for(
                        plugin.run(scan_id, client, endpoints, recon_data, log_callback),
                        timeout=25.0
                    )
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

    async def run_single_plugin(self, plugin_id: str, target: str, scan_id: Optional[str] = None) -> Dict[str, Any]:
        """Executes a single specified OWASP plugin against the target URL."""
        plugin = self.get_plugin(plugin_id)
        if not plugin:
            return {"status": "ERROR", "error": f"Plugin '{plugin_id}' not found", "findings": []}
        
        target_clean = target if target.startswith("http") else f"https://{target}"
        endpoint = DiscoveredEndpoint(url=target_clean, method="GET")
        
        limits = httpx.Limits(max_keepalive_connections=10, max_connections=20)
        findings = []
        async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True, limits=limits) as client:
            try:
                res = await asyncio.wait_for(
                    plugin.run(scan_id or "adhoc_plugin_scan", client, [endpoint], {}),
                    timeout=20.0
                )
                findings = res or []
            except Exception as e:
                return {
                    "status": "ERROR",
                    "plugin_id": plugin_id,
                    "plugin_name": plugin.name,
                    "target": target,
                    "error": str(e),
                    "findings": []
                }
        
        # Save any findings to DB
        from core.database import db
        for f in findings:
            try:
                db.save_finding(f)
            except Exception:
                pass

        return {
            "status": "COMPLETED",
            "plugin_id": plugin_id,
            "plugin_name": plugin.name,
            "owasp_category": plugin.owasp_category,
            "target": target,
            "findings_count": len(findings),
            "findings": [f.model_dump() if hasattr(f, "model_dump") else f for f in findings],
            "passed": len(findings) == 0
        }

    async def run_all_enabled_plugins(self, target: str, scan_id: Optional[str] = None) -> Dict[str, Any]:
        """Runs all enabled OWASP Top 10 plugins against the target URL."""
        target_clean = target if target.startswith("http") else f"https://{target}"
        endpoint = DiscoveredEndpoint(url=target_clean, method="GET")
        
        findings = await self.execute_all(
            scan_id=scan_id or "owasp_audit",
            endpoints=[endpoint],
            recon_data={}
        )
        
        from core.database import db
        for f in findings:
            try:
                db.save_finding(f)
            except Exception:
                pass

        return {
            "status": "COMPLETED",
            "target": target,
            "total_plugins": len(self.plugins),
            "enabled_plugins": sum(1 for p in self.plugins.values() if p.enabled),
            "findings_count": len(findings),
            "findings": [f.model_dump() if hasattr(f, "model_dump") else f for f in findings]
        }

plugin_manager = SecurityPluginManager()
