"""
SWA AI — Integrations Module
"""

from core.integrations.base import BaseIntegrationAdapter
from core.integrations.registry import IntegrationRegistry, integration_registry

__all__ = ["BaseIntegrationAdapter", "IntegrationRegistry", "integration_registry"]
