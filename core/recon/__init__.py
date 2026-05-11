"""
Unique Features
================
Features that set Strix-Advanced apart from other security tools.

Components:
- APIDiscovery: Auto-discover and fuzz API endpoints
- SupplyChain: Dependency vulnerability analysis
- Infrastructure: Cloud/DNS/SSL misconfiguration detection
- CustomRules: User-defined attack pattern engine
"""

from .api_discovery import APIDiscovery
from .supply_chain import SupplyChainAnalyzer
from .infrastructure import InfrastructureAnalyzer
from .custom_rules import CustomRuleEngine

__all__ = [
    "APIDiscovery",
    "SupplyChainAnalyzer",
    "InfrastructureAnalyzer",
    "CustomRuleEngine",
]
