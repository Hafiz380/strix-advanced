"""
Specialized Agent System
=========================
Enhanced agent orchestration with specialized roles for different
security testing phases.

Agents:
- ReconAgent: Asset discovery, technology fingerprinting, attack surface mapping
- ExploitAgent: Vulnerability exploitation and PoC development
- AnalysisAgent: Static analysis and code review
- ReportAgent: Finding documentation and report generation
- CoordinatorAgent: Orchestrates all agents and manages workflow

Inspired by Strix's agent system but with specialization like Shannon.
"""

from .recon_agent import ReconAgent
from .exploit_agent import ExploitAgent
from .analysis_agent import AnalysisAgent
from .report_agent import ReportAgent
from .coordinator import CoordinatorAgent

__all__ = [
    "ReconAgent",
    "ExploitAgent",
    "AnalysisAgent",
    "ReportAgent",
    "CoordinatorAgent",
]
