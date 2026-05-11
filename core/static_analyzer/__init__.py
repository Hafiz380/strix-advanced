"""
Strix-Advanced Static Analysis Engine
=====================================
CPG-based white-box security analysis with LLM-guided vulnerability detection.

Architecture:
    Source Code → AST (tree-sitter) → Control Flow Graph → Data Flow Graph → CPG
    CPG → Source-Sink Analysis → Sanitizer Check → LLM Validation → Findings

Inspired by Shannon's CPG approach but uses tree-sitter instead of Joern
for portability and speed.
"""

from .cpg_builder import CPGBuilder
from .data_flow import DataFlowAnalyzer
from .sanitizer_analyzer import SanitizerAnalyzer
from .findings import Finding, FindingSeverity, FindingConfidence

__all__ = [
    "CPGBuilder",
    "DataFlowAnalyzer",
    "SanitizerAnalyzer",
    "Finding",
    "FindingSeverity",
    "FindingConfidence",
]
