"""
Memory & Learning System
=========================
Persistent learning across scans — inspired by Hermes Agent's learning loop
and ECC's continuous learning system.

Components:
- ScanMemory: Per-scan state and findings storage
- GlobalMemory: Cross-scan knowledge accumulation
- DedupEngine: Finding deduplication across scans
- SkillGenerator: Auto-generate skills from findings
- KnowledgeGraph: Relationships between vulnerabilities, targets, and techniques
"""

from .scan_memory import ScanMemory
from .global_memory import GlobalMemory
from .dedup_engine import DedupEngine
from .skill_generator import SkillGenerator

__all__ = [
    "ScanMemory",
    "GlobalMemory",
    "DedupEngine",
    "SkillGenerator",
]
