"""
Analysis Agent
===============
Specialized in static and dynamic code analysis.

Integrates with the Static Analysis Engine (Step 2) to perform
white-box security testing.
"""

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class AnalysisTarget:
    """Target for code analysis."""
    path: str
    analysis_type: str = "full"  # "full", "quick", "diff"
    language: str = ""
    exclude_patterns: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


@dataclass
class AnalysisResult:
    """Result of code analysis."""
    target: str
    findings: list = field(default_factory=list)
    cpg_stats: dict = field(default_factory=dict)
    languages_detected: list[str] = field(default_factory=list)
    files_analyzed: int = 0
    duration_seconds: float = 0.0
    metadata: dict = field(default_factory=dict)


class AnalysisAgent:
    """
    Code analysis agent that wraps the Static Analysis Engine.
    
    Usage:
        agent = AnalysisAgent()
        result = await agent.analyze("/path/to/project")
        for finding in result.findings:
            print(f"{finding.severity}: {finding.title}")
    """
    
    def __init__(self, llm_provider: str = None, llm_api_key: str = None):
        self.llm_provider = llm_provider
        self.llm_api_key = llm_api_key
        self._engine = None
    
    def _get_engine(self):
        """Lazy-load the static analysis engine."""
        if self._engine is None:
            from core.static_analyzer import StaticAnalysisEngine
            from core.static_analyzer.engine import AnalysisConfig
            
            config = AnalysisConfig(
                llm_provider=self.llm_provider,
                llm_api_key=self.llm_api_key,
            )
            self._engine = StaticAnalysisEngine(config)
        return self._engine
    
    async def analyze(self, target: AnalysisTarget) -> AnalysisResult:
        """Run static analysis on target."""
        import time
        start = time.time()
        
        engine = self._get_engine()
        
        if not engine.is_available():
            return AnalysisResult(
                target=target.path,
                metadata={"error": f"Engine not available: {engine.get_init_error()}"},
            )
        
        try:
            if target.analysis_type == "quick":
                findings = engine.analyze_files([target.path])
            else:
                findings = engine.analyze_project(
                    target.path,
                    exclude_patterns=target.exclude_patterns,
                )
            
            return AnalysisResult(
                target=target.path,
                findings=findings,
                cpg_stats={"nodes": 0, "edges": 0},  # Would come from CPG
                languages_detected=list(set(f.language for f in findings if f.language)),
                files_analyzed=len(engine.cpg_builder.file_index) if hasattr(engine.cpg_builder, 'file_index') else 0,
                duration_seconds=time.time() - start,
            )
        except Exception as e:
            return AnalysisResult(
                target=target.path,
                metadata={"error": str(e)},
                duration_seconds=time.time() - start,
            )
    
    def generate_report(self, result: AnalysisResult) -> str:
        """Generate analysis report."""
        if not result.findings:
            return "# Code Analysis Report\n\n✅ No vulnerabilities found.\n"
        
        report = f"""# 🔬 Code Analysis Report

**Target:** {result.target}
**Files Analyzed:** {result.files_analyzed}
**Languages:** {', '.join(result.languages_detected)}
**Duration:** {result.duration_seconds:.1f}s
**Findings:** {len(result.findings)}

"""
        
        for finding in result.findings:
            report += finding.to_markdown()
            report += "\n---\n\n"
        
        return report
