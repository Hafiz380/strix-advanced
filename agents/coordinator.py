"""
Coordinator Agent
==================
Orchestrates all specialized agents for comprehensive security testing.

Workflow:
1. Recon → Discover attack surface
2. Analysis → Find vulnerabilities in code
3. Exploit → Validate findings with PoCs
4. Report → Generate comprehensive report

Inspired by Strix's root_agent skill but with better specialization.
"""

from dataclasses import dataclass, field
from typing import Any, Optional

from .recon_agent import ReconAgent, ReconResult
from .exploit_agent import ExploitAgent, ExploitTarget, ExploitResult
from .analysis_agent import AnalysisAgent, AnalysisTarget, AnalysisResult
from .report_agent import ReportAgent, ReportConfig


@dataclass
class ScanConfig:
    """Configuration for a full security scan."""
    target: str
    scan_type: str = "full"  # "full", "quick", "recon_only", "code_only"
    
    # Scope
    scope: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    
    # Auth
    auth_url: str = ""
    username: str = ""
    password: str = ""
    totp_secret: str = ""
    
    # Analysis
    code_path: str = ""  # Local code path for white-box
    include_tests: bool = False
    
    # Depth
    recon_depth: str = "standard"  # "quick", "standard", "deep"
    max_exploits: int = 50
    
    # Output
    report_config: ReportConfig = field(default_factory=ReportConfig)


@dataclass
class ScanProgress:
    """Progress of a security scan."""
    phase: str  # "recon", "analysis", "exploit", "report"
    status: str  # "running", "completed", "failed"
    progress: float  # 0.0 to 1.0
    message: str = ""
    findings_count: int = 0


class CoordinatorAgent:
    """
    Main orchestrator for security assessments.
    
    Usage:
        coordinator = CoordinatorAgent(http_client=client)
        
        results = await coordinator.run_scan(ScanConfig(
            target="https://target.com",
            scan_type="full",
            code_path="/path/to/source",
        ))
        
        print(results["report"])
    """
    
    def __init__(self, http_client=None, llm_provider: str = None, llm_api_key: str = None):
        self.http = http_client
        self.recon_agent = ReconAgent(http_client)
        self.exploit_agent = ExploitAgent(http_client)
        self.analysis_agent = AnalysisAgent(llm_provider, llm_api_key)
        self.report_agent = ReportAgent()
        self._progress_callbacks = []
    
    def on_progress(self, callback):
        """Register progress callback."""
        self._progress_callbacks.append(callback)
    
    def _notify_progress(self, progress: ScanProgress):
        """Notify all progress callbacks."""
        for callback in self._progress_callbacks:
            callback(progress)
    
    async def run_scan(self, config: ScanConfig) -> dict[str, Any]:
        """
        Run a complete security scan.
        
        Returns dict with:
        - "recon": ReconResult
        - "analysis": AnalysisResult
        - "exploits": list[ExploitResult]
        - "chains": list[ExploitChain]
        - "race_conditions": list[RaceTestResult]
        - "report": str (markdown)
        """
        results = {}
        
        # Phase 1: Reconnaissance
        if config.scan_type in ("full", "recon_only"):
            self._notify_progress(ScanProgress(
                phase="recon", status="running", progress=0.0,
                message="Starting reconnaissance..."
            ))
            
            try:
                results["recon"] = await self.recon_agent.recon(
                    config.target, config.recon_depth
                )
                self._notify_progress(ScanProgress(
                    phase="recon", status="completed", progress=1.0,
                    message=f"Recon complete: {len(results['recon'].subdomains)} subdomains, {len(results['recon'].endpoints)} endpoints",
                    findings_count=len(results["recon"].subdomains) + len(results["recon"].endpoints),
                ))
            except Exception as e:
                results["recon"] = None
                self._notify_progress(ScanProgress(
                    phase="recon", status="failed", progress=0.0,
                    message=f"Recon failed: {e}",
                ))
        
        # Phase 2: Static Analysis
        if config.scan_type in ("full", "code_only") and config.code_path:
            self._notify_progress(ScanProgress(
                phase="analysis", status="running", progress=0.0,
                message="Starting static analysis..."
            ))
            
            try:
                results["analysis"] = await self.analysis_agent.analyze(
                    AnalysisTarget(path=config.code_path)
                )
                self._notify_progress(ScanProgress(
                    phase="analysis", status="completed", progress=1.0,
                    message=f"Analysis complete: {len(results['analysis'].findings)} findings",
                    findings_count=len(results["analysis"].findings),
                ))
            except Exception as e:
                results["analysis"] = None
                self._notify_progress(ScanProgress(
                    phase="analysis", status="failed", progress=0.0,
                    message=f"Analysis failed: {e}",
                ))
        
        # Phase 3: Exploitation
        if config.scan_type == "full":
            self._notify_progress(ScanProgress(
                phase="exploit", status="running", progress=0.0,
                message="Starting exploitation..."
            ))
            
            exploits = []
            
            # Exploit findings from static analysis
            if results.get("analysis") and results["analysis"].findings:
                for i, finding in enumerate(results["analysis"].findings[:config.max_exploits]):
                    self._notify_progress(ScanProgress(
                        phase="exploit", status="running",
                        progress=i / min(len(results["analysis"].findings), config.max_exploits),
                        message=f"Exploiting {finding.vuln_type}...",
                    ))
                    
                    result = await self.exploit_agent.exploit(ExploitTarget(
                        url=config.target,
                        vuln_type=finding.vuln_type,
                        endpoint=finding.location.file_path,
                        parameter=finding.location.function_name,
                    ))
                    exploits.append(result)
            
            results["exploits"] = exploits
            
            # Find exploit chains
            from core.exploitation import ExploitChainBuilder
            chain_builder = ExploitChainBuilder()
            
            # Convert findings to Vulnerability objects for chain analysis
            from core.exploitation.chain_builder import Vulnerability
            vulns = []
            if results.get("analysis") and results["analysis"].findings:
                for f in results["analysis"].findings:
                    vulns.append(Vulnerability(
                        id=f.id,
                        vuln_type=f.vuln_type,
                        severity=f.severity.value,
                        title=f.title,
                        description=f.description,
                        file_path=f.location.file_path,
                        endpoint="",
                        poc=f.evidence.poc if hasattr(f.evidence, 'poc') else "",
                    ))
            
            results["chains"] = chain_builder.analyze(vulns)
            
            self._notify_progress(ScanProgress(
                phase="exploit", status="completed", progress=1.0,
                message=f"Exploitation complete: {sum(1 for e in exploits if e.exploited)} confirmed",
                findings_count=sum(1 for e in exploits if e.exploited),
            ))
        
        # Phase 4: Report Generation
        self._notify_progress(ScanProgress(
            phase="report", status="running", progress=0.0,
            message="Generating report..."
        ))
        
        try:
            config.report_config.client_name = config.target
            results["report"] = self.report_agent.generate_full_report(
                config=config.report_config,
                recon_results=results.get("recon"),
                analysis_results=results.get("analysis"),
                exploit_results=results.get("exploits"),
                chains=results.get("chains"),
            )
            self._notify_progress(ScanProgress(
                phase="report", status="completed", progress=1.0,
                message="Report generated",
            ))
        except Exception as e:
            results["report"] = f"Report generation failed: {e}"
            self._notify_progress(ScanProgress(
                phase="report", status="failed", progress=0.0,
                message=f"Report failed: {e}",
            ))
        
        return results
    
    async def quick_scan(self, target: str) -> dict[str, Any]:
        """Quick scan - recon + basic exploitation."""
        return await self.run_scan(ScanConfig(
            target=target,
            scan_type="full",
            recon_depth="quick",
            max_exploits=10,
        ))
    
    async def code_review(self, code_path: str, target: str = "") -> dict[str, Any]:
        """Code review only - static analysis + report."""
        return await self.run_scan(ScanConfig(
            target=target or code_path,
            scan_type="code_only",
            code_path=code_path,
        ))
