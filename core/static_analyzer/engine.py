"""
Static Analysis Engine — Main Integration
==========================================
Ties together CPG builder, data flow analyzer, and sanitizer analyzer
into a single, easy-to-use interface.

Usage:
    from core.static_analyzer import StaticAnalysisEngine
    
    engine = StaticAnalysisEngine()
    
    # Analyze a project directory
    findings = engine.analyze_project("/path/to/project")
    
    # Analyze specific files
    findings = engine.analyze_files(["/path/to/file.py", "/path/to/app.js"])
    
    # Generate report
    report = engine.generate_report(findings)
"""

import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .cpg_builder import CPGBuilder, CPG
from .data_flow import DataFlowAnalyzer, TaintPath
from .sanitizer_analyzer import SanitizerAnalyzer, SanitizerValidation
from .findings import (
    Finding,
    FindingSeverity,
    FindingConfidence,
    FindingLocation,
    FindingEvidence,
    FindingStatus,
    VULN_TYPE_TO_CWE,
    VULN_TYPE_TO_OWASP,
    VULN_TYPE_CVSS_BASE,
)


@dataclass
class AnalysisConfig:
    """Configuration for the static analysis engine."""
    # What to analyze
    include_tests: bool = False
    include_vendor: bool = False
    max_file_size_kb: int = 500
    
    # Analysis depth
    enable_llm_validation: bool = True
    llm_provider: Optional[str] = None
    llm_api_key: Optional[str] = None
    
    # Filtering
    min_severity: FindingSeverity = FindingSeverity.LOW
    min_confidence: FindingConfidence = FindingConfidence.LOW
    
    # Custom patterns
    custom_sources: Optional[dict] = None
    custom_sinks: Optional[dict] = None
    custom_sanitizers: Optional[dict] = None
    
    # Output
    include_code_snippets: bool = True
    code_context_lines: int = 5


class StaticAnalysisEngine:
    """
    Main entry point for static security analysis.
    
    This engine:
    1. Builds a CPG from source code (tree-sitter)
    2. Identifies sources, sinks, and sanitizers
    3. Traces data flow paths (source → sink)
    4. Validates sanitizer effectiveness (LLM or heuristic)
    5. Generates security findings with PoCs
    """
    
    def __init__(self, config: Optional[AnalysisConfig] = None):
        self.config = config or AnalysisConfig()
        self.cpg_builder = CPGBuilder()
        self.data_flow_analyzer = DataFlowAnalyzer(
            custom_sources=self.config.custom_sources,
            custom_sinks=self.config.custom_sinks,
            custom_sanitizers=self.config.custom_sanitizers,
        )
        self.sanitizer_analyzer = SanitizerAnalyzer(
            llm_provider=self.config.llm_provider,
            llm_api_key=self.config.llm_api_key,
        )
    
    def is_available(self) -> bool:
        """Check if the static analysis engine is ready to use."""
        return self.cpg_builder.is_available()
    
    def get_status(self) -> dict[str, Any]:
        """Get engine status and capabilities."""
        return {
            "available": self.is_available(),
            "tree_sitter": self.cpg_builder.is_available(),
            "init_error": self.cpg_builder.get_init_error() if not self.is_available() else None,
            "supported_languages": list(self.cpg_builder.SUPPORTED_EXTENSIONS.values()),
            "llm_validation": self.config.enable_llm_validation,
            "config": {
                "include_tests": self.config.include_tests,
                "min_severity": self.config.min_severity.value,
                "min_confidence": self.config.min_confidence.value,
            }
        }
    
    def analyze_project(
        self,
        project_path: str,
        exclude_patterns: Optional[list[str]] = None,
    ) -> list[Finding]:
        """
        Analyze an entire project directory.
        
        Args:
            project_path: Path to project root
            exclude_patterns: Glob patterns to exclude
        
        Returns:
            List of security findings
        """
        if not self.is_available():
            raise RuntimeError(f"Static analysis not available: {self.cpg_builder.get_init_error()}")
        
        # Build CPG
        cpg = self.cpg_builder.build(project_path, exclude_patterns)
        
        # Analyze
        return self._analyze_cpg(cpg)
    
    def analyze_files(self, files: list[str]) -> list[Finding]:
        """
        Analyze specific files.
        
        Args:
            files: List of file paths
        
        Returns:
            List of security findings
        """
        if not self.is_available():
            raise RuntimeError(f"Static analysis not available: {self.cpg_builder.get_init_error()}")
        
        # Detect languages
        file_tuples = []
        for f in files:
            lang = self.cpg_builder._detect_language(f)
            if lang:
                file_tuples.append((f, lang))
        
        if not file_tuples:
            raise ValueError("No supported source files found")
        
        # Build CPG
        cpg = self.cpg_builder.build_from_files(file_tuples)
        
        # Analyze
        return self._analyze_cpg(cpg)
    
    def analyze_code(self, code: str, language: str, filename: str = "<inline>") -> list[Finding]:
        """
        Analyze a code snippet.
        
        Args:
            code: Source code string
            language: Programming language
            filename: Virtual filename for reporting
        
        Returns:
            List of security findings
        """
        if not self.is_available():
            raise RuntimeError(f"Static analysis not available: {self.cpg_builder.get_init_error()}")
        
        # Write to temp file for analysis
        import tempfile
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=f".{language}",
            delete=False,
            prefix="strix_sast_",
        ) as tmp:
            tmp.write(code)
            tmp_path = tmp.name
        
        try:
            cpg = self.cpg_builder.build_from_files([(tmp_path, language)])
            findings = self._analyze_cpg(cpg)
            
            # Update file paths in findings
            for f in findings:
                if f.location.file_path == tmp_path:
                    f.location.file_path = filename
            
            return findings
        finally:
            os.unlink(tmp_path)
    
    def _analyze_cpg(self, cpg: CPG) -> list[Finding]:
        """Run full analysis pipeline on a CPG."""
        # Step 1: Data flow analysis (find source→sink paths)
        taint_paths = self.data_flow_analyzer.analyze(cpg)
        
        # Step 2: Validate sanitizers
        sanitizer_validations = []
        if self.config.enable_llm_validation:
            sanitizer_validations = self.sanitizer_analyzer.validate_sanitizers(cpg, taint_paths)
        
        # Step 3: Convert taint paths to findings
        findings = self._taint_paths_to_findings(cpg, taint_paths, sanitizer_validations)
        
        # Step 4: Filter by severity and confidence
        findings = self._filter_findings(findings)
        
        # Step 5: Deduplicate
        findings = self._deduplicate_findings(findings)
        
        return findings
    
    def _taint_paths_to_findings(
        self,
        cpg: CPG,
        taint_paths: list[TaintPath],
        sanitizer_validations: list[SanitizerValidation],
    ) -> list[Finding]:
        """Convert taint paths to security findings."""
        findings = []
        
        # Build sanitizer validation lookup
        sanitizer_effectiveness = {}
        for sv in sanitizer_validations:
            key = (sv.sanitizer_node.id, sv.taint_path.vuln_type)
            sanitizer_effectiveness[key] = sv
        
        for path in taint_paths:
            # Determine severity
            severity = self._calculate_severity(path)
            confidence = self._calculate_confidence(path, sanitizer_validations)
            
            # Check if sanitizer is actually effective
            is_sanitized = path.is_sanitized
            sanitizer_effective = None
            if is_sanitized:
                for san_node in path.sanitizer_nodes:
                    key = (san_node.id, path.vuln_type)
                    if key in sanitizer_effectiveness:
                        sv = sanitizer_effectiveness[key]
                        if not sv.is_effective:
                            is_sanitized = False
                            sanitizer_effective = False
                        else:
                            sanitizer_effective = True
            
            # If properly sanitized, reduce severity/confidence
            if is_sanitized and sanitizer_effective:
                severity = self._reduce_severity(severity)
                confidence = FindingConfidence.LOW
            
            # Build finding
            finding = Finding(
                id=f"SAST-{uuid.uuid4().hex[:8].upper()}",
                title=self._generate_title(path),
                vuln_type=path.vuln_type,
                severity=severity,
                confidence=confidence,
                location=self._build_location(cpg, path.sink_node),
                evidence=self._build_evidence(cpg, path),
                description=self._generate_description(path, is_sanitized, sanitizer_effective),
                impact=self._generate_impact(path),
                recommendation=self._generate_recommendation(path),
                cwe_id=VULN_TYPE_TO_CWE.get(path.vuln_type, ""),
                owasp_category=VULN_TYPE_TO_OWASP.get(path.vuln_type, ""),
                cvss_score=VULN_TYPE_CVSS_BASE.get(path.vuln_type, 5.0),
                language=path.source_node.properties.get("language", ""),
                is_sanitized=is_sanitized,
                sanitizer_effective=sanitizer_effective,
            )
            
            findings.append(finding)
        
        return findings
    
    def _calculate_severity(self, path: TaintPath) -> FindingSeverity:
        """Calculate severity based on vulnerability type."""
        critical_vulns = {"sqli", "rce", "ssti", "deserialization", "nosql_injection"}
        high_vulns = {"ssrf", "path_traversal", "auth_bypass", "privilege_escalation"}
        medium_vulns = {"xss", "idor", "csrf", "xxe", "open_redirect", "header_injection"}
        
        if path.vuln_type in critical_vulns:
            return FindingSeverity.CRITICAL
        elif path.vuln_type in high_vulns:
            return FindingSeverity.HIGH
        elif path.vuln_type in medium_vulns:
            return FindingSeverity.MEDIUM
        else:
            return FindingSeverity.LOW
    
    def _reduce_severity(self, severity: FindingSeverity) -> FindingSeverity:
        """Reduce severity when sanitizer is effective."""
        reduction = {
            FindingSeverity.CRITICAL: FindingSeverity.HIGH,
            FindingSeverity.HIGH: FindingSeverity.MEDIUM,
            FindingSeverity.MEDIUM: FindingSeverity.LOW,
            FindingSeverity.LOW: FindingSeverity.INFO,
            FindingSeverity.INFO: FindingSeverity.INFO,
        }
        return reduction.get(severity, severity)
    
    def _calculate_confidence(
        self,
        path: TaintPath,
        validations: list[SanitizerValidation],
    ) -> FindingConfidence:
        """Calculate confidence based on path characteristics."""
        if path.is_sanitized:
            # Check if sanitizer was validated as ineffective
            for sv in validations:
                if sv.taint_path.source_node.id == path.source_node.id and \
                   sv.taint_path.sink_node.id == path.sink_node.id:
                    if not sv.is_effective:
                        return FindingConfidence.HIGH
                    else:
                        return FindingConfidence.LOW
            return FindingConfidence.MEDIUM
        
        # Shorter paths = higher confidence
        if len(path.path) <= 3:
            return FindingConfidence.HIGH
        elif len(path.path) <= 6:
            return FindingConfidence.MEDIUM
        else:
            return FindingConfidence.LOW
    
    def _generate_title(self, path: TaintPath) -> str:
        """Generate a descriptive title for the finding."""
        vuln_names = {
            "sqli": "SQL Injection",
            "xss": "Cross-Site Scripting (XSS)",
            "rce": "Remote Code Execution",
            "ssti": "Server-Side Template Injection",
            "ssrf": "Server-Side Request Forgery",
            "path_traversal": "Path Traversal",
            "idor": "Insecure Direct Object Reference",
            "csrf": "Cross-Site Request Forgery",
            "xxe": "XML External Entity Injection",
            "deserialization": "Insecure Deserialization",
            "open_redirect": "Open Redirect",
            "nosql_injection": "NoSQL Injection",
            "header_injection": "HTTP Header Injection",
            "race_condition": "Race Condition",
            "auth_bypass": "Authentication Bypass",
            "privilege_escalation": "Privilege Escalation",
            "information_disclosure": "Information Disclosure",
            "mass_assignment": "Mass Assignment",
            "subdomain_takeover": "Subdomain Takeover",
        }
        
        vuln_name = vuln_names.get(path.vuln_type, path.vuln_type.replace("_", " ").title())
        return f"{vuln_name} via {path.source_node.name}"
    
    def _generate_description(self, path: TaintPath, is_sanitized: bool, sanitizer_effective: Optional[bool]) -> str:
        """Generate finding description."""
        desc = (
            f"Untrusted data from '{path.source_node.name}' "
            f"({path.source_node.file_path}:{path.source_node.line_start}) "
            f"flows to '{path.sink_node.name}' "
            f"({path.sink_node.file_path}:{path.sink_node.line_start}) "
            f"without proper sanitization."
        )
        
        if is_sanitized:
            if sanitizer_effective:
                desc += " The data passes through a sanitizer that appears effective, but manual verification is recommended."
            else:
                desc += " The data passes through a sanitizer that is NOT effective for this vulnerability type."
        
        return desc
    
    def _generate_impact(self, path: TaintPath) -> str:
        """Generate impact description."""
        impacts = {
            "sqli": "An attacker could execute arbitrary SQL queries, potentially reading, modifying, or deleting data, or executing system commands.",
            "xss": "An attacker could inject malicious scripts that execute in users' browsers, stealing session tokens, credentials, or performing actions on behalf of the user.",
            "rce": "An attacker could execute arbitrary system commands on the server, potentially gaining full control of the application and underlying system.",
            "ssti": "An attacker could inject template directives that execute arbitrary code on the server.",
            "ssrf": "An attacker could make the server send requests to internal services, potentially accessing sensitive data or internal APIs.",
            "path_traversal": "An attacker could access files outside the intended directory, potentially reading sensitive configuration files, source code, or system files.",
            "idor": "An attacker could access or modify resources belonging to other users by manipulating object identifiers.",
            "open_redirect": "An attacker could redirect users to malicious websites, facilitating phishing attacks.",
            "deserialization": "An attacker could inject malicious serialized objects that execute arbitrary code during deserialization.",
        }
        return impacts.get(path.vuln_type, "Potential security vulnerability detected.")
    
    def _generate_recommendation(self, path: TaintPath) -> str:
        """Generate remediation recommendation."""
        recommendations = {
            "sqli": "Use parameterized queries or an ORM. Never concatenate user input directly into SQL queries.",
            "xss": "Encode all user input before rendering in HTML. Use context-appropriate encoding (HTML, JavaScript, URL). Use Content Security Policy (CSP).",
            "rce": "Avoid using shell commands with user input. If necessary, use shlex.quote() and validate input against a whitelist.",
            "ssti": "Never pass user input to template rendering. Use sandboxed template environments.",
            "ssrf": "Validate and whitelist URLs. Use an allowlist of permitted domains/IPs. Block internal/private IP ranges.",
            "path_traversal": "Validate file paths against a whitelist. Use os.path.realpath() and verify the resolved path is within the expected directory.",
            "idor": "Implement proper authorization checks. Verify the authenticated user has permission to access the requested resource.",
            "open_redirect": "Validate redirect URLs against a whitelist of allowed domains.",
            "deserialization": "Avoid deserializing untrusted data. Use safe alternatives like JSON. If necessary, implement strict type checking.",
        }
        return recommendations.get(path.vuln_type, "Validate and sanitize all user input before use.")
    
    def _build_location(self, cpg: CPG, node) -> FindingLocation:
        """Build FindingLocation from CPG node."""
        return FindingLocation(
            file_path=node.file_path,
            line_start=node.line_start,
            line_end=node.line_end,
            col_start=node.col_start,
            col_end=node.col_end,
            function_name=self._find_function_name(cpg, node),
            code_snippet=node.code[:500] if self.config.include_code_snippets else "",
        )
    
    def _find_function_name(self, cpg: CPG, node) -> str:
        """Find the enclosing function name for a node."""
        for edge in cpg.get_edges_to(node.id):
            parent = cpg.get_node(edge.source_id)
            if parent and parent.node_type.value in ("function", "method"):
                return parent.name
        return ""
    
    def _build_evidence(self, cpg: CPG, path: TaintPath) -> FindingEvidence:
        """Build FindingEvidence from taint path."""
        # Build path locations
        path_locations = []
        for node_id in path.path:
            node = cpg.get_node(node_id)
            if node:
                path_locations.append(FindingLocation(
                    file_path=node.file_path,
                    line_start=node.line_start,
                    line_end=node.line_end,
                    function_name=node.name,
                    code_snippet=node.code[:200],
                ))
        
        # Build flow description
        flow_parts = []
        for i, node_id in enumerate(path.path):
            node = cpg.get_node(node_id)
            if node:
                label = "SOURCE" if i == 0 else ("SINK" if i == len(path.path) - 1 else "FLOW")
                flow_parts.append(f"  [{label}] {node.name} ({node.file_path}:{node.line_start})")
        
        return FindingEvidence(
            source_location=self._build_location(cpg, path.source_node),
            sink_location=self._build_location(cpg, path.sink_node),
            taint_path=path_locations,
            sanitizer_locations=[
                self._build_location(cpg, san) for san in path.sanitizer_nodes
            ],
            code_flow="\n".join(flow_parts) if flow_parts else "",
        )
    
    def _filter_findings(self, findings: list[Finding]) -> list[Finding]:
        """Filter findings by severity and confidence."""
        severity_order = {
            FindingSeverity.INFO: 0,
            FindingSeverity.LOW: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.HIGH: 3,
            FindingSeverity.CRITICAL: 4,
        }
        confidence_order = {
            FindingConfidence.INFO: 0,
            FindingConfidence.LOW: 1,
            FindingConfidence.MEDIUM: 2,
            FindingConfidence.HIGH: 3,
            FindingConfidence.CONFIRMED: 4,
        }
        
        min_sev = severity_order.get(self.config.min_severity, 0)
        min_conf = confidence_order.get(self.config.min_confidence, 0)
        
        return [
            f for f in findings
            if severity_order.get(f.severity, 0) >= min_sev
            and confidence_order.get(f.confidence, 0) >= min_conf
        ]
    
    def _deduplicate_findings(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings."""
        seen = set()
        unique = []
        
        for finding in findings:
            key = (
                finding.vuln_type,
                finding.location.file_path,
                finding.location.line_start,
            )
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        
        return unique
    
    def generate_report(self, findings: list[Finding]) -> str:
        """Generate a comprehensive markdown report."""
        if not findings:
            return "# Security Analysis Report\n\n✅ No vulnerabilities found.\n"
        
        # Sort by severity
        severity_order = {
            FindingSeverity.CRITICAL: 0,
            FindingSeverity.HIGH: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 3,
            FindingSeverity.INFO: 4,
        }
        findings.sort(key=lambda f: severity_order.get(f.severity, 5))
        
        # Count by severity
        counts = {s: 0 for s in FindingSeverity}
        for f in findings:
            counts[f.severity] += 1
        
        report = f"""# 🔍 Security Analysis Report

**Total Findings:** {len(findings)}

| Severity | Count |
|----------|-------|
| 🔴 Critical | {counts[FindingSeverity.CRITICAL]} |
| 🟠 High | {counts[FindingSeverity.HIGH]} |
| 🟡 Medium | {counts[FindingSeverity.MEDIUM]} |
| 🟢 Low | {counts[FindingSeverity.LOW]} |
| ℹ️ Info | {counts[FindingSeverity.INFO]} |

---

"""
        
        for finding in findings:
            report += finding.to_markdown()
            report += "\n---\n\n"
        
        return report
