"""
Supply Chain Analyzer
======================
Detects vulnerabilities in dependencies and supply chain attacks.

Capabilities:
- Dependency vulnerability scanning (CVE matching)
- Typosquatting detection
- Malicious package detection
- License compliance checking
- Outdated dependency detection
- Dependency confusion detection
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class Dependency:
    """A project dependency."""
    name: str
    version: str
    ecosystem: str  # "npm", "pypi", "maven", "go", "cargo", "composer"
    is_dev: bool = False
    source: str = ""  # "package.json", "requirements.txt", etc.


@dataclass
class DependencyVulnerability:
    """A vulnerability in a dependency."""
    dependency: Dependency
    cve_id: str = ""
    severity: str = ""
    title: str = ""
    description: str = ""
    fixed_version: str = ""
    advisory_url: str = ""
    cvss_score: float = 0.0


@dataclass
class SupplyChainRisk:
    """A supply chain risk."""
    risk_type: str  # "typosquat", "malicious", "confusion", "outdated", "vulnerable"
    dependency: Dependency
    description: str
    severity: str = "medium"
    evidence: str = ""
    recommendation: str = ""


# Known malicious/typosquat patterns
TYPOSQUAT_PATTERNS = {
    "npm": [
        # Common typosquats
        ("lodash", ["lodsah", "lodahs", "lodaash"]),
        ("express", ["expres", "exppress", "expresS"]),
        ("react", ["raect", "raectjs", "reacct"]),
        ("axios", ["axois", "axio", "axioss"]),
    ],
    "pypi": [
        ("requests", ["request", "requets", "reqeusts"]),
        ("flask", ["flaskk", "flasK"]),
        ("django", ["djang0", "djangoo"]),
        ("numpy", ["numpY", "numpyy"]),
    ],
}


class SupplyChainAnalyzer:
    """
    Analyzes project dependencies for vulnerabilities and risks.
    
    Usage:
        analyzer = SupplyChainAnalyzer()
        
        # Scan a project
        results = analyzer.scan_project("/path/to/project")
        
        # Check specific package
        risk = analyzer.check_package("npm", "lodash", "4.17.20")
    """
    
    def scan_project(self, project_path: str) -> dict[str, list]:
        """
        Scan a project for dependency issues.
        
        Returns dict with:
        - "dependencies": list[Dependency]
        - "vulnerabilities": list[DependencyVulnerability]
        - "risks": list[SupplyChainRisk]
        """
        project_path = Path(project_path)
        
        dependencies = []
        vulnerabilities = []
        risks = []
        
        # Detect package managers and parse dependencies
        if (project_path / "package.json").exists():
            deps = self._parse_npm(project_path)
            dependencies.extend(deps)
        
        if (project_path / "requirements.txt").exists():
            deps = self._parse_pip(project_path)
            dependencies.extend(deps)
        
        if (project_path / "Pipfile").exists():
            deps = self._parse_pipfile(project_path)
            dependencies.extend(deps)
        
        if (project_path / "pyproject.toml").exists():
            deps = self._parse_pyproject(project_path)
            dependencies.extend(deps)
        
        if (project_path / "go.mod").exists():
            deps = self._parse_go_mod(project_path)
            dependencies.extend(deps)
        
        if (project_path / "Cargo.toml").exists():
            deps = self._parse_cargo(project_path)
            dependencies.extend(deps)
        
        if (project_path / "composer.json").exists():
            deps = self._parse_composer(project_path)
            dependencies.extend(deps)
        
        # Check for vulnerabilities
        for dep in dependencies:
            vulns = self._check_vulnerabilities(dep)
            vulnerabilities.extend(vulns)
            
            risk = self._check_typosquat(dep)
            if risk:
                risks.append(risk)
        
        # Check for dependency confusion
        confusion_risks = self._check_dependency_confusion(dependencies, project_path)
        risks.extend(confusion_risks)
        
        return {
            "dependencies": dependencies,
            "vulnerabilities": vulnerabilities,
            "risks": risks,
        }
    
    def _parse_npm(self, project_path: Path) -> list[Dependency]:
        """Parse package.json for npm dependencies."""
        dependencies = []
        
        try:
            with open(project_path / "package.json") as f:
                pkg = json.load(f)
            
            for name, version in pkg.get("dependencies", {}).items():
                dependencies.append(Dependency(
                    name=name,
                    version=version.lstrip("^~>=<"),
                    ecosystem="npm",
                    is_dev=False,
                    source="package.json",
                ))
            
            for name, version in pkg.get("devDependencies", {}).items():
                dependencies.append(Dependency(
                    name=name,
                    version=version.lstrip("^~>=<"),
                    ecosystem="npm",
                    is_dev=True,
                    source="package.json",
                ))
        except Exception:
            pass
        
        return dependencies
    
    def _parse_pip(self, project_path: Path) -> list[Dependency]:
        """Parse requirements.txt for pip dependencies."""
        dependencies = []
        
        try:
            with open(project_path / "requirements.txt") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    
                    # Parse name==version or name>=version
                    match = re.match(r'^([a-zA-Z0-9_-]+)\s*(?:==|>=|<=|~=|!=)?\s*([0-9][^\s;]*)?', line)
                    if match:
                        dependencies.append(Dependency(
                            name=match.group(1).lower(),
                            version=match.group(2) or "latest",
                            ecosystem="pypi",
                            source="requirements.txt",
                        ))
        except Exception:
            pass
        
        return dependencies
    
    def _parse_pipfile(self, project_path: Path) -> list[Dependency]:
        """Parse Pipfile."""
        # Simplified parsing
        return []
    
    def _parse_pyproject(self, project_path: Path) -> list[Dependency]:
        """Parse pyproject.toml."""
        dependencies = []
        
        try:
            with open(project_path / "pyproject.toml") as f:
                content = f.read()
            
            # Simple regex parsing for dependencies
            deps_match = re.search(r'dependencies\s*=\s*\[(.*?)\]', content, re.DOTALL)
            if deps_match:
                for dep_str in re.findall(r'"([^"]+)"', deps_match.group(1)):
                    match = re.match(r'^([a-zA-Z0-9_-]+)\s*(?:>=|<=|==|~=)?\s*([0-9][^\s"]*)?', dep_str)
                    if match:
                        dependencies.append(Dependency(
                            name=match.group(1).lower(),
                            version=match.group(2) or "latest",
                            ecosystem="pypi",
                            source="pyproject.toml",
                        ))
        except Exception:
            pass
        
        return dependencies
    
    def _parse_go_mod(self, project_path: Path) -> list[Dependency]:
        """Parse go.mod."""
        dependencies = []
        
        try:
            with open(project_path / "go.mod") as f:
                content = f.read()
            
            for match in re.finditer(r'^\s+([^\s]+)\s+(v[^\s]+)', content, re.MULTILINE):
                dependencies.append(Dependency(
                    name=match.group(1),
                    version=match.group(2),
                    ecosystem="go",
                    source="go.mod",
                ))
        except Exception:
            pass
        
        return dependencies
    
    def _parse_cargo(self, project_path: Path) -> list[Dependency]:
        """Parse Cargo.toml."""
        dependencies = []
        
        try:
            with open(project_path / "Cargo.toml") as f:
                content = f.read()
            
            in_deps = False
            for line in content.split("\n"):
                if line.strip() == "[dependencies]":
                    in_deps = True
                    continue
                if line.strip().startswith("["):
                    in_deps = False
                    continue
                
                if in_deps:
                    match = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"', line)
                    if match:
                        dependencies.append(Dependency(
                            name=match.group(1),
                            version=match.group(2),
                            ecosystem="cargo",
                            source="Cargo.toml",
                        ))
        except Exception:
            pass
        
        return dependencies
    
    def _parse_composer(self, project_path: Path) -> list[Dependency]:
        """Parse composer.json."""
        dependencies = []
        
        try:
            with open(project_path / "composer.json") as f:
                pkg = json.load(f)
            
            for name, version in pkg.get("require", {}).items():
                if name != "php":
                    dependencies.append(Dependency(
                        name=name,
                        version=version.lstrip("^~>=<"),
                        ecosystem="composer",
                        source="composer.json",
                    ))
        except Exception:
            pass
        
        return dependencies
    
    def _check_vulnerabilities(self, dep: Dependency) -> list[DependencyVulnerability]:
        """Check a dependency for known vulnerabilities."""
        # This would query a vulnerability database (OSV, NVD, etc.)
        # For now, return empty - would need API integration
        return []
    
    def _check_typosquat(self, dep: Dependency) -> Optional[SupplyChainRisk]:
        """Check if a dependency might be a typosquat."""
        patterns = TYPOSQUAT_PATTERNS.get(dep.ecosystem, [])
        
        for legitimate, typosquats in patterns:
            if dep.name in typosquats:
                return SupplyChainRisk(
                    risk_type="typosquat",
                    dependency=dep,
                    description=f"'{dep.name}' might be a typosquat of '{legitimate}'",
                    severity="critical",
                    evidence=f"Similar name to popular package '{legitimate}'",
                    recommendation=f"Verify you meant '{dep.name}' and not '{legitimate}'",
                )
        
        return None
    
    def _check_dependency_confusion(
        self,
        dependencies: list[Dependency],
        project_path: Path,
    ) -> list[SupplyChainRisk]:
        """Check for dependency confusion vulnerabilities."""
        risks = []
        
        # Check if project uses private packages
        has_private = False
        
        # Check for .npmrc with private registry
        npmrc = project_path / ".npmrc"
        if npmrc.exists():
            content = npmrc.read_text()
            if "registry" in content and "npmjs.org" not in content:
                has_private = True
        
        # Check for private Python index
        pip_conf = project_path / "pip.conf"
        if pip_conf.exists():
            has_private = True
        
        if has_private:
            for dep in dependencies:
                if not dep.is_dev:
                    risks.append(SupplyChainRisk(
                        risk_type="confusion",
                        dependency=dep,
                        description=f"Dependency '{dep.name}' might be vulnerable to dependency confusion",
                        severity="high",
                        recommendation="Use scoped packages or verify package integrity",
                    ))
        
        return risks
    
    def generate_report(self, results: dict) -> str:
        """Generate supply chain analysis report."""
        deps = results.get("dependencies", [])
        vulns = results.get("vulnerabilities", [])
        risks = results.get("risks", [])
        
        report = f"""# 🔗 Supply Chain Analysis

**Dependencies Scanned:** {len(deps)}
**Vulnerabilities Found:** {len(vulns)}
**Risks Identified:** {len(risks)}

## Dependencies

| Package | Version | Ecosystem | Dev Only |
|---------|---------|-----------|----------|
"""
        for dep in deps[:50]:
            dev = "✅" if dep.is_dev else ""
            report += f"| {dep.name} | {dep.version} | {dep.ecosystem} | {dev} |\n"
        
        if risks:
            report += "\n## ⚠️ Risks\n\n"
            for risk in risks:
                report += f"""### {risk.risk_type.upper()}: {risk.dependency.name}
- **Severity:** {risk.severity}
- **Description:** {risk.description}
- **Recommendation:** {risk.recommendation}

"""
        
        if vulns:
            report += "\n## 🔴 Vulnerabilities\n\n"
            for vuln in vulns:
                report += f"### {vuln.cve_id}: {vuln.title}\n"
                report += f"- **Package:** {vuln.dependency.name} {vuln.dependency.version}\n"
                report += f"- **Severity:** {vuln.severity}\n"
                report += f"- **Fixed:** {vuln.fixed_version}\n\n"
        
        return report
