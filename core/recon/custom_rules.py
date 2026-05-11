"""
Custom Rule Engine
===================
User-defined security rules for custom attack patterns.

Allows security researchers to define their own detection rules
in YAML/JSON format, making Strix-Advanced extensible.

Rule types:
- Pattern rules: Match patterns in code/requests
- Flow rules: Data flow from source to sink
- Behavior rules: Anomalous behavior detection
- Custom rules: Python-based custom logic
"""

import json
import re
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional


@dataclass
class Rule:
    """A custom security rule."""
    id: str
    name: str
    description: str
    category: str  # "pattern", "flow", "behavior", "custom"
    severity: str  # "critical", "high", "medium", "low", "info"
    
    # Pattern matching
    patterns: list[str] = field(default_factory=list)  # Regex patterns
    file_patterns: list[str] = field(default_factory=list)  # File glob patterns
    
    # Context
    vuln_type: str = ""
    cwe_id: str = ""
    owasp: str = ""
    
    # Detection
    check_function: Optional[Callable] = None  # Custom Python function
    
    # Metadata
    author: str = ""
    tags: list[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class RuleMatch:
    """A match found by a rule."""
    rule: Rule
    file_path: str
    line_number: int
    matched_text: str
    context: str = ""
    severity: str = ""
    description: str = ""


class CustomRuleEngine:
    """
    Custom security rule engine.
    
    Usage:
        engine = CustomRuleEngine()
        
        # Load rules from file
        engine.load_rules("/path/to/rules.yaml")
        
        # Or add rules programmatically
        engine.add_rule(Rule(
            id="CUSTOM-001",
            name="Hardcoded API Key",
            description="Detects hardcoded API keys",
            category="pattern",
            severity="high",
            patterns=[r'api_key\s*=\s*["\'][a-zA-Z0-9]{20,}["\']'],
            file_patterns=["*.py", "*.js"],
        ))
        
        # Run rules against code
        matches = engine.scan_directory("/path/to/project")
    """
    
    def __init__(self):
        self.rules: list[Rule] = []
        self._load_builtin_rules()
    
    def _load_builtin_rules(self):
        """Load built-in security rules."""
        
        builtin_rules = [
            # Hardcoded secrets
            Rule(
                id="SECRET-001",
                name="Hardcoded API Key",
                description="Detects potential hardcoded API keys",
                category="pattern",
                severity="high",
                patterns=[
                    r'(?:api[_-]?key|apikey)\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
                    r'(?:secret|token)\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
                ],
                file_patterns=["*.py", "*.js", "*.ts", "*.java", "*.go", "*.env"],
                vuln_type="hardcoded_secret",
                cwe_id="CWE-798",
                tags=["secrets", "credentials"],
            ),
            Rule(
                id="SECRET-002",
                name="AWS Access Key",
                description="Detects AWS access key IDs",
                category="pattern",
                severity="critical",
                patterns=[r'AKIA[0-9A-Z]{16}'],
                vuln_type="hardcoded_secret",
                cwe_id="CWE-798",
                tags=["secrets", "aws"],
            ),
            Rule(
                id="SECRET-003",
                name="Private Key",
                description="Detects private key files",
                category="pattern",
                severity="critical",
                patterns=[
                    r'-----BEGIN\s+(RSA|EC|DSA|OPENSSH)?\s*PRIVATE\s+KEY-----',
                ],
                vuln_type="exposed_key",
                cwe_id="CWE-321",
                tags=["secrets", "keys"],
            ),
            Rule(
                id="SECRET-004",
                name="Generic Password",
                description="Detects hardcoded passwords",
                category="pattern",
                severity="high",
                patterns=[
                    r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{8,}["\']',
                    r'(?:pass)\s*[:=]\s*["\'][^"\']{8,}["\']',
                ],
                vuln_type="hardcoded_password",
                cwe_id="CWE-798",
                tags=["secrets", "passwords"],
            ),
            
            # Dangerous functions
            Rule(
                id="DANGER-001",
                name="Eval Usage",
                description="Detects use of eval() which can lead to code injection",
                category="pattern",
                severity="high",
                patterns=[
                    r'\beval\s*\(',
                    r'\bexec\s*\(',
                    r'\bcompile\s*\(',
                ],
                file_patterns=["*.py"],
                vuln_type="code_injection",
                cwe_id="CWE-95",
                tags=["rce", "injection"],
            ),
            Rule(
                id="DANGER-002",
                name="SQL String Concatenation",
                description="Detects SQL queries built with string concatenation",
                category="pattern",
                severity="high",
                patterns=[
                    r'execute\s*\(\s*f["\']',
                    r'execute\s*\(\s*["\'].*%s',
                    r'execute\s*\(\s*["\'].*\+',
                    r'cursor\.execute\s*\(\s*["\'].*\.format',
                ],
                file_patterns=["*.py"],
                vuln_type="sqli",
                cwe_id="CWE-89",
                tags=["sqli", "injection"],
            ),
            Rule(
                id="DANGER-003",
                name="OS Command Injection",
                description="Detects OS command execution with user input",
                category="pattern",
                severity="critical",
                patterns=[
                    r'os\.system\s*\(',
                    r'os\.popen\s*\(',
                    r'subprocess\.call\s*\(\s*["\']',
                    r'subprocess\.run\s*\(\s*["\']',
                    r'subprocess\.Popen\s*\(\s*["\']',
                ],
                file_patterns=["*.py"],
                vuln_type="rce",
                cwe_id="CWE-78",
                tags=["rce", "command_injection"],
            ),
            Rule(
                id="DANGER-004",
                name="Deserialization",
                description="Detects unsafe deserialization",
                category="pattern",
                severity="critical",
                patterns=[
                    r'pickle\.loads?\s*\(',
                    r'yaml\.load\s*\(',
                    r'yaml\.unsafe_load\s*\(',
                    r'marshal\.loads?\s*\(',
                ],
                file_patterns=["*.py"],
                vuln_type="deserialization",
                cwe_id="CWE-502",
                tags=["deserialization"],
            ),
            
            # Security misconfigurations
            Rule(
                id="CONFIG-001",
                name="Debug Mode Enabled",
                description="Detects debug mode in production configs",
                category="pattern",
                severity="medium",
                patterns=[
                    r'DEBUG\s*=\s*True',
                    r'debug\s*[:=]\s*true',
                    r'FLASK_DEBUG\s*=\s*1',
                ],
                vuln_type="misconfiguration",
                cwe_id="CWE-489",
                tags=["config", "debug"],
            ),
            Rule(
                id="CONFIG-002",
                name="CORS Wildcard",
                description="Detects permissive CORS configuration",
                category="pattern",
                severity="medium",
                patterns=[
                    r'Access-Control-Allow-Origin.*\*',
                    r'CORS_ORIGIN_ALLOW_ALL\s*=\s*True',
                    r'allow_origin\s*=\s*["\']\*["\']',
                ],
                vuln_type="misconfiguration",
                cwe_id="CWE-942",
                tags=["config", "cors"],
            ),
            Rule(
                id="CONFIG-003",
                name="SSL Verification Disabled",
                description="Detects disabled SSL certificate verification",
                category="pattern",
                severity="medium",
                patterns=[
                    r'verify\s*=\s*False',
                    r'CURLLOPT_SSL_VERIFYPEER.*0',
                    r'ssl_verify\s*[:=]\s*false',
                    r'REQUESTS_CA_BUNDLE\s*=\s*["\']',
                ],
                vuln_type="misconfiguration",
                cwe_id="CWE-295",
                tags=["config", "ssl"],
            ),
            
            # Information disclosure
            Rule(
                id="INFO-001",
                name="Stack Trace Exposure",
                description="Detects potential stack trace exposure",
                category="pattern",
                severity="medium",
                patterns=[
                    r'traceback\.format_exc\(\)',
                    r'printStackTrace\(\)',
                    r'console\.error\(.*err',
                ],
                vuln_type="info_disclosure",
                cwe_id="CWE-209",
                tags=["info", "error"],
            ),
            Rule(
                id="INFO-002",
                name="Internal IP Address",
                description="Detects hardcoded internal IP addresses",
                category="pattern",
                severity="low",
                patterns=[
                    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}',
                    r'172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}',
                    r'192\.168\.\d{1,3}\.\d{1,3}',
                ],
                vuln_type="info_disclosure",
                cwe_id="CWE-200",
                tags=["info", "network"],
            ),
            
            # Injection
            Rule(
                id="INJECT-001",
                name="Template Injection",
                description="Detects potential template injection",
                category="pattern",
                severity="high",
                patterns=[
                    r'Template\s*\(\s*f["\']',
                    r'render_template_string\s*\(',
                    r'Environment\s*\(\s*).*\.from_string',
                ],
                file_patterns=["*.py"],
                vuln_type="ssti",
                cwe_id="CWE-1336",
                tags=["ssti", "injection"],
            ),
            Rule(
                id="INJECT-002",
                name="LDAP Injection",
                description="Detects potential LDAP injection",
                category="pattern",
                severity="high",
                patterns=[
                    r'ldap.*search.*%s',
                    r'ldap.*filter.*\+',
                ],
                file_patterns=["*.py", "*.java"],
                vuln_type="ldap_injection",
                cwe_id="CWE-90",
                tags=["ldap", "injection"],
            ),
        ]
        
        self.rules.extend(builtin_rules)
    
    def add_rule(self, rule: Rule):
        """Add a custom rule."""
        self.rules.append(rule)
    
    def load_rules(self, path: str):
        """Load rules from a YAML/JSON file."""
        path = Path(path)
        
        if path.suffix in (".yaml", ".yml"):
            try:
                import yaml
                with open(path) as f:
                    data = yaml.safe_load(f)
            except ImportError:
                raise ImportError("PyYAML required: pip install pyyaml")
        elif path.suffix == ".json":
            with open(path) as f:
                data = json.load(f)
        else:
            raise ValueError(f"Unsupported format: {path.suffix}")
        
        for rule_data in data.get("rules", []):
            rule = Rule(
                id=rule_data.get("id", ""),
                name=rule_data.get("name", ""),
                description=rule_data.get("description", ""),
                category=rule_data.get("category", "pattern"),
                severity=rule_data.get("severity", "medium"),
                patterns=rule_data.get("patterns", []),
                file_patterns=rule_data.get("file_patterns", []),
                vuln_type=rule_data.get("vuln_type", ""),
                cwe_id=rule_data.get("cwe_id", ""),
                tags=rule_data.get("tags", []),
                enabled=rule_data.get("enabled", True),
            )
            self.rules.append(rule)
    
    def scan_file(self, file_path: str) -> list[RuleMatch]:
        """Scan a single file against all rules."""
        matches = []
        
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.split("\n")
        except (OSError, UnicodeDecodeError):
            return matches
        
        file_ext = Path(file_path).suffix
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            # Check file pattern
            if rule.file_patterns and file_ext not in rule.file_patterns:
                continue
            
            # Check patterns
            for pattern in rule.patterns:
                try:
                    for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                        # Find line number
                        line_num = content[:match.start()].count("\n") + 1
                        
                        # Get context (surrounding lines)
                        start_line = max(0, line_num - 2)
                        end_line = min(len(lines), line_num + 1)
                        context = "\n".join(lines[start_line:end_line])
                        
                        matches.append(RuleMatch(
                            rule=rule,
                            file_path=file_path,
                            line_number=line_num,
                            matched_text=match.group(0)[:200],
                            context=context,
                            severity=rule.severity,
                            description=rule.description,
                        ))
                except re.error:
                    continue
        
        return matches
    
    def scan_directory(self, directory: str, exclude_patterns: list[str] = None) -> list[RuleMatch]:
        """Scan a directory against all rules."""
        import os
        
        if exclude_patterns is None:
            exclude_patterns = [
                "node_modules", ".git", "__pycache__", ".venv", "venv",
                "dist", "build", ".next", "target", "vendor",
                "*.min.js", "*.bundle.js",
            ]
        
        matches = []
        
        for root, dirs, files in os.walk(directory):
            # Filter directories
            dirs[:] = [d for d in dirs if d not in exclude_patterns]
            
            for file in files:
                file_path = os.path.join(root, file)
                
                # Check if file matches any rule's file patterns
                ext = Path(file).suffix
                has_matching_rule = any(
                    not r.file_patterns or ext in r.file_patterns
                    for r in self.rules if r.enabled
                )
                
                if has_matching_rule:
                    file_matches = self.scan_file(file_path)
                    matches.extend(file_matches)
        
        return matches
    
    def generate_report(self, matches: list[RuleMatch]) -> str:
        """Generate custom rules report."""
        if not matches:
            return "# Custom Rules Analysis\n\n✅ No rule violations found.\n"
        
        report = f"""# 📏 Custom Rules Analysis

**Matches Found:** {len(matches)}

"""
        
        # Group by severity
        by_severity = {}
        for m in matches:
            by_severity.setdefault(m.severity, []).append(m)
        
        severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "ℹ️"}
        
        for severity in ["critical", "high", "medium", "low", "info"]:
            severity_matches = by_severity.get(severity, [])
            if not severity_matches:
                continue
            
            emoji = severity_emoji.get(severity, "❓")
            report += f"\n## {emoji} {severity.upper()} ({len(severity_matches)})\n\n"
            
            for m in severity_matches[:20]:
                report += f"""### {m.rule.name}
- **File:** `{m.file_path}:{m.line_number}`
- **Rule ID:** {m.rule.id}
- **CWE:** {m.rule.cwe_id}
```
{m.matched_text}
```

"""
        
        return report
    
    def export_rules(self, path: str):
        """Export rules to YAML/JSON."""
        rules_data = []
        for rule in self.rules:
            rules_data.append({
                "id": rule.id,
                "name": rule.name,
                "description": rule.description,
                "category": rule.category,
                "severity": rule.severity,
                "patterns": rule.patterns,
                "file_patterns": rule.file_patterns,
                "vuln_type": rule.vuln_type,
                "cwe_id": rule.cwe_id,
                "tags": rule.tags,
                "enabled": rule.enabled,
            })
        
        data = {"rules": rules_data}
        
        path = Path(path)
        if path.suffix in (".yaml", ".yml"):
            try:
                import yaml
                with open(path, "w") as f:
                    yaml.dump(data, f, default_flow_style=False)
            except ImportError:
                with open(path.with_suffix(".json"), "w") as f:
                    json.dump(data, f, indent=2)
        else:
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
