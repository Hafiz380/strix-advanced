"""
Security Findings
=================
Data structures for representing discovered vulnerabilities.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class FindingSeverity(Enum):
    """CVSS-like severity levels."""
    CRITICAL = "critical"  # 9.0-10.0
    HIGH = "high"          # 7.0-8.9
    MEDIUM = "medium"      # 4.0-6.9
    LOW = "low"            # 0.1-3.9
    INFO = "info"          # 0.0


class FindingConfidence(Enum):
    """Confidence level of the finding."""
    CONFIRMED = "confirmed"    # PoC exists or proven exploitable
    HIGH = "high"              # Strong evidence, likely exploitable
    MEDIUM = "medium"          # Some evidence, needs verification
    LOW = "low"                # Weak evidence, might be false positive
    INFO = "info"              # Informational, not a vulnerability


class FindingStatus(Enum):
    """Status of the finding."""
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"


@dataclass
class FindingLocation:
    """Location of a vulnerability in source code."""
    file_path: str
    line_start: int
    line_end: int = 0
    col_start: int = 0
    col_end: int = 0
    function_name: str = ""
    class_name: str = ""
    code_snippet: str = ""
    
    def __str__(self):
        loc = f"{self.file_path}:{self.line_start}"
        if self.function_name:
            loc += f" in {self.function_name}()"
        return loc


@dataclass
class FindingEvidence:
    """Evidence supporting the finding."""
    source_location: Optional[FindingLocation] = None
    sink_location: Optional[FindingLocation] = None
    taint_path: list[FindingLocation] = field(default_factory=list)
    sanitizer_locations: list[FindingLocation] = field(default_factory=list)
    code_flow: str = ""  # Human-readable description of the data flow
    poc: str = ""        # Proof of concept code
    request_response: str = ""  # HTTP request/response if applicable


@dataclass
class Finding:
    """
    A discovered security vulnerability.
    
    This is the main output of the static analysis engine.
    """
    # Identity
    id: str
    title: str
    vuln_type: str  # "sqli", "xss", "rce", "ssrf", etc.
    
    # Severity & Confidence
    severity: FindingSeverity
    confidence: FindingConfidence
    
    # Location
    location: FindingLocation
    evidence: FindingEvidence
    
    # Description
    description: str
    impact: str = ""
    recommendation: str = ""
    
    # Metadata
    cwe_id: str = ""  # CWE identifier (e.g., "CWE-89" for SQLi)
    owasp_category: str = ""  # OWASP Top 10 category
    cvss_score: float = 0.0
    cvss_vector: str = ""
    
    # Status
    status: FindingStatus = FindingStatus.NEW
    
    # Context
    language: str = ""
    framework: str = ""
    is_sanitized: bool = False
    sanitizer_effective: Optional[bool] = None
    
    # Timestamps
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    # Raw data
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize finding to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "vuln_type": self.vuln_type,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "location": {
                "file": self.location.file_path,
                "line": self.location.line_start,
                "function": self.location.function_name,
                "code": self.location.code_snippet[:500],
            },
            "evidence": {
                "source": str(self.evidence.source_location) if self.evidence.source_location else None,
                "sink": str(self.evidence.sink_location) if self.evidence.sink_location else None,
                "flow": self.evidence.code_flow,
                "poc": self.evidence.poc,
            },
            "description": self.description,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "cwe": self.cwe_id,
            "owasp": self.owasp_category,
            "cvss": self.cvss_score,
            "status": self.status.value,
            "language": self.language,
            "is_sanitized": self.is_sanitized,
            "discovered_at": self.discovered_at,
        }
    
    def to_markdown(self) -> str:
        """Generate markdown report for this finding."""
        severity_emoji = {
            FindingSeverity.CRITICAL: "🔴",
            FindingSeverity.HIGH: "🟠",
            FindingSeverity.MEDIUM: "🟡",
            FindingSeverity.LOW: "🟢",
            FindingSeverity.INFO: "ℹ️",
        }
        
        emoji = severity_emoji.get(self.severity, "❓")
        
        md = f"""## {emoji} {self.title}

**Severity:** {self.severity.value.upper()} | **Confidence:** {self.confidence.value.upper()}
**Type:** {self.vuln_type} | **CWE:** {self.cwe_id} | **CVSS:** {self.cvss_score}

### Location
- **File:** `{self.location.file_path}:{self.location.line_start}`
- **Function:** `{self.location.function_name or 'N/A'}`

### Description
{self.description}

### Impact
{self.impact or 'Not specified'}

### Data Flow
{self.evidence.code_flow or 'Not traced'}

### Code
```{self.language}
{self.location.code_snippet}
```

### Recommendation
{self.recommendation or 'Not specified'}
"""
        
        if self.evidence.poc:
            md += f"""
### Proof of Concept
```
{self.evidence.poc}
```
"""
        
        return md


# ============================================================
# CWE Mappings
# ============================================================

VULN_TYPE_TO_CWE = {
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "rce": "CWE-78",
    "ssti": "CWE-1336",
    "ssrf": "CWE-918",
    "path_traversal": "CWE-22",
    "lfi": "CWE-98",
    "open_redirect": "CWE-601",
    "idor": "CWE-639",
    "csrf": "CWE-352",
    "xxe": "CWE-611",
    "deserialization": "CWE-502",
    "race_condition": "CWE-362",
    "auth_bypass": "CWE-287",
    "privilege_escalation": "CWE-269",
    "information_disclosure": "CWE-200",
    "mass_assignment": "CWE-915",
    "nosql_injection": "CWE-943",
    "header_injection": "CWE-113",
    "subdomain_takeover": "CWE-346",
}

VULN_TYPE_TO_OWASP = {
    "sqli": "A03:2021 - Injection",
    "xss": "A03:2021 - Injection",
    "rce": "A03:2021 - Injection",
    "ssti": "A03:2021 - Injection",
    "ssrf": "A10:2021 - Server-Side Request Forgery",
    "path_traversal": "A01:2021 - Broken Access Control",
    "idor": "A01:2021 - Broken Access Control",
    "auth_bypass": "A07:2021 - Identification and Authentication Failures",
    "csrf": "A01:2021 - Broken Access Control",
    "xxe": "A05:2021 - Security Misconfiguration",
    "deserialization": "A08:2021 - Software and Data Integrity Failures",
    "race_condition": "A04:2021 - Insecure Design",
    "information_disclosure": "A01:2021 - Broken Access Control",
}

# CVSS base scores (approximate)
VULN_TYPE_CVSS_BASE = {
    "sqli": 9.8,
    "rce": 9.8,
    "ssti": 9.0,
    "deserialization": 9.8,
    "ssrf": 8.6,
    "xss": 6.1,
    "path_traversal": 7.5,
    "idor": 6.5,
    "csrf": 6.5,
    "open_redirect": 6.1,
    "xxe": 7.5,
    "race_condition": 5.9,
    "auth_bypass": 9.1,
    "privilege_escalation": 8.8,
    "information_disclosure": 5.3,
    "nosql_injection": 9.8,
    "header_injection": 6.1,
    "subdomain_takeover": 7.5,
}
