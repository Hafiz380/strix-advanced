"""
Dedup Engine
=============
Finding deduplication across scans. Prevents reporting the same vulnerability
multiple times when scanning the same target.

Key idea: A vulnerability found in scan 1 that also exists in scan 2
should be flagged as "known" not "new" — saving the hunter time.
"""

from dataclasses import dataclass
from typing import Any, Optional

from .global_memory import GlobalMemory, FindingFingerprint


@dataclass
class DedupResult:
    """Result of deduplication check."""
    is_duplicate: bool
    original_fingerprint: Optional[FindingFingerprint] = None
    occurrence_count: int = 1
    first_seen: Optional[str] = None
    scan_ids: list[str] = None
    recommendation: str = ""
    
    def __post_init__(self):
        if self.scan_ids is None:
            self.scan_ids = []


class DedupEngine:
    """
    Deduplicates findings across scans.
    
    Uses fingerprinting to identify the same vulnerability across different scans:
    - Same vuln type + same file pattern + same code pattern = same finding
    
    For bug bounty hunters, this means:
    - Scan 1: Found SQLi in /api/users → NEW finding
    - Scan 2: Same SQLi in /api/users → KNOWN (report once)
    - Scan 3: SQLi in /api/orders → NEW finding (different location)
    
    Usage:
        dedup = DedupEngine(global_memory)
        
        for finding in new_findings:
            result = dedup.check(finding, scan_id)
            if result.is_duplicate:
                print(f"Known finding: seen {result.occurrence_count} times")
            else:
                print("New finding!")
    """
    
    def __init__(self, global_memory: GlobalMemory):
        self.memory = global_memory
    
    def check(self, finding: Any, scan_id: str) -> DedupResult:
        """
        Check if a finding is a duplicate of a known finding.
        
        Args:
            finding: Finding object or dict with vuln_type, file_path, code_snippet
            scan_id: Current scan ID
        
        Returns:
            DedupResult with duplicate status and history
        """
        existing = self.memory.is_duplicate(finding)
        
        if existing:
            # It's a duplicate
            recommendation = self._generate_recommendation(existing)
            
            return DedupResult(
                is_duplicate=True,
                original_fingerprint=existing,
                occurrence_count=existing.occurrence_count,
                first_seen=existing.first_seen,
                scan_ids=existing.scan_ids,
                recommendation=recommendation,
            )
        else:
            return DedupResult(
                is_duplicate=False,
                occurrence_count=1,
            )
    
    def check_batch(
        self,
        findings: list,
        scan_id: str,
    ) -> tuple[list, list]:
        """
        Check a batch of findings and separate into new vs known.
        
        Returns:
            (new_findings, known_findings) — each element is (finding, DedupResult)
        """
        new_findings = []
        known_findings = []
        
        for finding in findings:
            result = self.check(finding, scan_id)
            if result.is_duplicate:
                known_findings.append((finding, result))
            else:
                new_findings.append((finding, result))
        
        return new_findings, known_findings
    
    def register_and_check(
        self,
        findings: list,
        scan_id: str,
    ) -> tuple[list, list]:
        """
        Register findings in global memory AND check for duplicates.
        This is the main method to use after a scan completes.
        
        Returns:
            (new_findings, known_findings)
        """
        # First register all findings
        fingerprints = self.memory.register_findings(scan_id, findings)
        
        # Then check which are duplicates
        new_findings = []
        known_findings = []
        
        for finding, fp in zip(findings, fingerprints):
            if fp.is_confirmed and fp.occurrence_count > 1:
                # This was already known before this scan
                result = DedupResult(
                    is_duplicate=True,
                    original_fingerprint=fp,
                    occurrence_count=fp.occurrence_count,
                    first_seen=fp.first_seen,
                    scan_ids=fp.scan_ids,
                    recommendation=self._generate_recommendation(fp),
                )
                known_findings.append((finding, result))
            else:
                result = DedupResult(
                    is_duplicate=False,
                    occurrence_count=fp.occurrence_count,
                )
                new_findings.append((finding, result))
        
        return new_findings, known_findings
    
    def get_summary(self, scan_id: str, findings: list) -> dict[str, Any]:
        """Generate a dedup summary for a scan."""
        new_findings, known_findings = self.register_and_check(findings, scan_id)
        
        return {
            "total": len(findings),
            "new": len(new_findings),
            "known": len(known_findings),
            "new_percentage": len(new_findings) / len(findings) * 100 if findings else 0,
            "known_percentage": len(known_findings) / len(findings) * 100 if findings else 0,
            "new_findings": [
                {
                    "title": f.title if hasattr(f, 'title') else f.get('title', ''),
                    "vuln_type": f.vuln_type if hasattr(f, 'vuln_type') else f.get('vuln_type', ''),
                    "severity": f.severity if hasattr(f, 'severity') else f.get('severity', ''),
                }
                for f, r in new_findings
            ],
            "known_findings": [
                {
                    "title": f.title if hasattr(f, 'title') else f.get('title', ''),
                    "vuln_type": f.vuln_type if hasattr(f, 'vuln_type') else f.get('vuln_type', ''),
                    "first_seen": r.first_seen,
                    "occurrence_count": r.occurrence_count,
                    "recommendation": r.recommendation,
                }
                for f, r in known_findings
            ],
        }
    
    def _generate_recommendation(self, fp: FindingFingerprint) -> str:
        """Generate recommendation for a known finding."""
        if fp.occurrence_count >= 5:
            return (
                f"This vulnerability has been seen {fp.occurrence_count} times across "
                f"{len(fp.scan_ids)} scans. It's likely a persistent issue. "
                f"Prioritize fixing or report with high confidence."
            )
        elif fp.occurrence_count >= 3:
            return (
                f"Seen {fp.occurrence_count} times. This is a recurring vulnerability. "
                f"Consider automating detection in CI/CD."
            )
        else:
            return (
                f"Previously seen {fp.occurrence_count} time(s). "
                f"Verify it's still exploitable before reporting."
            )
