"""
Scan Memory
============
Per-scan state management. Stores findings, attack patterns, and scan metadata
for a single security assessment.

Uses SQLite for persistence.
"""

import json
import os
import sqlite3
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


@dataclass
class ScanRecord:
    """A single scan's metadata."""
    scan_id: str
    target: str
    target_type: str  # "url", "repo", "local", "ip"
    started_at: str
    completed_at: Optional[str] = None
    status: str = "running"  # running, completed, failed, cancelled
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    duration_seconds: float = 0.0
    metadata: dict = field(default_factory=dict)


@dataclass
class ScanFinding:
    """A finding stored in scan memory."""
    finding_id: str
    scan_id: str
    vuln_type: str
    severity: str
    confidence: str
    title: str
    description: str
    file_path: str
    line_start: int
    line_end: int = 0
    function_name: str = ""
    code_snippet: str = ""
    cwe_id: str = ""
    owasp_category: str = ""
    cvss_score: float = 0.0
    is_sanitized: bool = False
    sanitizer_effective: Optional[bool] = None
    recommendation: str = ""
    poc: str = ""
    metadata: dict = field(default_factory=dict)
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class ScanTechnique:
    """An attack technique used during a scan."""
    technique_id: str
    scan_id: str
    technique_type: str  # "recon", "exploit", "fuzz", "scan"
    target: str
    tool_used: str
    command: str
    result_summary: str
    success: bool = False
    duration_seconds: float = 0.0
    metadata: dict = field(default_factory=dict)
    executed_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class ScanMemory:
    """
    Per-scan persistent memory using SQLite.
    
    Usage:
        memory = ScanMemory("/path/to/scans.db")
        scan = memory.start_scan("https://example.com", "url")
        memory.add_finding(scan.scan_id, finding)
        memory.complete_scan(scan.scan_id)
    """
    
    def __init__(self, db_path: str = "scan_memory.db"):
        self.db_path = db_path
        self._conn = None
        self._init_db()
    
    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn
    
    def _init_db(self):
        """Initialize database schema."""
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                target_type TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                status TEXT DEFAULT 'running',
                findings_count INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                duration_seconds REAL DEFAULT 0.0,
                metadata TEXT DEFAULT '{}'
            );
            
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                vuln_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                file_path TEXT,
                line_start INTEGER,
                line_end INTEGER DEFAULT 0,
                function_name TEXT DEFAULT '',
                code_snippet TEXT DEFAULT '',
                cwe_id TEXT DEFAULT '',
                owasp_category TEXT DEFAULT '',
                cvss_score REAL DEFAULT 0.0,
                is_sanitized INTEGER DEFAULT 0,
                sanitizer_effective INTEGER,
                recommendation TEXT DEFAULT '',
                poc TEXT DEFAULT '',
                metadata TEXT DEFAULT '{}',
                discovered_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            );
            
            CREATE TABLE IF NOT EXISTS techniques (
                technique_id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                technique_type TEXT NOT NULL,
                target TEXT,
                tool_used TEXT,
                command TEXT,
                result_summary TEXT,
                success INTEGER DEFAULT 0,
                duration_seconds REAL DEFAULT 0.0,
                metadata TEXT DEFAULT '{}',
                executed_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            );
            
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_vuln ON findings(vuln_type);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_techniques_scan ON techniques(scan_id);
            CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
            CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
        """)
        conn.commit()
    
    def start_scan(self, target: str, target_type: str = "url", metadata: Optional[dict] = None) -> ScanRecord:
        """Start a new scan and return its record."""
        scan_id = f"scan-{uuid.uuid4().hex[:12]}"
        now = datetime.utcnow().isoformat()
        
        record = ScanRecord(
            scan_id=scan_id,
            target=target,
            target_type=target_type,
            started_at=now,
            metadata=metadata or {},
        )
        
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO scans (scan_id, target, target_type, started_at, metadata) VALUES (?, ?, ?, ?, ?)",
            (scan_id, target, target_type, now, json.dumps(metadata or {}))
        )
        conn.commit()
        
        return record
    
    def complete_scan(self, scan_id: str, status: str = "completed") -> None:
        """Mark a scan as completed."""
        now = datetime.utcnow().isoformat()
        conn = self._get_conn()
        
        # Get start time to calculate duration
        row = conn.execute("SELECT started_at FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        if row:
            started = datetime.fromisoformat(row["started_at"])
            duration = (datetime.utcnow() - started).total_seconds()
        else:
            duration = 0.0
        
        # Count findings
        counts = conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM findings WHERE scan_id = ? GROUP BY severity",
            (scan_id,)
        ).fetchall()
        
        severity_counts = {row["severity"]: row["cnt"] for row in counts}
        total = sum(severity_counts.values())
        
        conn.execute(
            """UPDATE scans SET 
                completed_at = ?, status = ?, duration_seconds = ?,
                findings_count = ?, critical_count = ?, high_count = ?,
                medium_count = ?, low_count = ?
            WHERE scan_id = ?""",
            (
                now, status, duration,
                total,
                severity_counts.get("critical", 0),
                severity_counts.get("high", 0),
                severity_counts.get("medium", 0),
                severity_counts.get("low", 0),
                scan_id,
            )
        )
        conn.commit()
    
    def add_finding(self, scan_id: str, finding: ScanFinding) -> None:
        """Add a finding to a scan."""
        conn = self._get_conn()
        conn.execute(
            """INSERT OR REPLACE INTO findings 
            (finding_id, scan_id, vuln_type, severity, confidence, title, description,
             file_path, line_start, line_end, function_name, code_snippet,
             cwe_id, owasp_category, cvss_score, is_sanitized, sanitizer_effective,
             recommendation, poc, metadata, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding.finding_id, scan_id, finding.vuln_type, finding.severity,
                finding.confidence, finding.title, finding.description,
                finding.file_path, finding.line_start, finding.line_end,
                finding.function_name, finding.code_snippet,
                finding.cwe_id, finding.owasp_category, finding.cvss_score,
                1 if finding.is_sanitized else 0,
                1 if finding.sanitizer_effective else (0 if finding.sanitizer_effective is False else None),
                finding.recommendation, finding.poc,
                json.dumps(finding.metadata), finding.discovered_at,
            )
        )
        conn.commit()
    
    def add_technique(self, scan_id: str, technique: ScanTechnique) -> None:
        """Record an attack technique used during the scan."""
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO techniques 
            (technique_id, scan_id, technique_type, target, tool_used, command,
             result_summary, success, duration_seconds, metadata, executed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                technique.technique_id, scan_id, technique.technique_type,
                technique.target, technique.tool_used, technique.command,
                technique.result_summary, 1 if technique.success else 0,
                technique.duration_seconds, json.dumps(technique.metadata),
                technique.executed_at,
            )
        )
        conn.commit()
    
    def get_scan(self, scan_id: str) -> Optional[ScanRecord]:
        """Get scan record by ID."""
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        return ScanRecord(
            scan_id=row["scan_id"],
            target=row["target"],
            target_type=row["target_type"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            status=row["status"],
            findings_count=row["findings_count"],
            critical_count=row["critical_count"],
            high_count=row["high_count"],
            medium_count=row["medium_count"],
            low_count=row["low_count"],
            duration_seconds=row["duration_seconds"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
        )
    
    def get_findings(self, scan_id: str, severity: Optional[str] = None) -> list[ScanFinding]:
        """Get all findings for a scan."""
        conn = self._get_conn()
        if severity:
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? AND severity = ? ORDER BY cvss_score DESC",
                (scan_id, severity)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY cvss_score DESC",
                (scan_id,)
            ).fetchall()
        
        return [self._row_to_finding(row) for row in rows]
    
    def get_techniques(self, scan_id: str) -> list[ScanTechnique]:
        """Get all techniques used in a scan."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM techniques WHERE scan_id = ? ORDER BY executed_at",
            (scan_id,)
        ).fetchall()
        
        return [ScanTechnique(
            technique_id=row["technique_id"],
            scan_id=row["scan_id"],
            technique_type=row["technique_type"],
            target=row["target"],
            tool_used=row["tool_used"],
            command=row["command"],
            result_summary=row["result_summary"],
            success=bool(row["success"]),
            duration_seconds=row["duration_seconds"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            executed_at=row["executed_at"],
        ) for row in rows]
    
    def get_recent_scans(self, limit: int = 10) -> list[ScanRecord]:
        """Get recent scans."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
        
        return [ScanRecord(
            scan_id=row["scan_id"],
            target=row["target"],
            target_type=row["target_type"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            status=row["status"],
            findings_count=row["findings_count"],
            critical_count=row["critical_count"],
            high_count=row["high_count"],
            medium_count=row["medium_count"],
            low_count=row["low_count"],
            duration_seconds=row["duration_seconds"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
        ) for row in rows]
    
    def get_target_history(self, target: str) -> list[ScanRecord]:
        """Get all scans for a specific target."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM scans WHERE target = ? ORDER BY started_at DESC",
            (target,)
        ).fetchall()
        
        return [ScanRecord(
            scan_id=row["scan_id"],
            target=row["target"],
            target_type=row["target_type"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            status=row["status"],
            findings_count=row["findings_count"],
            critical_count=row["critical_count"],
            high_count=row["high_count"],
            medium_count=row["medium_count"],
            low_count=row["low_count"],
            duration_seconds=row["duration_seconds"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
        ) for row in rows]
    
    def _row_to_finding(self, row) -> ScanFinding:
        return ScanFinding(
            finding_id=row["finding_id"],
            scan_id=row["scan_id"],
            vuln_type=row["vuln_type"],
            severity=row["severity"],
            confidence=row["confidence"],
            title=row["title"],
            description=row["description"],
            file_path=row["file_path"],
            line_start=row["line_start"],
            line_end=row["line_end"],
            function_name=row["function_name"],
            code_snippet=row["code_snippet"],
            cwe_id=row["cwe_id"],
            owasp_category=row["owasp_category"],
            cvss_score=row["cvss_score"],
            is_sanitized=bool(row["is_sanitized"]),
            sanitizer_effective=bool(row["sanitizer_effective"]) if row["sanitizer_effective"] is not None else None,
            recommendation=row["recommendation"],
            poc=row["poc"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            discovered_at=row["discovered_at"],
        )
    
    def close(self):
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()
