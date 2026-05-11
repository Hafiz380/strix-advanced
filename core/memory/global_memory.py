"""
Global Memory
==============
Cross-scan knowledge accumulation. Learns patterns from all scans
to improve future detection.

Inspired by Hermes Agent's persistent memory and ECC's continuous learning.

Key features:
- Finding fingerprinting (deduplicate across scans)
- Target profiling (remember what we know about each target)
- Attack pattern effectiveness tracking
- Vulnerability trend analysis
"""

import json
import sqlite3
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class TargetProfile:
    """Persistent knowledge about a target."""
    target: str
    target_type: str
    first_seen: str
    last_seen: str
    scan_count: int = 0
    total_findings: int = 0
    technologies: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    vuln_history: dict[str, int] = field(default_factory=dict)  # vuln_type → count
    notes: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


@dataclass
class AttackPattern:
    """A learned attack pattern with effectiveness data."""
    pattern_id: str
    name: str
    description: str
    vuln_type: str
    technique: str
    success_count: int = 0
    failure_count: int = 0
    last_used: Optional[str] = None
    effectiveness: float = 0.0  # 0.0 to 1.0
    contexts: list[str] = field(default_factory=list)  # Where it worked
    metadata: dict = field(default_factory=dict)


@dataclass
class FindingFingerprint:
    """Unique fingerprint for deduplication."""
    fingerprint: str
    vuln_type: str
    file_pattern: str  # File path pattern (without specific line)
    code_pattern: str  # Normalized code pattern
    first_seen: str
    last_seen: str
    occurrence_count: int = 0
    scan_ids: list[str] = field(default_factory=list)
    is_confirmed: bool = False  # Seen in multiple scans


class GlobalMemory:
    """
    Cross-scan knowledge accumulation.
    
    Learns from every scan to improve future detection:
    - Remembers targets and their characteristics
    - Tracks which attack patterns work
    - Deduplicates findings across scans
    - Identifies vulnerability trends
    
    Usage:
        memory = GlobalMemory("/path/to/global_memory.db")
        
        # After a scan
        memory.update_target_profile(target, findings)
        memory.learn_attack_patterns(techniques)
        memory.register_findings(scan_id, findings)
        
        # Before a scan
        profile = memory.get_target_profile(target)
        patterns = memory.get_effective_patterns(vuln_type)
        known = memory.get_known_findings(target)
    """
    
    def __init__(self, db_path: str = "global_memory.db"):
        self.db_path = db_path
        self._conn = None
        self._init_db()
    
    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
        return self._conn
    
    def _init_db(self):
        """Initialize database schema."""
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS target_profiles (
                target TEXT PRIMARY KEY,
                target_type TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                scan_count INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0,
                technologies TEXT DEFAULT '[]',
                endpoints TEXT DEFAULT '[]',
                vuln_history TEXT DEFAULT '{}',
                notes TEXT DEFAULT '[]',
                metadata TEXT DEFAULT '{}'
            );
            
            CREATE TABLE IF NOT EXISTS attack_patterns (
                pattern_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                vuln_type TEXT NOT NULL,
                technique TEXT NOT NULL,
                success_count INTEGER DEFAULT 0,
                failure_count INTEGER DEFAULT 0,
                last_used TEXT,
                effectiveness REAL DEFAULT 0.0,
                contexts TEXT DEFAULT '[]',
                metadata TEXT DEFAULT '{}'
            );
            
            CREATE TABLE IF NOT EXISTS finding_fingerprints (
                fingerprint TEXT PRIMARY KEY,
                vuln_type TEXT NOT NULL,
                file_pattern TEXT,
                code_pattern TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                occurrence_count INTEGER DEFAULT 0,
                scan_ids TEXT DEFAULT '[]',
                is_confirmed INTEGER DEFAULT 0
            );
            
            CREATE TABLE IF NOT EXISTS knowledge_entries (
                entry_id TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                confidence REAL DEFAULT 0.5,
                source_scan TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            
            CREATE INDEX IF NOT EXISTS idx_fp_vuln ON finding_fingerprints(vuln_type);
            CREATE INDEX IF NOT EXISTS idx_fp_confirmed ON finding_fingerprints(is_confirmed);
            CREATE INDEX IF NOT EXISTS idx_patterns_vuln ON attack_patterns(vuln_type);
            CREATE INDEX IF NOT EXISTS idx_patterns_effective ON attack_patterns(effectiveness);
            CREATE INDEX IF NOT EXISTS idx_knowledge_cat ON knowledge_entries(category);
        """)
        conn.commit()
    
    # ===== Target Profiling =====
    
    def update_target_profile(
        self,
        target: str,
        target_type: str = "url",
        findings: Optional[list] = None,
        technologies: Optional[list[str]] = None,
        endpoints: Optional[list[str]] = None,
    ) -> TargetProfile:
        """Update or create a target profile with new scan data."""
        conn = self._get_conn()
        now = datetime.utcnow().isoformat()
        
        existing = conn.execute(
            "SELECT * FROM target_profiles WHERE target = ?", (target,)
        ).fetchone()
        
        if existing:
            # Update existing profile
            scan_count = existing["scan_count"] + 1
            total_findings = existing["total_findings"] + (len(findings) if findings else 0)
            
            existing_tech = json.loads(existing["technologies"])
            existing_endpoints = json.loads(existing["endpoints"])
            existing_vulns = json.loads(existing["vuln_history"])
            existing_notes = json.loads(existing["notes"])
            
            # Merge technologies
            if technologies:
                existing_tech = list(set(existing_tech + technologies))
            
            # Merge endpoints
            if endpoints:
                existing_endpoints = list(set(existing_endpoints + endpoints))
            
            # Update vuln history
            if findings:
                for f in findings:
                    vuln_type = f.vuln_type if hasattr(f, 'vuln_type') else f.get('vuln_type', 'unknown')
                    existing_vulns[vuln_type] = existing_vulns.get(vuln_type, 0) + 1
            
            conn.execute(
                """UPDATE target_profiles SET 
                    last_seen = ?, scan_count = ?, total_findings = ?,
                    technologies = ?, endpoints = ?, vuln_history = ?, notes = ?
                WHERE target = ?""",
                (now, scan_count, total_findings,
                 json.dumps(existing_tech), json.dumps(existing_endpoints),
                 json.dumps(existing_vulns), json.dumps(existing_notes), target)
            )
        else:
            # Create new profile
            vuln_history = {}
            if findings:
                for f in findings:
                    vuln_type = f.vuln_type if hasattr(f, 'vuln_type') else f.get('vuln_type', 'unknown')
                    vuln_history[vuln_type] = vuln_history.get(vuln_type, 0) + 1
            
            conn.execute(
                """INSERT INTO target_profiles 
                (target, target_type, first_seen, last_seen, scan_count, total_findings,
                 technologies, endpoints, vuln_history, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (target, target_type, now, now, 1, len(findings or []),
                 json.dumps(technologies or []), json.dumps(endpoints or []),
                 json.dumps(vuln_history), json.dumps([]))
            )
        
        conn.commit()
        return self.get_target_profile(target)
    
    def get_target_profile(self, target: str) -> Optional[TargetProfile]:
        """Get target profile."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM target_profiles WHERE target = ?", (target,)
        ).fetchone()
        
        if not row:
            return None
        
        return TargetProfile(
            target=row["target"],
            target_type=row["target_type"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            scan_count=row["scan_count"],
            total_findings=row["total_findings"],
            technologies=json.loads(row["technologies"]),
            endpoints=json.loads(row["endpoints"]),
            vuln_history=json.loads(row["vuln_history"]),
            notes=json.loads(row["notes"]),
            metadata=json.loads(row["metadata"]),
        )
    
    def add_target_note(self, target: str, note: str) -> None:
        """Add a note to a target profile."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT notes FROM target_profiles WHERE target = ?", (target,)
        ).fetchone()
        
        if row:
            notes = json.loads(row["notes"])
            notes.append({"text": note, "time": datetime.utcnow().isoformat()})
            conn.execute(
                "UPDATE target_profiles SET notes = ? WHERE target = ?",
                (json.dumps(notes), target)
            )
            conn.commit()
    
    # ===== Attack Pattern Learning =====
    
    def learn_attack_pattern(
        self,
        name: str,
        vuln_type: str,
        technique: str,
        success: bool,
        context: str = "",
        description: str = "",
    ) -> AttackPattern:
        """Record the result of an attack technique."""
        conn = self._get_conn()
        now = datetime.utcnow().isoformat()
        
        # Generate pattern ID from name + vuln_type
        pattern_id = hashlib.md5(f"{name}:{vuln_type}".encode()).hexdigest()[:16]
        
        existing = conn.execute(
            "SELECT * FROM attack_patterns WHERE pattern_id = ?", (pattern_id,)
        ).fetchone()
        
        if existing:
            success_count = existing["success_count"] + (1 if success else 0)
            failure_count = existing["failure_count"] + (0 if success else 1)
            total = success_count + failure_count
            effectiveness = success_count / total if total > 0 else 0.0
            
            contexts = json.loads(existing["contexts"])
            if context and context not in contexts:
                contexts.append(context)
            
            conn.execute(
                """UPDATE attack_patterns SET 
                    success_count = ?, failure_count = ?, last_used = ?,
                    effectiveness = ?, contexts = ?
                WHERE pattern_id = ?""",
                (success_count, failure_count, now, effectiveness,
                 json.dumps(contexts), pattern_id)
            )
        else:
            success_count = 1 if success else 0
            failure_count = 0 if success else 1
            effectiveness = 1.0 if success else 0.0
            
            conn.execute(
                """INSERT INTO attack_patterns 
                (pattern_id, name, description, vuln_type, technique,
                 success_count, failure_count, last_used, effectiveness, contexts)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (pattern_id, name, description, vuln_type, technique,
                 success_count, failure_count, now, effectiveness,
                 json.dumps([context] if context else []))
            )
        
        conn.commit()
        return self.get_attack_pattern(pattern_id)
    
    def get_attack_pattern(self, pattern_id: str) -> Optional[AttackPattern]:
        """Get a specific attack pattern."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM attack_patterns WHERE pattern_id = ?", (pattern_id,)
        ).fetchone()
        
        if not row:
            return None
        
        return AttackPattern(
            pattern_id=row["pattern_id"],
            name=row["name"],
            description=row["description"],
            vuln_type=row["vuln_type"],
            technique=row["technique"],
            success_count=row["success_count"],
            failure_count=row["failure_count"],
            last_used=row["last_used"],
            effectiveness=row["effectiveness"],
            contexts=json.loads(row["contexts"]),
            metadata=json.loads(row["metadata"]),
        )
    
    def get_effective_patterns(
        self,
        vuln_type: Optional[str] = None,
        min_effectiveness: float = 0.5,
        limit: int = 10,
    ) -> list[AttackPattern]:
        """Get the most effective attack patterns."""
        conn = self._get_conn()
        
        if vuln_type:
            rows = conn.execute(
                """SELECT * FROM attack_patterns 
                WHERE vuln_type = ? AND effectiveness >= ?
                ORDER BY effectiveness DESC, success_count DESC LIMIT ?""",
                (vuln_type, min_effectiveness, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT * FROM attack_patterns 
                WHERE effectiveness >= ?
                ORDER BY effectiveness DESC, success_count DESC LIMIT ?""",
                (min_effectiveness, limit)
            ).fetchall()
        
        return [AttackPattern(
            pattern_id=row["pattern_id"],
            name=row["name"],
            description=row["description"],
            vuln_type=row["vuln_type"],
            technique=row["technique"],
            success_count=row["success_count"],
            failure_count=row["failure_count"],
            last_used=row["last_used"],
            effectiveness=row["effectiveness"],
            contexts=json.loads(row["contexts"]),
            metadata=json.loads(row["metadata"]),
        ) for row in rows]
    
    # ===== Finding Fingerprinting =====
    
    def register_findings(self, scan_id: str, findings: list) -> list[FindingFingerprint]:
        """Register findings and return fingerprints for deduplication."""
        conn = self._get_conn()
        now = datetime.utcnow().isoformat()
        fingerprints = []
        
        for finding in findings:
            # Generate fingerprint
            vuln_type = finding.vuln_type if hasattr(finding, 'vuln_type') else finding.get('vuln_type', '')
            file_path = finding.file_path if hasattr(finding, 'file_path') else finding.get('file_path', '')
            code = finding.code_snippet if hasattr(finding, 'code_snippet') else finding.get('code_snippet', '')
            
            # Normalize for fingerprinting
            file_pattern = self._normalize_file_path(file_path)
            code_pattern = self._normalize_code(code)
            
            fp_string = f"{vuln_type}:{file_pattern}:{code_pattern}"
            fingerprint = hashlib.md5(fp_string.encode()).hexdigest()[:20]
            
            existing = conn.execute(
                "SELECT * FROM finding_fingerprints WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
            
            if existing:
                # Update existing
                occurrence_count = existing["occurrence_count"] + 1
                scan_ids = json.loads(existing["scan_ids"])
                if scan_id not in scan_ids:
                    scan_ids.append(scan_id)
                
                is_confirmed = occurrence_count >= 2 or len(scan_ids) >= 2
                
                conn.execute(
                    """UPDATE finding_fingerprints SET 
                        last_seen = ?, occurrence_count = ?, scan_ids = ?, is_confirmed = ?
                    WHERE fingerprint = ?""",
                    (now, occurrence_count, json.dumps(scan_ids), 
                     1 if is_confirmed else 0, fingerprint)
                )
            else:
                # Create new
                conn.execute(
                    """INSERT INTO finding_fingerprints 
                    (fingerprint, vuln_type, file_pattern, code_pattern,
                     first_seen, last_seen, occurrence_count, scan_ids, is_confirmed)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (fingerprint, vuln_type, file_pattern, code_pattern,
                     now, now, 1, json.dumps([scan_id]), 0)
                )
            
            fingerprints.append(FindingFingerprint(
                fingerprint=fingerprint,
                vuln_type=vuln_type,
                file_pattern=file_pattern,
                code_pattern=code_pattern,
                first_seen=existing["first_seen"] if existing else now,
                last_seen=now,
                occurrence_count=existing["occurrence_count"] + 1 if existing else 1,
                scan_ids=json.loads(existing["scan_ids"]) + [scan_id] if existing and scan_id not in json.loads(existing["scan_ids"]) else ([scan_id] if not existing else json.loads(existing["scan_ids"])),
                is_confirmed=bool(existing["is_confirmed"]) or (occurrence_count >= 2 if existing else False),
            ))
        
        conn.commit()
        return fingerprints
    
    def get_known_findings(
        self,
        target: Optional[str] = None,
        vuln_type: Optional[str] = None,
        confirmed_only: bool = False,
    ) -> list[FindingFingerprint]:
        """Get known findings for deduplication."""
        conn = self._get_conn()
        
        conditions = []
        params = []
        
        if vuln_type:
            conditions.append("vuln_type = ?")
            params.append(vuln_type)
        if confirmed_only:
            conditions.append("is_confirmed = 1")
        
        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        
        rows = conn.execute(
            f"SELECT * FROM finding_fingerprints {where} ORDER BY occurrence_count DESC",
            params
        ).fetchall()
        
        return [FindingFingerprint(
            fingerprint=row["fingerprint"],
            vuln_type=row["vuln_type"],
            file_pattern=row["file_pattern"],
            code_pattern=row["code_pattern"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            occurrence_count=row["occurrence_count"],
            scan_ids=json.loads(row["scan_ids"]),
            is_confirmed=bool(row["is_confirmed"]),
        ) for row in rows]
    
    def is_duplicate(self, finding) -> Optional[FindingFingerprint]:
        """Check if a finding is a known duplicate."""
        vuln_type = finding.vuln_type if hasattr(finding, 'vuln_type') else finding.get('vuln_type', '')
        file_path = finding.file_path if hasattr(finding, 'file_path') else finding.get('file_path', '')
        code = finding.code_snippet if hasattr(finding, 'code_snippet') else finding.get('code_snippet', '')
        
        file_pattern = self._normalize_file_path(file_path)
        code_pattern = self._normalize_code(code)
        
        fp_string = f"{vuln_type}:{file_pattern}:{code_pattern}"
        fingerprint = hashlib.md5(fp_string.encode()).hexdigest()[:20]
        
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM finding_fingerprints WHERE fingerprint = ?",
            (fingerprint,)
        ).fetchone()
        
        if row:
            return FindingFingerprint(
                fingerprint=row["fingerprint"],
                vuln_type=row["vuln_type"],
                file_pattern=row["file_pattern"],
                code_pattern=row["code_pattern"],
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                occurrence_count=row["occurrence_count"],
                scan_ids=json.loads(row["scan_ids"]),
                is_confirmed=bool(row["is_confirmed"]),
            )
        return None
    
    # ===== Knowledge Entries =====
    
    def store_knowledge(
        self,
        category: str,
        key: str,
        value: Any,
        confidence: float = 0.5,
        source_scan: Optional[str] = None,
    ) -> None:
        """Store a knowledge entry."""
        import uuid
        conn = self._get_conn()
        now = datetime.utcnow().isoformat()
        
        entry_id = hashlib.md5(f"{category}:{key}".encode()).hexdigest()[:16]
        value_str = json.dumps(value) if not isinstance(value, str) else value
        
        conn.execute(
            """INSERT OR REPLACE INTO knowledge_entries 
            (entry_id, category, key, value, confidence, source_scan, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (entry_id, category, key, value_str, confidence, source_scan, now, now)
        )
        conn.commit()
    
    def get_knowledge(self, category: str, key: Optional[str] = None) -> list[dict]:
        """Retrieve knowledge entries."""
        conn = self._get_conn()
        
        if key:
            rows = conn.execute(
                "SELECT * FROM knowledge_entries WHERE category = ? AND key = ?",
                (category, key)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM knowledge_entries WHERE category = ?",
                (category,)
            ).fetchall()
        
        return [{
            "entry_id": row["entry_id"],
            "category": row["category"],
            "key": row["key"],
            "value": row["value"],
            "confidence": row["confidence"],
            "source_scan": row["source_scan"],
            "updated_at": row["updated_at"],
        } for row in rows]
    
    # ===== Statistics =====
    
    def get_stats(self) -> dict[str, Any]:
        """Get global memory statistics."""
        conn = self._get_conn()
        
        targets = conn.execute("SELECT COUNT(*) as cnt FROM target_profiles").fetchone()["cnt"]
        patterns = conn.execute("SELECT COUNT(*) as cnt FROM attack_patterns").fetchone()["cnt"]
        fingerprints = conn.execute("SELECT COUNT(*) as cnt FROM finding_fingerprints").fetchone()["cnt"]
        confirmed = conn.execute("SELECT COUNT(*) as cnt FROM finding_fingerprints WHERE is_confirmed = 1").fetchone()["cnt"]
        knowledge = conn.execute("SELECT COUNT(*) as cnt FROM knowledge_entries").fetchone()["cnt"]
        
        return {
            "targets_tracked": targets,
            "attack_patterns_learned": patterns,
            "finding_fingerprints": fingerprints,
            "confirmed_findings": confirmed,
            "knowledge_entries": knowledge,
        }
    
    # ===== Helpers =====
    
    def _normalize_file_path(self, file_path: str) -> str:
        """Normalize file path for fingerprinting."""
        import os
        # Remove specific directories, keep structure
        parts = file_path.replace("\\", "/").split("/")
        # Keep last 3 parts
        return "/".join(parts[-3:]) if len(parts) > 3 else file_path
    
    def _normalize_code(self, code: str) -> str:
        """Normalize code snippet for fingerprinting."""
        import re
        # Remove whitespace, comments, and string literals
        code = re.sub(r'#.*$', '', code, flags=re.MULTILINE)
        code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
        code = re.sub(r'".*?"', '"..."', code)
        code = re.sub(r"'.*?'", "'...'", code)
        code = re.sub(r'\s+', ' ', code).strip()
        # Take first 100 chars
        return code[:100]
    
    def close(self):
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()
