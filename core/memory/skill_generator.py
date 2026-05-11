"""
Skill Generator
================
Auto-generates reusable skills from scan findings and attack patterns.

Inspired by Hermes Agent's self-improving skill system:
- When a new vulnerability pattern is found, create a skill for it
- When an attack technique works, document it as a reusable skill
- Skills improve over time as more scans are run

Generated skills are stored as markdown files and can be loaded
by future scans to improve detection.
"""

import json
import os
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .global_memory import GlobalMemory, AttackPattern, FindingFingerprint


@dataclass
class GeneratedSkill:
    """A skill generated from scan experience."""
    skill_id: str
    name: str
    category: str  # "vulnerability", "technique", "target", "tool"
    description: str
    content: str  # Markdown content
    vuln_type: str = ""
    language: str = ""
    effectiveness: float = 0.0
    source_scan_ids: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    usage_count: int = 0
    metadata: dict = field(default_factory=dict)


class SkillGenerator:
    """
    Generates reusable skills from scan experience.
    
    Three types of skills:
    1. Vulnerability Skills — How to find a specific vuln type
    2. Technique Skills — How to use an attack technique effectively
    3. Target Skills — What we know about a specific target/framework
    
    Usage:
        generator = SkillGenerator(global_memory, skills_dir="./generated_skills")
        
        # After a scan
        skills = generator.generate_from_findings(scan_id, findings)
        generator.save_skills(skills)
        
        # Before a scan
        relevant_skills = generator.get_relevant_skills(target, vuln_types)
    """
    
    def __init__(
        self,
        global_memory: GlobalMemory,
        skills_dir: str = "generated_skills",
    ):
        self.memory = global_memory
        self.skills_dir = skills_dir
        os.makedirs(skills_dir, exist_ok=True)
    
    def generate_from_findings(
        self,
        scan_id: str,
        findings: list,
    ) -> list[GeneratedSkill]:
        """Generate skills from scan findings."""
        skills = []
        
        # Group findings by vuln_type
        vuln_groups = {}
        for finding in findings:
            vuln_type = finding.vuln_type if hasattr(finding, 'vuln_type') else finding.get('vuln_type', '')
            if vuln_type not in vuln_groups:
                vuln_groups[vuln_type] = []
            vuln_groups[vuln_type].append(finding)
        
        # Generate skill for each vuln type
        for vuln_type, group_findings in vuln_groups.items():
            skill = self._generate_vulnerability_skill(vuln_type, group_findings, scan_id)
            if skill:
                skills.append(skill)
        
        return skills
    
    def generate_from_patterns(
        self,
        scan_id: str,
    ) -> list[GeneratedSkill]:
        """Generate skills from effective attack patterns."""
        skills = []
        
        # Get effective patterns from memory
        patterns = self.memory.get_effective_patterns(min_effectiveness=0.6)
        
        for pattern in patterns:
            skill = self._generate_technique_skill(pattern, scan_id)
            if skill:
                skills.append(skill)
        
        return skills
    
    def _generate_vulnerability_skill(
        self,
        vuln_type: str,
        findings: list,
        scan_id: str,
    ) -> Optional[GeneratedSkill]:
        """Generate a skill for a specific vulnerability type."""
        if not findings:
            return None
        
        skill_id = f"gen-vuln-{vuln_type}-{hashlib.md5(scan_id.encode()).hexdigest()[:8]}"
        
        # Collect common patterns
        file_patterns = []
        code_patterns = []
        recommendations = []
        
        for f in findings:
            file_path = f.file_path if hasattr(f, 'file_path') else f.get('file_path', '')
            code = f.code_snippet if hasattr(f, 'code_snippet') else f.get('code_snippet', '')
            rec = f.recommendation if hasattr(f, 'recommendation') else f.get('recommendation', '')
            
            if file_path:
                file_patterns.append(file_path)
            if code:
                code_patterns.append(code[:200])
            if rec:
                recommendations.append(rec)
        
        # Build skill content
        content = self._build_vulnerability_skill_content(
            vuln_type, findings, file_patterns, code_patterns, recommendations
        )
        
        # Get language from findings
        language = ""
        for f in findings:
            lang = f.metadata.get("language", "") if hasattr(f, 'metadata') else f.get('metadata', {}).get('language', '')
            if lang:
                language = lang
                break
        
        return GeneratedSkill(
            skill_id=skill_id,
            name=f"auto-{vuln_type}-detection",
            category="vulnerability",
            description=f"Auto-generated skill for detecting {vuln_type} vulnerabilities",
            content=content,
            vuln_type=vuln_type,
            language=language,
            source_scan_ids=[scan_id],
        )
    
    def _generate_technique_skill(
        self,
        pattern: AttackPattern,
        scan_id: str,
    ) -> Optional[GeneratedSkill]:
        """Generate a skill from an effective attack pattern."""
        skill_id = f"gen-technique-{pattern.pattern_id}"
        
        content = f"""---
name: {pattern.name.lower().replace(' ', '-')}
description: Auto-generated from attack pattern: {pattern.name}
vuln_type: {pattern.vuln_type}
effectiveness: {pattern.effectiveness:.0%}
---

# {pattern.name}

{pattern.description}

## Technique

{pattern.technique}

## Effectiveness

- **Success rate:** {pattern.effectiveness:.0%}
- **Times used:** {pattern.success_count + pattern.failure_count}
- **Successful:** {pattern.success_count}
- **Failed:** {pattern.failure_count}

## Contexts Where It Worked

"""
        for ctx in pattern.contexts[:5]:
            content += f"- {ctx}\n"
        
        content += f"""
## Usage Notes

This skill was auto-generated from scan experience. Use it as a reference
when testing for {pattern.vuln_type} vulnerabilities.

Last used: {pattern.last_used or 'Unknown'}
"""
        
        return GeneratedSkill(
            skill_id=skill_id,
            name=pattern.name,
            category="technique",
            description=f"Attack pattern: {pattern.name} ({pattern.effectiveness:.0%} effective)",
            content=content,
            vuln_type=pattern.vuln_type,
            effectiveness=pattern.effectiveness,
            source_scan_ids=[scan_id],
        )
    
    def _build_vulnerability_skill_content(
        self,
        vuln_type: str,
        findings: list,
        file_patterns: list,
        code_patterns: list,
        recommendations: list,
    ) -> str:
        """Build markdown content for a vulnerability skill."""
        content = f"""---
name: auto-{vuln_type}
description: Auto-generated detection patterns for {vuln_type}
category: vulnerabilities
generated: true
---

# {vuln_type.replace('_', ' ').title()} — Auto-Generated Detection Patterns

This skill was automatically generated from scan findings.
It contains real patterns found in production code.

## Common File Patterns

Locations where {vuln_type} was found:

"""
        # Unique file patterns
        seen = set()
        for fp in file_patterns[:10]:
            normalized = os.path.basename(fp)
            if normalized not in seen:
                seen.add(normalized)
                content += f"- `{fp}`\n"
        
        content += f"""
## Code Patterns

Common vulnerable code patterns:

"""
        for i, cp in enumerate(code_patterns[:5], 1):
            content += f"### Pattern {i}\n```python\n{cp}\n```\n\n"
        
        content += f"""
## Detection Checklist

When scanning for {vuln_type}, check:

1. **Input sources:** Look for user-controlled data entering the application
2. **Data flow:** Trace how data flows from source to sink
3. **Sanitization:** Verify if any sanitization is applied
4. **Context:** Check the context where data is used

## Recommendations

"""
        unique_recs = list(set(recommendations))[:5]
        for rec in unique_recs:
            content += f"- {rec}\n"
        
        content += f"""
## Statistics

- Findings analyzed: {len(findings)}
- Unique file patterns: {len(seen)}
- Generated: {datetime.utcnow().isoformat()[:10]}
"""
        
        return content
    
    def save_skills(self, skills: list[GeneratedSkill]) -> list[str]:
        """Save generated skills to disk."""
        saved_paths = []
        
        for skill in skills:
            # Create category directory
            category_dir = os.path.join(self.skills_dir, skill.category)
            os.makedirs(category_dir, exist_ok=True)
            
            # Save skill file
            filename = f"{skill.name}.md"
            filepath = os.path.join(category_dir, filename)
            
            with open(filepath, "w") as f:
                f.write(skill.content)
            
            saved_paths.append(filepath)
            
            # Store in global memory
            self.memory.store_knowledge(
                category="generated_skills",
                key=skill.skill_id,
                value={
                    "name": skill.name,
                    "category": skill.category,
                    "vuln_type": skill.vuln_type,
                    "file_path": filepath,
                    "effectiveness": skill.effectiveness,
                },
                confidence=skill.effectiveness,
                source_scan=skill.source_scan_ids[0] if skill.source_scan_ids else None,
            )
        
        return saved_paths
    
    def get_relevant_skills(
        self,
        target: Optional[str] = None,
        vuln_types: Optional[list[str]] = None,
        language: Optional[str] = None,
    ) -> list[GeneratedSkill]:
        """Get skills relevant to a scan target."""
        skills = []
        
        # Get from memory
        entries = self.memory.get_knowledge("generated_skills")
        
        for entry in entries:
            value = json.loads(entry["value"]) if isinstance(entry["value"], str) else entry["value"]
            
            # Filter by vuln type
            if vuln_types and value.get("vuln_type") not in vuln_types:
                continue
            
            # Load skill content
            filepath = value.get("file_path")
            if filepath and os.path.exists(filepath):
                with open(filepath, "r") as f:
                    content = f.read()
                
                skill = GeneratedSkill(
                    skill_id=entry["key"],
                    name=value.get("name", ""),
                    category=value.get("category", ""),
                    description=f"Auto-generated skill: {value.get('name', '')}",
                    content=content,
                    vuln_type=value.get("vuln_type", ""),
                    effectiveness=value.get("effectiveness", 0.0),
                )
                skills.append(skill)
        
        return skills
    
    def list_skills(self) -> list[dict[str, Any]]:
        """List all generated skills."""
        entries = self.memory.get_knowledge("generated_skills")
        
        return [
            {
                "id": entry["key"],
                **(json.loads(entry["value"]) if isinstance(entry["value"], str) else entry["value"]),
                "confidence": entry["confidence"],
                "updated_at": entry["updated_at"],
            }
            for entry in entries
        ]
