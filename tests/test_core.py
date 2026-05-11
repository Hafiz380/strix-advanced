"""
Tests for Strix-Advanced
"""

import pytest
import sys
import os

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestCustomRules:
    """Test the custom rule engine."""
    
    def test_builtin_rules_loaded(self):
        from core.recon.custom_rules import CustomRuleEngine
        engine = CustomRuleEngine()
        assert len(engine.rules) >= 15
    
    def test_scan_python_file(self, tmp_path):
        from core.recon.custom_rules import CustomRuleEngine
        
        # Create test file with known vulnerability
        test_file = tmp_path / "test.py"
        test_file.write_text('''
import os
password = "supersecret123"
api_key = "AKIA1234567890ABCDEF"
os.system(f"echo {user_input}")
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
eval(user_code)
''')
        
        engine = CustomRuleEngine()
        matches = engine.scan_file(str(test_file))
        
        # Should find multiple issues
        assert len(matches) > 0
        
        # Check for specific findings
        match_names = [m.rule.name for m in matches]
        assert any("Password" in n for n in match_names)
        assert any("AWS" in n for n in match_names)
        assert any("Command" in n for n in match_names)
        assert any("SQL" in n for n in match_names)
        assert any("Eval" in n for n in match_names)
    
    def test_scan_directory(self, tmp_path):
        from core.recon.custom_rules import CustomRuleEngine
        
        # Create test files
        (tmp_path / "safe.py").write_text('x = 1\ny = 2\n')
        (tmp_path / "unsafe.py").write_text('password = "test123"\nos.system("ls")\n')
        
        engine = CustomRuleEngine()
        matches = engine.scan_directory(str(tmp_path))
        
        # Should find issues in unsafe.py but not safe.py
        assert len(matches) > 0
    
    def test_custom_rule(self, tmp_path):
        from core.recon.custom_rules import CustomRuleEngine, Rule
        
        engine = CustomRuleEngine()
        
        # Add custom rule
        engine.add_rule(Rule(
            id="TEST-001",
            name="Test Pattern",
            description="Test rule",
            category="pattern",
            severity="info",
            patterns=[r"TODO"],
        ))
        
        test_file = tmp_path / "test.py"
        test_file.write_text('# TODO: fix this\nprint("hello")\n')
        
        matches = engine.scan_file(str(test_file))
        assert any(m.rule.id == "TEST-001" for m in matches)


class TestFindings:
    """Test the findings data model."""
    
    def test_finding_creation(self):
        from core.static_analyzer.findings import Finding, FindingSeverity, FindingConfidence, FindingLocation, FindingEvidence
        
        finding = Finding(
            id="TEST-001",
            title="Test Finding",
            vuln_type="sqli",
            severity=FindingSeverity.CRITICAL,
            confidence=FindingConfidence.HIGH,
            location=FindingLocation(file_path="test.py", line_start=10),
            evidence=FindingEvidence(),
            description="Test description",
        )
        
        assert finding.severity == FindingSeverity.CRITICAL
        assert finding.cwe_id == ""  # Not set yet
    
    def test_finding_cwe_mapping(self):
        from core.static_analyzer.findings import VULN_TYPE_TO_CWE
        
        assert VULN_TYPE_TO_CWE["sqli"] == "CWE-89"
        assert VULN_TYPE_TO_CWE["xss"] == "CWE-79"
        assert VULN_TYPE_TO_CWE["rce"] == "CWE-78"
    
    def test_finding_to_markdown(self):
        from core.static_analyzer.findings import Finding, FindingSeverity, FindingConfidence, FindingLocation, FindingEvidence
        
        finding = Finding(
            id="TEST-001",
            title="SQL Injection",
            vuln_type="sqli",
            severity=FindingSeverity.CRITICAL,
            confidence=FindingConfidence.HIGH,
            location=FindingLocation(file_path="app.py", line_start=42, function_name="get_user"),
            evidence=FindingEvidence(),
            description="User input flows directly into SQL query.",
        )
        
        md = finding.to_markdown()
        assert "SQL Injection" in md
        assert "app.py:42" in md
        assert "CRITICAL" in md


class TestExploitChain:
    """Test exploit chain builder."""
    
    def test_chain_detection(self):
        from core.exploitation.chain_builder import ExploitChainBuilder, Vulnerability
        
        builder = ExploitChainBuilder()
        
        vulns = [
            Vulnerability(id="1", vuln_type="xss", severity="high", title="XSS", description=""),
            Vulnerability(id="2", vuln_type="csrf", severity="medium", title="CSRF", description=""),
        ]
        
        chains = builder.analyze(vulns)
        
        # Should detect XSS + CSRF chain
        assert len(chains) > 0
        assert any("Account Takeover" in c.name for c in chains)
    
    def test_no_chains(self):
        from core.exploitation.chain_builder import ExploitChainBuilder, Vulnerability
        
        builder = ExploitChainBuilder()
        
        vulns = [
            Vulnerability(id="1", vuln_type="xss", severity="high", title="XSS", description=""),
        ]
        
        chains = builder.analyze(vulns)
        
        # Single vuln shouldn't create chains (except novel ones)
        # The novel discovery might find something, but known chains need 2+ vulns
        known_chains = [c for c in chains if not c.chain_id.startswith("novel")]
        assert len(known_chains) == 0


class TestWAFBypass:
    """Test WAF bypass engine."""
    
    def test_sqli_bypasses(self):
        from core.exploitation.waf_bypass import WAFBypass
        
        bypass = WAFBypass()
        payloads = bypass.bypass_sqli("' OR 1=1--")
        
        assert len(payloads) > 5
        techniques = [p.technique for p in payloads]
        assert "inline_comments" in techniques
        assert "url_encoding" in techniques
    
    def test_xss_bypasses(self):
        from core.exploitation.waf_bypass import WAFBypass
        
        bypass = WAFBypass()
        payloads = bypass.bypass_xss("<script>alert(1)</script>")
        
        assert len(payloads) > 5
        techniques = [p.technique for p in payloads]
        assert "case_manipulation" in techniques


class TestMemory:
    """Test memory system."""
    
    def test_scan_memory(self, tmp_path):
        from core.memory.scan_memory import ScanMemory
        
        db_path = str(tmp_path / "test.db")
        memory = ScanMemory(db_path)
        
        # Start scan
        scan = memory.start_scan("https://example.com", "url")
        assert scan.scan_id.startswith("scan-")
        
        # Get scan
        retrieved = memory.get_scan(scan.scan_id)
        assert retrieved is not None
        assert retrieved.target == "https://example.com"
        
        memory.close()
    
    def test_global_memory(self, tmp_path):
        from core.memory.global_memory import GlobalMemory
        
        db_path = str(tmp_path / "test.db")
        memory = GlobalMemory(db_path)
        
        # Update target
        profile = memory.update_target_profile("https://example.com", "url")
        assert profile.scan_count == 1
        
        # Update again
        profile = memory.update_target_profile("https://example.com", "url")
        assert profile.scan_count == 2
        
        memory.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
