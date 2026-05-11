#!/usr/bin/env python3
"""
Usage Example — Static Analysis Engine
=======================================
Shows how to use the Strix-Advanced static analyzer.

Run:
    python examples/static_analysis_example.py
"""

import sys
import os

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def example_analyze_project():
    """Analyze an entire project directory."""
    from core.static_analyzer import StaticAnalysisEngine
    
    engine = StaticAnalysisEngine()
    
    if not engine.is_available():
        print("❌ tree-sitter not installed. Run:")
        print("   pip install tree-sitter tree-sitter-python tree-sitter-javascript")
        return
    
    print("✅ Static Analysis Engine ready")
    print(f"   Supported languages: {engine.get_status()['supported_languages']}")
    
    # Analyze current directory
    project_path = sys.argv[1] if len(sys.argv) > 1 else "."
    
    print(f"\n🔍 Analyzing: {os.path.abspath(project_path)}")
    print("   Building CPG...")
    
    try:
        findings = engine.analyze_project(project_path)
        
        print(f"\n📊 Found {len(findings)} potential vulnerabilities:\n")
        
        for f in findings:
            severity_emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢",
                "info": "ℹ️",
            }
            emoji = severity_emoji.get(f.severity.value, "❓")
            print(f"  {emoji} [{f.severity.value.upper()}] {f.title}")
            print(f"     📍 {f.location.file_path}:{f.location.line_start}")
            print(f"     🔗 CWE: {f.cwe_id} | Type: {f.vuln_type}")
            if f.is_sanitized:
                if f.sanitizer_effective:
                    print(f"     🛡️  Sanitized (appears effective)")
                else:
                    print(f"     ⚠️  Sanitizer INEFFECTIVE")
            print()
        
        # Generate report
        report = engine.generate_report(findings)
        report_path = "security_report.md"
        with open(report_path, "w") as f:
            f.write(report)
        print(f"\n📝 Full report saved to: {report_path}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


def example_analyze_code():
    """Analyze a code snippet directly."""
    from core.static_analyzer import StaticAnalysisEngine
    
    engine = StaticAnalysisEngine()
    
    if not engine.is_available():
        print("❌ tree-sitter not installed")
        return
    
    # Example vulnerable code
    vulnerable_code = '''
from flask import Flask, request
import sqlite3
import os

app = Flask(__name__)

@app.route("/search")
def search():
    query = request.args.get("q")
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    # VULNERABLE: SQL Injection
    cursor.execute(f"SELECT * FROM users WHERE name = '{query}'")
    results = cursor.fetchall()
    return str(results)

@app.route("/run")
def run_command():
    cmd = request.args.get("cmd")
    # VULNERABLE: Command Injection
    output = os.system(cmd)
    return str(output)

@app.route("/render")
def render_template():
    name = request.args.get("name")
    # VULNERABLE: SSTI
    from jinja2 import Template
    template = Template(f"Hello {name}")
    return template.render()
'''
    
    print("🔍 Analyzing vulnerable Flask app snippet...\n")
    
    findings = engine.analyze_code(vulnerable_code, "python", "app.py")
    
    for f in findings:
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "ℹ️",
        }
        emoji = severity_emoji.get(f.severity.value, "❓")
        print(f"{emoji} {f.title}")
        print(f"   Severity: {f.severity.value.upper()}")
        print(f"   CWE: {f.cwe_id}")
        print(f"   Location: {f.location.file_path}:{f.location.line_start}")
        print(f"   Impact: {f.impact[:100]}...")
        print()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--snippet":
        example_analyze_code()
    else:
        example_analyze_project()
