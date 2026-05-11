"""
Strix-Advanced CLI
==================
Command-line interface for the Strix-Advanced security testing platform.

Usage:
    strix-advanced scan https://target.com
    strix-advanced scan ./code --type code
    strix-advanced scan https://target.com --code ./src --type full
    strix-advanced rules list
    strix-advanced rules scan ./code
    strix-advanced report ./results
"""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


def cmd_scan(args):
    """Run a security scan."""
    from agents.coordinator import CoordinatorAgent, ScanConfig
    from agents.report_agent import ReportConfig
    
    config = ScanConfig(
        target=args.target,
        scan_type=args.type,
        code_path=args.code,
        recon_depth=args.depth,
        max_exploits=args.max_exploits,
    )
    
    config.report_config = ReportConfig(
        title=f"Security Scan: {args.target}",
        executive_summary=not args.no_summary,
    )
    
    async def run():
        import httpx
        
        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            coordinator = CoordinatorAgent(http_client=client)
            
            # Progress callback
            def on_progress(progress):
                emoji = {"recon": "🔍", "analysis": "🔬", "exploit": "💥", "report": "📝"}
                status = "✅" if progress.status == "completed" else "🔄" if progress.status == "running" else "❌"
                print(f"  {emoji.get(progress.phase, '📋')} {progress.phase}: {status} {progress.message}")
            
            coordinator.on_progress(on_progress)
            
            print(f"\n⚡ Strix-Advanced Security Scan")
            print(f"🎯 Target: {args.target}")
            print(f"📋 Type: {args.type}")
            print(f"{'=' * 50}\n")
            
            results = await coordinator.run_scan(config)
            
            # Save report
            output_dir = Path(args.output)
            output_dir.mkdir(parents=True, exist_ok=True)
            
            report_path = output_dir / "report.md"
            with open(report_path, "w") as f:
                f.write(results.get("report", "No report generated"))
            
            print(f"\n{'=' * 50}")
            print(f"📝 Report saved to: {report_path}")
            
            # Save raw results as JSON
            json_path = output_dir / "results.json"
            json_results = {}
            for key, value in results.items():
                if key != "report":
                    if hasattr(value, "__dict__"):
                        json_results[key] = str(value)
                    elif isinstance(value, list):
                        json_results[key] = [str(v) for v in value]
                    else:
                        json_results[key] = str(value) if value else None
            
            with open(json_path, "w") as f:
                json.dump(json_results, f, indent=2, default=str)
            
            print(f"📊 Raw results saved to: {json_path}")
            
            # Summary
            findings = results.get("analysis")
            exploits = results.get("exploits", [])
            
            if findings and hasattr(findings, "findings"):
                total = len(findings.findings)
                critical = sum(1 for f in findings.findings if f.severity.value == "critical")
                high = sum(1 for f in findings.findings if f.severity.value == "high")
                exploited = sum(1 for e in exploits if hasattr(e, "exploited") and e.exploited)
                
                print(f"\n📊 Summary:")
                print(f"  🔴 Critical: {critical}")
                print(f"  🟠 High: {high}")
                print(f"  💥 Exploited: {exploited}")
                print(f"  📋 Total: {total}")
    
    asyncio.run(run())


def cmd_rules(args):
    """Manage custom rules."""
    from core.recon.custom_rules import CustomRuleEngine
    
    engine = CustomRuleEngine()
    
    if args.rules_action == "list":
        print(f"\n📏 Custom Rules ({len(engine.rules)} total)\n")
        print(f"{'ID':<15} {'Name':<30} {'Severity':<10} {'Category':<10}")
        print("-" * 65)
        for rule in engine.rules:
            if rule.enabled:
                print(f"{rule.id:<15} {rule.name:<30} {rule.severity:<10} {rule.category:<10}")
    
    elif args.rules_action == "scan":
        print(f"\n🔍 Scanning: {args.path}\n")
        matches = engine.scan_directory(args.path)
        
        if matches:
            print(f"Found {len(matches)} matches:\n")
            for m in matches:
                severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "ℹ️"}
                emoji = severity_emoji.get(m.severity, "❓")
                print(f"  {emoji} {m.rule.name}")
                print(f"     📍 {m.file_path}:{m.line_number}")
                print(f"     🔗 {m.rule.cwe_id}")
                print()
        else:
            print("✅ No rule violations found.")
    
    elif args.rules_action == "export":
        engine.export_rules(args.output)
        print(f"📏 Rules exported to: {args.output}")


def cmd_analyze(args):
    """Run static analysis only."""
    from core.static_analyzer import StaticAnalysisEngine
    
    engine = StaticAnalysisEngine()
    
    if not engine.is_available():
        print(f"❌ Static analysis not available: {engine.get_init_error()}")
        print("   Install: pip install tree-sitter tree-sitter-python")
        return
    
    print(f"\n🔬 Static Analysis")
    print(f"📁 Target: {args.path}")
    print(f"{'=' * 50}\n")
    
    if os.path.isfile(args.path):
        findings = engine.analyze_files([args.path])
    else:
        findings = engine.analyze_project(args.path)
    
    if findings:
        print(f"Found {len(findings)} vulnerabilities:\n")
        
        severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "ℹ️"}
        for f in findings:
            emoji = severity_emoji.get(f.severity.value, "❓")
            print(f"  {emoji} [{f.severity.value.upper()}] {f.title}")
            print(f"     📍 {f.location.file_path}:{f.location.line_start}")
            print(f"     🔗 {f.cwe_id}")
            if f.is_sanitized:
                if f.sanitizer_effective:
                    print(f"     🛡️  Sanitized")
                else:
                    print(f"     ⚠️  Sanitizer INEFFECTIVE")
            print()
        
        # Save report
        report = engine.generate_report(findings)
        report_path = args.output or "sast_report.md"
        with open(report_path, "w") as f:
            f.write(report)
        print(f"📝 Report saved to: {report_path}")
    else:
        print("✅ No vulnerabilities found.")


def cmd_recon(args):
    """Run reconnaissance only."""
    from agents.recon_agent import ReconAgent
    
    async def run():
        import httpx
        
        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            agent = ReconAgent(http_client=client)
            
            print(f"\n🔍 Reconnaissance")
            print(f"🎯 Target: {args.target}")
            print(f"📋 Depth: {args.depth}")
            print(f"{'=' * 50}\n")
            
            result = await agent.recon(args.target, args.depth)
            
            print(f"  🌐 Subdomains: {len(result.subdomains)}")
            for sub in result.subdomains[:10]:
                print(f"     - {sub}")
            
            print(f"  🔧 Technologies: {len(result.technologies)}")
            for tech in result.technologies:
                print(f"     - {tech}")
            
            print(f"  📡 Endpoints: {len(result.endpoints)}")
            for ep in result.endpoints[:10]:
                print(f"     - {ep}")
            
            print(f"  📜 JS Files: {len(result.js_files)}")
            print(f"  🔌 API Endpoints: {len(result.api_endpoints)}")
            print(f"  ⚠️  Interesting Files: {len(result.interesting_files)}")
            for f in result.interesting_files:
                print(f"     - ⚠️  {f}")
            
            # Save report
            report = agent.generate_report(result)
            report_path = args.output or "recon_report.md"
            with open(report_path, "w") as f:
                f.write(report)
            print(f"\n📝 Report saved to: {report_path}")
    
    asyncio.run(run())


def cmd_info(args):
    """Show system info and capabilities."""
    print("""
⚡ Strix-Advanced — AI-Powered Security Testing Platform
========================================================

📦 Modules:
  ✅ Static Analysis Engine (CPG Builder, Data Flow, Sanitizer)
  ✅ Memory & Learning System (Scan Memory, Global Memory, Dedup, Skill Gen)
  ✅ Advanced Exploitation (Chain Builder, Auth, Race Detector, Logic Fuzzer, WAF Bypass)
  ✅ Specialized Agents (Recon, Exploit, Analysis, Report, Coordinator)
  ✅ Unique Features (API Discovery, Supply Chain, Infrastructure, Custom Rules)

🔧 Capabilities:
  • 6 languages (Python, JS, TS, Go, Java, PHP)
  • 20+ vulnerability types (CWE/OWASP mapped)
  • 15+ custom rules built-in
  • WAF bypass (15+ techniques)
  • Exploit chain discovery
  • Race condition detection
  • Business logic fuzzing
  • API discovery (Swagger, GraphQL, brute-force)
  • Supply chain analysis (npm, pip, go, cargo)
  • Infrastructure security (DNS, SSL, headers, cloud)

📖 Docs: https://github.com/Hafiz380/strix-advanced
""")


def main():
    parser = argparse.ArgumentParser(
        prog="strix-advanced",
        description="⚡ Strix-Advanced — AI-Powered Security Testing Platform",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run security scan")
    scan_parser.add_argument("target", help="Target URL or path")
    scan_parser.add_argument("--type", choices=["full", "quick", "code_only", "recon_only"], default="full", help="Scan type")
    scan_parser.add_argument("--code", help="Local code path for white-box testing")
    scan_parser.add_argument("--depth", choices=["quick", "standard", "deep"], default="standard", help="Recon depth")
    scan_parser.add_argument("--max-exploits", type=int, default=50, help="Max exploits to try")
    scan_parser.add_argument("--output", "-o", default="./strix-results", help="Output directory")
    scan_parser.add_argument("--no-summary", action="store_true", help="Skip executive summary")
    
    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Static analysis only")
    analyze_parser.add_argument("path", help="File or directory to analyze")
    analyze_parser.add_argument("--output", "-o", help="Report output file")
    
    # Recon command
    recon_parser = subparsers.add_parser("recon", help="Reconnaissance only")
    recon_parser.add_argument("target", help="Target URL or domain")
    recon_parser.add_argument("--depth", choices=["quick", "standard", "deep"], default="standard", help="Recon depth")
    recon_parser.add_argument("--output", "-o", help="Report output file")
    
    # Rules command
    rules_parser = subparsers.add_parser("rules", help="Manage custom rules")
    rules_sub = rules_parser.add_subparsers(dest="rules_action")
    
    rules_list = rules_sub.add_parser("list", help="List all rules")
    
    rules_scan = rules_sub.add_parser("scan", help="Scan with custom rules")
    rules_scan.add_argument("path", help="Directory to scan")
    
    rules_export = rules_sub.add_parser("export", help="Export rules")
    rules_export.add_argument("--output", "-o", default="custom_rules.yaml", help="Output file")
    
    # Info command
    subparsers.add_parser("info", help="Show system info")
    
    args = parser.parse_args()
    
    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "recon":
        cmd_recon(args)
    elif args.command == "rules":
        cmd_rules(args)
    elif args.command == "info":
        cmd_info(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
