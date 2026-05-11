#!/usr/bin/env python3
"""
Strix-Advanced Setup Script
============================
Installs dependencies and verifies the installation.
"""

import subprocess
import sys


def install():
    """Install dependencies."""
    print("⚡ Strix-Advanced Setup\n")
    
    # Core dependencies
    core_deps = [
        "tree-sitter",
        "tree-sitter-python",
        "tree-sitter-javascript",
        "tree-sitter-typescript",
        "tree-sitter-go",
        "tree-sitter-java",
        "httpx",
        "litellm",
        "jinja2",
        "defusedxml",
    ]
    
    # Dev dependencies
    dev_deps = [
        "pytest",
        "pytest-asyncio",
        "ruff",
    ]
    
    print("📦 Installing core dependencies...")
    for dep in core_deps:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", dep])
            print(f"  ✅ {dep}")
        except subprocess.CalledProcessError:
            print(f"  ❌ {dep} (failed)")
    
    print("\n📦 Installing dev dependencies...")
    for dep in dev_deps:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", dep])
            print(f"  ✅ {dep}")
        except subprocess.CalledProcessError:
            print(f"  ❌ {dep} (failed)")
    
    # Verify installation
    print("\n🔍 Verifying installation...")
    
    try:
        from core.static_analyzer import StaticAnalysisEngine
        engine = StaticAnalysisEngine()
        if engine.is_available():
            print("  ✅ Static Analysis Engine ready")
        else:
            print(f"  ⚠️  Static Analysis Engine: {engine.get_init_error()}")
    except Exception as e:
        print(f"  ❌ Static Analysis Engine: {e}")
    
    try:
        from core.recon.custom_rules import CustomRuleEngine
        engine = CustomRuleEngine()
        print(f"  ✅ Custom Rule Engine ready ({len(engine.rules)} rules)")
    except Exception as e:
        print(f"  ❌ Custom Rule Engine: {e}")
    
    try:
        from core.exploitation import WAFBypass, ExploitChainBuilder
        print("  ✅ Exploitation Engine ready")
    except Exception as e:
        print(f"  ❌ Exploitation Engine: {e}")
    
    try:
        from core.memory import ScanMemory, GlobalMemory
        print("  ✅ Memory System ready")
    except Exception as e:
        print(f"  ❌ Memory System: {e}")
    
    try:
        from agents import CoordinatorAgent
        print("  ✅ Agent System ready")
    except Exception as e:
        print(f"  ❌ Agent System: {e}")
    
    print("\n🎉 Setup complete!")
    print("\nNext steps:")
    print("  python cli.py info          # Show system info")
    print("  python cli.py rules list    # List custom rules")
    print("  python cli.py analyze .     # Run static analysis")
    print("  python cli.py scan https://target.com  # Full scan")


if __name__ == "__main__":
    install()
