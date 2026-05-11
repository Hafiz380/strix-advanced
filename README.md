# Strix-Advanced
## AI-Powered Security Testing Platform

An enhanced fork of [Strix](https://github.com/usestrix/strix) with advanced capabilities inspired by:
- [Shannon](https://github.com/KeygraphHQ/shannon) — White-box analysis & static-dynamic correlation
- [Hermes Agent](https://github.com/nousresearch/hermes-agent) — Self-improving learning loop & memory
- [Everything Claude Code](https://github.com/affaan-m/everything-claude-code) — Continuous learning & skill evolution

## Components

### Step 1: Architecture Analysis
- Full analysis of Strix codebase
- Gap analysis vs Shannon, Hermes, ECC
- Enhancement roadmap

### Step 2: Static Analysis Engine (`core/static_analyzer/`)
- CPG Builder (tree-sitter based, 6 languages)
- Data Flow Analyzer (source → sink tracing)
- Sanitizer Analyzer (LLM-guided validation)
- 20+ vulnerability types with CWE/OWASP/CVSS

### Step 3: Memory & Learning System (`core/memory/`)
- Scan Memory (SQLite per-scan storage)
- Global Memory (cross-scan knowledge accumulation)
- Dedup Engine (finding deduplication across scans)
- Skill Generator (auto-generate skills from experience)

### Step 4: Advanced Exploitation Engine (`core/exploitation/`)
- Exploit Chain Builder (multi-vuln chaining)
- Auth Automator (2FA/TOTP/SSO/OAuth2)
- Race Condition Detector (concurrent request engine)
- Logic Fuzzer (business logic invariant testing)
- WAF Bypass Engine (15+ evasion techniques)

## Installation

```bash
python install_strix_advanced.py
cd strix-advanced
pip install tree-sitter tree-sitter-python tree-sitter-javascript
```

## Usage

```python
# Static Analysis
from core.static_analyzer import StaticAnalysisEngine
engine = StaticAnalysisEngine()
findings = engine.analyze_project("/path/to/project")

# Memory System
from core.memory import ScanMemory, GlobalMemory, DedupEngine
memory = ScanMemory("scans.db")
global_mem = GlobalMemory("global.db")
dedup = DedupEngine(global_mem)

# Exploitation
from core.exploitation import ExploitChainBuilder, RaceConditionDetector, WAFBypass
chain_builder = ExploitChainBuilder()
chains = chain_builder.analyze(vulnerabilities)

waf = WAFBypass()
payloads = waf.bypass_sqli("' OR 1=1--")
```

## Status

- [x] Step 1: Architecture Analysis & Gap Report
- [x] Step 2: Static Analysis Engine
- [x] Step 3: Memory & Learning System
- [x] Step 4: Advanced Exploitation Engine
- [ ] Step 5: Specialized Agent System
- [ ] Step 6: Unique Features
- [ ] Step 7: Integration & Polish
