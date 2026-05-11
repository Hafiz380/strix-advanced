# Step 2 — Static Analysis Engine (Complete)

## What Was Built

### Components

1. **CPG Builder** (`core/static_analyzer/cpg_builder.py`)
   - tree-sitter integration for multi-language AST parsing
   - Supported: Python, JavaScript, TypeScript, Go, Java, PHP
   - Builds Code Property Graph = AST + CFG + Data Flow
   - Node types: Function, Method, Class, Variable, Call, Assignment, If, While, For, Try, Import
   - Edge types: Child, FlowsTo, Defines, Uses, Reaches, TaintedBy, Calls

2. **Data Flow Analyzer** (`core/static_analyzer/data_flow.py`)
   - Source identification (user input, HTTP requests, env vars, file reads)
   - Sink identification (SQL, command exec, eval, template rendering, HTTP client)
   - Sanitizer identification (escape functions, parameterized queries, validation)
   - Taint propagation through data flow edges
   - Source → Sink path finding with confidence scoring

3. **Sanitizer Analyzer** (`core/static_analyzer/sanitizer_analyzer.py`)
   - LLM-guided validation of sanitizer effectiveness
   - Context-aware: checks if sanitizer works FOR SPECIFIC vuln type
   - Fallback heuristic validation when LLM unavailable
   - Example: html.escape() is effective for XSS but NOT for SQLi

4. **Findings** (`core/static_analyzer/findings.py`)
   - Rich finding model with severity, confidence, CWE, OWASP, CVSS
   - Code flow evidence with source/sink/path locations
   - Markdown report generation
   - 20+ vulnerability types with CWE/OWASP mappings

5. **Engine** (`core/static_analyzer/engine.py`)
   - Main integration: CPG → Data Flow → Sanitizer Validation → Findings
   - Analyze project, files, or code snippets
   - Configurable severity/confidence filtering
   - Report generation

### Vulnerability Coverage

| Vuln Type | CWE | OWASP | CVSS |
|-----------|-----|-------|------|
| SQL Injection | CWE-89 | A03 | 9.8 |
| XSS | CWE-79 | A03 | 6.1 |
| RCE | CWE-78 | A03 | 9.8 |
| SSTI | CWE-1336 | A03 | 9.0 |
| SSRF | CWE-918 | A10 | 8.6 |
| Path Traversal | CWE-22 | A01 | 7.5 |
| IDOR | CWE-639 | A01 | 6.5 |
| CSRF | CWE-352 | A01 | 6.5 |
| XXE | CWE-611 | A05 | 7.5 |
| Deserialization | CWE-502 | A08 | 9.8 |
| Open Redirect | CWE-601 | - | 6.1 |
| NoSQL Injection | CWE-943 | A03 | 9.8 |
| Auth Bypass | CWE-287 | A07 | 9.1 |

### Language-Specific Patterns

**Python Sources:** Flask, Django, FastAPI request objects, input(), os.environ, sys.argv, file reads
**Python Sinks:** cursor.execute, os.system, eval, exec, render_template_string, requests.get, open
**Python Sanitizers:** html.escape, shlex.quote, os.path.realpath, re.match, pydantic

**JavaScript Sources:** Express req.body/query/params, window.location, DOM input
**JavaScript Sinks:** innerHTML, eval, Function, fetch, child_process.exec, ejs.render
**JavaScript Sanitizers:** DOMPurify, encodeURIComponent, validator.js

## Installation

```bash
cd strix-advanced
pip install tree-sitter tree-sitter-python tree-sitter-javascript tree-sitter-typescript tree-sitter-go tree-sitter-java
```

## Usage

```python
from core.static_analyzer import StaticAnalysisEngine

engine = StaticAnalysisEngine()

# Analyze a project
findings = engine.analyze_project("/path/to/project")

# Analyze code snippet
findings = engine.analyze_code(code, "python", "app.py")

# Generate report
report = engine.generate_report(findings)
```

## Next Steps

**Step 3:** Memory & Learning System
- Persistent scan memory (SQLite)
- Finding deduplication across scans
- Auto-skill generation from findings
- Cross-scan knowledge accumulation
