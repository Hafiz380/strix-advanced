# ⚡ Strix-Advanced

**AI-Powered Security Testing Platform**

An enhanced fork of [Strix](https://github.com/usestrix/strix) with advanced capabilities inspired by:
- [Shannon](https://github.com/KeygraphHQ/shannon) — White-box analysis & static-dynamic correlation
- [Hermes Agent](https://github.com/nousresearch/hermes-agent) — Self-improving learning loop & memory
- [Everything Claude Code](https://github.com/affaan-m/everything-claude-code) — Continuous learning & skill evolution

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/Hafiz380/strix-advanced.git
cd strix-advanced

# Setup
python setup.py

# Run
python cli.py info
python cli.py scan https://target.com
```

---

## 📦 Modules

### Step 2: Static Analysis Engine (`core/static_analyzer/`)
- **CPG Builder** — tree-sitter based Code Property Graph (6 languages)
- **Data Flow Analyzer** — Source → Sink taint tracing
- **Sanitizer Analyzer** — LLM-guided sanitizer effectiveness validation
- **20+ vulnerability types** with CWE/OWASP/CVSS mappings

### Step 3: Memory & Learning System (`core/memory/`)
- **Scan Memory** — Per-scan SQLite storage
- **Global Memory** — Cross-scan knowledge accumulation
- **Dedup Engine** — Finding deduplication across scans
- **Skill Generator** — Auto-generate skills from scan experience

### Step 4: Advanced Exploitation Engine (`core/exploitation/`)
- **Exploit Chain Builder** — Multi-vulnerability chaining (10 known patterns + novel discovery)
- **Auth Automator** — 2FA/TOTP/SSO/OAuth2/JWT handling
- **Race Condition Detector** — Concurrent request engine for TOCTOU bugs
- **Logic Fuzzer** — Business logic invariant testing
- **WAF Bypass** — 15+ evasion techniques for SQLi, XSS, SSRF, Path Traversal

### Step 5: Specialized Agent System (`agents/`)
- **Recon Agent** — Subdomain enum, DNS, tech fingerprinting, endpoint discovery
- **Exploit Agent** — SQLi, XSS, SSRF, RCE, SSTI, Path Traversal exploitation
- **Analysis Agent** — Static analysis integration
- **Report Agent** — Professional security reports with executive summary
- **Coordinator Agent** — Full scan orchestration pipeline

### Step 6: Unique Features (`core/recon/`)
- **API Discovery** — Swagger/OpenAPI parsing, GraphQL introspection, brute-force, JS extraction
- **Supply Chain** — npm/pip/go/cargo dependency scanning, typosquat detection
- **Infrastructure** — DNS, SSL/TLS, security headers, CORS, cookies, cloud storage
- **Custom Rules** — 15+ built-in rules, YAML/JSON rule loading, directory scanning

---

## 🔧 CLI Usage

```bash
# Full security scan
python cli.py scan https://target.com

# Code-only scan (white-box)
python cli.py scan https://target.com --code ./src --type code

# Quick scan
python cli.py scan https://target.com --type quick --depth quick

# Static analysis only
python cli.py analyze ./src

# Reconnaissance only
python cli.py recon https://target.com --depth deep

# Custom rules
python cli.py rules list
python cli.py rules scan ./code
python cli.py rules export --output rules.yaml

# System info
python cli.py info
```

---

## 📊 Vulnerability Coverage

| Vuln Type | CWE | OWASP |
|-----------|-----|-------|
| SQL Injection | CWE-89 | A03 |
| XSS | CWE-79 | A03 |
| RCE | CWE-78 | A03 |
| SSTI | CWE-1336 | A03 |
| SSRF | CWE-918 | A10 |
| Path Traversal | CWE-22 | A01 |
| IDOR | CWE-639 | A01 |
| CSRF | CWE-352 | A01 |
| XXE | CWE-611 | A05 |
| Deserialization | CWE-502 | A08 |
| Open Redirect | CWE-601 | - |
| NoSQL Injection | CWE-943 | A03 |
| Auth Bypass | CWE-287 | A07 |
| Race Condition | CWE-362 | A04 |

---

## 🧪 Testing

```bash
pytest tests/ -v
```

---

## 📁 Project Structure

```
strix-advanced/
├── cli.py                    # Command-line interface
├── setup.py                  # Setup & dependency installation
├── pyproject.toml            # Project config
├── core/
│   ├── static_analyzer/      # White-box analysis engine
│   ├── memory/               # Learning & memory system
│   ├── exploitation/         # Advanced exploitation engine
│   └── recon/                # API discovery, supply chain, infra, rules
├── agents/                   # Specialized agent system
├── tests/                    # Test suite
├── examples/                 # Usage examples
└── .github/workflows/        # CI/CD
```

---

## 📋 Status

- [x] Step 1: Architecture Analysis & Gap Report
- [x] Step 2: Static Analysis Engine
- [x] Step 3: Memory & Learning System
- [x] Step 4: Advanced Exploitation Engine
- [x] Step 5: Specialized Agent System
- [x] Step 6: Unique Features
- [x] Step 7: Integration & Polish (CLI, CI/CD, Tests, Setup)

**🎉 All steps complete!**

---

## 📄 License

Based on Strix (see original LICENSE). Enhancements are additive.

---

*Built with ⚡ by Hafiz & Zaid*
