# Strix Architecture Deep Analysis + Gap Report
## Step 1 Deliverable — Strix-Advanced Project

**Date:** 2026-05-11
**Analyst:** Zaid (AI Assistant for Hafiz)

---

## 1. Strix Architecture Overview

### 1.1 Core Components

```
strix/
├── agents/           # Agent system (BaseAgent → StrixAgent)
│   ├── base_agent.py      # Core agent loop, sandbox init, message handling
│   ├── state.py            # Agent state management
│   └── StrixAgent/         # Main scanning agent
├── config/           # Configuration management
│   └── config.py           # Env vars, CLI config, LLM resolution
├── llm/              # LLM integration (LiteLLM-based)
│   ├── llm.py              # Main LLM class, prompt building, streaming
│   ├── config.py           # LLMConfig dataclass
│   ├── memory_compressor.py # Context window management
│   └── dedupe.py           # Message deduplication
├── runtime/          # Execution sandboxing
│   ├── runtime.py          # Abstract runtime interface
│   └── docker_runtime.py   # Docker-based sandbox (Caido proxy + tool server)
├── skills/           # Knowledge base (markdown files)
│   ├── vulnerabilities/    # 20+ vuln categories (XSS, SQLi, SSRF, etc.)
│   ├── tooling/            # Tool usage guides (nmap, nuclei, sqlmap, etc.)
│   ├── frameworks/         # Framework-specific skills (FastAPI, Next.js, etc.)
│   ├── coordination/       # Agent orchestration skills
│   └── scan_modes/         # Quick/Standard/Deep mode configs
├── tools/            # Tool implementations
│   ├── browser/            # Playwright-based browser automation
│   ├── terminal/           # Shell execution in sandbox
│   ├── proxy/              # HTTP proxy (Caido integration)
│   ├── python/             # Python code execution
│   ├── web_search/         # Perplexity API integration
│   ├── file_edit/          # File read/write in sandbox
│   ├── agents_graph/       # Multi-agent coordination
│   ├── reporting/          # Report generation
│   ├── notes/              # Note-taking during scan
│   ├── todo/               # Task tracking
│   ├── thinking/           # Reasoning/thinking tool
│   ├── load_skill/         # Dynamic skill loading
│   ├── finish/             # Scan completion
│   └── registry.py         # Tool registration system (XML schema-based)
├── interface/        # TUI (Textual-based terminal UI)
│   ├── tui.py              # Main terminal interface
│   ├── main.py             # Entry point
│   └── tool_components/    # Renderers for each tool
├── telemetry/        # Analytics & tracing
│   ├── tracer.py           # Scan execution tracing
│   └── posthog.py          # Usage analytics
└── utils/            # Shared utilities
```

### 1.2 Agent System Architecture

**BaseAgent** (base_agent.py):
- Metaclass-based agent registration (AgentMeta)
- Jinja2 template system for prompts
- Async agent loop with max 300 iterations
- Sandbox initialization (Docker container)
- Inter-agent messaging system
- LLM error handling with retry logic
- Streaming response handling
- Telemetry integration (tracer)

**StrixAgent** (strix_agent.py):
- Extends BaseAgent
- Default skill: `root_agent` (orchestration)
- Scan config → task decomposition
- Multi-target support (repo, local code, URL, IP)
- Diff-scope support for PR scanning

**Key Insight:** Strix uses a SINGLE agent type (StrixAgent) that acts as both orchestrator AND worker. The `root_agent` skill teaches it to spawn sub-agents via the `agents_graph` tool.

### 1.3 Runtime / Sandbox System

**DockerRuntime** (docker_runtime.py):
- Docker container per scan
- Image: `ghcr.io/usestrix/strix-sandbox:0.1.13`
- Embedded Caido proxy (HTTP interception)
- Tool server (REST API inside container)
- Port mapping: tool_server (48081), caido (48080)
- Token-based auth for tool server
- Local directory copy into container
- NET_ADMIN + NET_RAW capabilities

**Tool Server** (runtime/tool_server.py):
- REST API running inside Docker container
- Provides: terminal, browser, proxy, file operations
- Agent communicates via HTTP to localhost:{port}

### 1.4 LLM Integration

**LLM class** (llm/llm.py):
- Built on LiteLLM (multi-provider support)
- Supports: OpenAI, Anthropic, Google, Ollama, local models
- Streaming responses
- Thinking/reasoning block extraction
- Memory compression (context window management)
- Tool invocation parsing (XML-based)
- System prompt construction from skills + tools

**LLMConfig** (llm/config.py):
- Model name, API key, base URL
- Skills list, scan mode
- Reasoning effort level
- Interactive mode flag

### 1.5 Skills System

**How Skills Work:**
- Markdown files in `strix/skills/` directories
- Loaded dynamically by name
- Injected into system prompt
- Max 5 skills per agent
- Categories: vulnerabilities, tooling, frameworks, coordination, scan_modes
- Excluded from user selection: scan_modes, coordination (internal)

**Skill Content Structure:**
- YAML frontmatter (name, description)
- Markdown body with attack patterns, payloads, reconnaissance steps
- Framework-specific guidance

### 1.6 Tool System

**Tool Registration** (tools/registry.py):
- Python decorator-based: `@register_tool`
- XML schema for LLM prompt
- Sandbox execution flag (runs in container vs host)
- Conditional registration (browser, web_search)
- Module-based grouping in prompts

**Available Tools:**
| Tool | Sandbox | Description |
|------|---------|-------------|
| terminal | ✅ | Shell command execution |
| browser | ✅ | Playwright browser automation |
| proxy | ✅ | HTTP proxy via Caido |
| python | ✅ | Python code execution |
| file_edit | ✅ | File read/write |
| web_search | ❌ | Perplexity API (host-side) |
| agents_graph | ❌ | Multi-agent coordination |
| reporting | ✅ | Report generation |
| notes | ✅ | Note-taking |
| todo | ✅ | Task management |
| thinking | ✅ | Reasoning tool |
| load_skill | ✅ | Dynamic skill loading |
| finish | ✅ | Scan completion |

### 1.7 Multi-Agent System

**agents_graph tool:**
- Agent spawn with task delegation
- Parent-child relationships
- Inter-agent messaging (async)
- Agent status tracking (running, waiting, completed, failed)
- Graph visualization of agent hierarchy

**Coordination Pattern:**
1. Root agent analyzes target
2. Spawns specialized sub-agents (recon, vuln assessment, exploitation)
3. Sub-agents report back via agents_graph
4. Root agent aggregates findings

---

## 2. Gap Analysis — Where Strix Falls Short

### 2.1 Critical Gaps

| Gap | Impact | Priority |
|-----|--------|----------|
| **No Static Analysis (White-box)** | Cannot analyze source code for vulnerabilities before testing | 🔴 Critical |
| **No Memory/Learning System** | Every scan starts from zero, duplicates common findings | 🔴 Critical |
| **Single Agent Type** | All agents are StrixAgent, no specialized roles | 🟡 High |
| **No Business Logic Intelligence** | Skills exist but no automated invariant discovery | 🟡 High |
| **No Auth Flow Automation** | Manual credential handling, no 2FA/SSO support | 🟡 High |
| **No Supply Chain Analysis** | Cannot detect dependency vulnerabilities | 🟡 High |
| **No Race Condition Automation** | Skill exists but no concurrent request engine | 🟡 High |
| **Basic Reporting** | No executive summary, no remediation code | 🟠 Medium |
| **No CI/CD Learning** | Doesn't learn from previous CI runs | 🟠 Medium |
| **No Custom Rule Engine** | Cannot define custom attack patterns | 🟠 Medium |

### 2.2 What Shannon Does Better

| Feature | Strix | Shannon |
|---------|-------|---------|
| Static Analysis | ❌ None | ✅ CPG-based (AST + CFG + PDF) |
| Data Flow Tracing | ❌ | ✅ Source → Sink with LLM validation |
| Business Logic | Skill-based guidance only | ✅ Automated invariant discovery + fuzzer gen |
| Auth Handling | Manual | ✅ 2FA/TOTP/SSO automated |
| Static-Dynamic Correlation | ❌ | ✅ Static findings → live exploit validation |
| Proactive Fuzzing | ❌ | ✅ Auto-generated fuzzers |

### 2.3 What Hermes Agent Does Better

| Feature | Strix | Hermes Agent |
|---------|-------|--------------|
| Learning Loop | ❌ None | ✅ Skills from experience, self-improvement |
| Memory System | ❌ | ✅ Persistent memory, FTS5 search |
| Skill Creation | Pre-defined only | ✅ Auto-created from complex tasks |
| Cross-session Knowledge | ❌ | ✅ Deepening user model |
| Multi-platform | Docker only | ✅ Docker, SSH, Singularity, Modal, Daytona |
| Cron/Scheduling | ❌ | ✅ Built-in scheduler |

### 2.4 What ECC Does Better

| Feature | Strix | ECC |
|---------|-------|-----|
| Continuous Learning | ❌ | ✅ Auto-extract patterns from sessions |
| Skill Evolution | Static | ✅ Skills self-improve during use |
| Memory Persistence | ❌ | ✅ Hooks that save/load context |
| Verification Loops | ❌ | ✅ Checkpoint vs continuous evals |
| Parallelization | Basic agent spawning | ✅ Git worktrees, cascade method |

---

## 3. Proposed Enhancement Architecture

### 3.1 New Components to Build

```
strix-advanced/
├── core/
│   ├── static_analyzer/        # NEW: White-box analysis engine
│   │   ├── cpg_builder.py          # Code Property Graph construction
│   │   ├── data_flow.py            # Source → Sink tracing
│   │   ├── sanitizer_analyzer.py   # LLM-guided sanitization check
│   │   └── languages/              # Per-language parsers
│   ├── memory/                 # NEW: Learning & memory system
│   │   ├── scan_memory.py          # Per-scan learning
│   │   ├── global_memory.py        # Cross-scan knowledge
│   │   ├── skill_generator.py      # Auto-skill creation
│   │   └── dedup_engine.py         # Finding deduplication
│   ├── exploitation/           # NEW: Advanced exploitation
│   │   ├── chain_builder.py        # Exploit chain discovery
│   │   ├── auth_automator.py       # 2FA/SSO/OAuth2 handling
│   │   ├── race_detector.py        # Concurrent request engine
│   │   ├── logic_fuzzer.py         # Business logic fuzzer
│   │   └── waf_bypass.py           # WAF/IDS evasion
│   ├── recon/                  # NEW: Advanced reconnaissance
│   │   ├── api_discovery.py        # API endpoint discovery
│   │   ├── supply_chain.py         # Dependency analysis
│   │   └── infrastructure.py       # Cloud/DNS/SSL analysis
│   └── reporting/              # ENHANCED: Better reports
│       ├── smart_reporter.py       # AI-powered reporting
│       ├── remediation.py          # Fix suggestions with code
│       └── executive_summary.py    # Non-technical summary
├── agents/                     # ENHANCED: Specialized agents
│   ├── recon_agent.py              # Reconnaissance specialist
│   ├── exploit_agent.py            # Exploitation specialist
│   ├── analysis_agent.py           # Static analysis specialist
│   ├── report_agent.py             # Reporting specialist
│   └── coordinator.py              # Enhanced orchestration
├── skills/                     # ENHANCED: More skills + auto-generation
│   ├── advanced/                   # New advanced skill categories
│   └── generated/                  # Auto-generated from memory
└── rules/                      # NEW: Custom rule engine
    ├── rule_engine.py              # Rule evaluation
    └── rules/                      # User-defined rules
```

### 3.2 Integration Points with Reference Repos

**From Shannon:**
- CPG builder concept (simplified — Shannon Pro uses Joern, we'll use tree-sitter)
- Static-dynamic correlation pattern
- Business logic invariant discovery approach
- Auth flow automation design

**From Hermes Agent:**
- Learning loop architecture (skill creation from experience)
- Memory persistence patterns (FTS5 search)
- Cross-session knowledge accumulation
- Self-improving skill system

**From ECC:**
- Continuous learning hooks
- Verification loop patterns
- Parallelization strategies
- Skill evolution framework

---

## 4. Implementation Priority Matrix

### Phase 1: Foundation (Steps 2-3)
1. Static Analysis Engine — CPG builder + data flow tracer
2. Memory System — Scan memory + dedup engine

### Phase 2: Intelligence (Steps 4-5)
3. Advanced Exploitation — Chain builder + auth automator + race detector
4. Specialized Agents — Recon, Exploit, Analysis, Report agents

### Phase 3: Differentiation (Steps 6-7)
5. API Discovery + Supply Chain Analysis
6. Smart Reporting + Remediation
7. Custom Rule Engine + CI/CD Learning

---

## 5. Technical Decisions

### 5.1 Language Parsers
- **tree-sitter** for multi-language AST parsing (Python, JS/TS, Go, Java, PHP)
- Lightweight, fast, runs in-process (no Joern dependency)
- Custom data flow analysis on top of tree-sitter AST

### 5.2 Memory Storage
- SQLite for persistent memory (like Hermes)
- FTS5 for full-text search across findings
- JSON for scan-specific state

### 5.3 LLM Integration
- Keep LiteLLM as base (proven, multi-provider)
- Add structured output for finding classification
- Use smaller models for dedup/classification (cost optimization)

### 5.4 Exploitation Engine
- Async HTTP client (httpx) for concurrent requests
- Playwright for browser-based exploitation
- Custom protocol handlers for WebSocket, GraphQL, gRPC

---

## Next Steps

**Step 2:** Build the Static Analysis Engine
- tree-sitter integration for Python, JS/TS, Go, Java
- Code Property Graph builder
- Data flow tracer (source → sink)
- Sanitizer analysis with LLM guidance

**Estimated effort:** This will be the largest component. Will deliver as a standalone module.
