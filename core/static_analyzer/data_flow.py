"""
Data Flow Analyzer
==================
Traces data flow from sources to sinks through the CPG.
Identifies tainted data paths that could lead to vulnerabilities.

Source: User input, HTTP requests, file reads, environment variables
Sink: SQL queries, command execution, file writes, HTTP responses, HTML output
Sanitizer: Input validation, encoding, parameterized queries
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .cpg_builder import CPG, CPGNode, CPGEdge, EdgeType, NodeType


class TaintLevel(Enum):
    """Taint level for data flow tracking."""
    CLEAN = 0        # Safe, validated data
    TAINTED = 1      # Untrusted user input
    PROPAGATED = 2   # Derived from tainted data
    SANITIZED = 3    # Passed through sanitizer (may still be risky)


@dataclass
class SourcePattern:
    """Pattern to identify data sources (where untrusted data enters)."""
    name: str
    language: str  # "python", "javascript", "go", "java", or "all"
    node_type: NodeType
    patterns: list[str]  # Function/variable name patterns
    description: str = ""
    severity: str = "high"


@dataclass
class SinkPattern:
    """Pattern to identify data sinks (where data is used dangerously)."""
    name: str
    language: str
    node_type: NodeType
    patterns: list[str]
    vuln_type: str  # "sqli", "xss", "rce", "ssrf", "path_traversal", etc.
    description: str = ""
    severity: str = "critical"


@dataclass
class SanitizerPattern:
    """Pattern to identify sanitizers (functions that clean data)."""
    name: str
    language: str
    patterns: list[str]
    effective_against: list[str]  # vuln_types this sanitizer handles
    description: str = ""


@dataclass
class TaintPath:
    """A path from source to sink through the CPG."""
    source_node: CPGNode
    sink_node: CPGNode
    path: list[str]  # Node IDs in order
    vuln_type: str
    is_sanitized: bool = False
    sanitizer_nodes: list[CPGNode] = field(default_factory=list)
    confidence: float = 0.0  # 0.0 to 1.0
    description: str = ""


# ============================================================
# Built-in Source/Sink/Sanitizer Patterns
# ============================================================

PYTHON_SOURCES = [
    SourcePattern(
        name="flask_request",
        language="python",
        node_type=NodeType.CALL,
        patterns=["request.args", "request.form", "request.json", "request.data",
                  "request.headers", "request.cookies", "request.values",
                  "request.get_json", "request.get_data"],
        description="Flask request data",
    ),
    SourcePattern(
        name="django_request",
        language="python",
        node_type=NodeType.CALL,
        patterns=["request.GET", "request.POST", "request.body", "request.headers",
                  "request.COOKIES", "request.FILES", "request.META",
                  "request.data", "request.query_params"],
        description="Django request data",
    ),
    SourcePattern(
        name="fastapi_request",
        language="python",
        node_type=NodeType.CALL,
        patterns=["request.query_params", "request.path_params", "request.headers",
                  "request.cookies", "request.body"],
        description="FastAPI request data",
    ),
    SourcePattern(
        name="input_function",
        language="python",
        node_type=NodeType.CALL,
        patterns=["input"],
        description="Built-in input() function",
    ),
    SourcePattern(
        name="env_vars",
        language="python",
        node_type=NodeType.CALL,
        patterns=["os.environ", "os.getenv", "environ.get"],
        description="Environment variables",
    ),
    SourcePattern(
        name="file_read",
        language="python",
        node_type=NodeType.CALL,
        patterns=["open", "file.read", "f.read", "pathlib.read_text",
                  "Path.read_text"],
        description="File read operations",
    ),
    SourcePattern(
        name="argv",
        language="python",
        node_type=NodeType.CALL,
        patterns=["sys.argv", "argparse", "click.argument", "click.option"],
        description="Command line arguments",
    ),
]

PYTHON_SINKS = [
    SinkPattern(
        name="sql_execution",
        language="python",
        node_type=NodeType.CALL,
        patterns=["execute", "executemany", "executescript", "raw",
                  "cursor.execute", "connection.execute"],
        vuln_type="sqli",
        description="SQL query execution",
    ),
    SinkPattern(
        name="command_execution",
        language="python",
        node_type=NodeType.CALL,
        patterns=["os.system", "os.popen", "subprocess.call", "subprocess.run",
                  "subprocess.Popen", "subprocess.check_output", "subprocess.check_call",
                  "commands.getoutput", "popen2.popen"],
        vuln_type="rce",
        description="OS command execution",
    ),
    SinkPattern(
        name="eval_execution",
        language="python",
        node_type=NodeType.CALL,
        patterns=["eval", "exec", "compile", "ast.literal_eval"],
        vuln_type="rce",
        description="Dynamic code evaluation",
    ),
    SinkPattern(
        name="template_rendering",
        language="python",
        node_type=NodeType.CALL,
        patterns=["render_template_string", "Template", "Jinja2.Template",
                  "Environment.from_string", "Markup"],
        vuln_type="ssti",
        description="Server-side template injection",
    ),
    SinkPattern(
        name="html_response",
        language="python",
        node_type=NodeType.CALL,
        patterns=["Response", "HttpResponse", "make_response", "html",
                  "render_template", "Markup"],
        vuln_type="xss",
        description="HTML response generation",
    ),
    SinkPattern(
        name="file_write",
        language="python",
        node_type=NodeType.CALL,
        patterns=["open", "file.write", "f.write", "pathlib.write_text",
                  "Path.write_text", "shutil.copy", "shutil.move"],
        vuln_type="path_traversal",
        description="File write operations",
    ),
    SinkPattern(
        name="ssrf_requests",
        language="python",
        node_type=NodeType.CALL,
        patterns=["requests.get", "requests.post", "requests.put", "requests.delete",
                  "requests.patch", "requests.head", "httpx.get", "httpx.post",
                  "urllib.request.urlopen", "urlopen"],
        vuln_type="ssrf",
        description="HTTP client requests",
    ),
    SinkPattern(
        name="deserialization",
        language="python",
        node_type=NodeType.CALL,
        patterns=["pickle.loads", "pickle.load", "yaml.load", "yaml.unsafe_load",
                  "marshal.loads", "shelve.open"],
        vuln_type="deserialization",
        description="Unsafe deserialization",
    ),
    SinkPattern(
        name="redirect",
        language="python",
        node_type=NodeType.CALL,
        patterns=["redirect", "HttpResponseRedirect", "Redirect"],
        vuln_type="open_redirect",
        description="URL redirect",
    ),
]

PYTHON_SANITIZERS = [
    SanitizerPattern(
        name="html_escape",
        language="python",
        patterns=["html.escape", "markupsafe.escape", "cgi.escape",
                  "bleach.clean", "bleach.linkify"],
        effective_against=["xss"],
        description="HTML escaping functions",
    ),
    SanitizerPattern(
        name="sql_parameterized",
        language="python",
        patterns=["bindparam", "text", "literal_column", "paramstyle"],
        effective_against=["sqli"],
        description="Parameterized query helpers",
    ),
    SanitizerPattern(
        name="shell_escape",
        language="python",
        patterns=["shlex.quote", "shlex.split", "pipes.quote"],
        effective_against=["rce"],
        description="Shell argument escaping",
    ),
    SanitizerPattern(
        name="path_validation",
        language="python",
        patterns=["os.path.abspath", "os.path.realpath", "pathlib.resolve",
                  "secure_filename", "werkzeug.utils.secure_filename"],
        effective_against=["path_traversal"],
        description="Path validation/normalization",
    ),
    SanitizerPattern(
        name="url_validation",
        language="python",
        patterns=["urlparse", "urljoin", "is_safe_url", "urllib.parse.urlparse"],
        effective_against=["ssrf", "open_redirect"],
        description="URL validation functions",
    ),
    SanitizerPattern(
        name="input_validation",
        language="python",
        patterns=["re.match", "re.fullmatch", "cerberus.validate",
                  "marshmallow.load", "pydantic", "jsonschema.validate",
                  "wtforms.validators"],
        effective_against=["sqli", "xss", "rce", "ssti"],
        description="Input validation libraries",
    ),
]

# JavaScript/TypeScript patterns
JS_SOURCES = [
    SourcePattern(
        name="express_request",
        language="javascript",
        node_type=NodeType.CALL,
        patterns=["req.body", "req.query", "req.params", "req.headers",
                  "req.cookies", "req.get", "req.param"],
        description="Express.js request data",
    ),
    SourcePattern(
        name="nextjs_request",
        language="javascript",
        node_type=NodeType.CALL,
        patterns=["request.json", "request.text", "request.formData",
                  "searchParams", "params"],
        description="Next.js request data",
    ),
    SourcePattern(
        name="window_location",
        language="javascript",
        node_type=NodeType.CALL,
        patterns=["window.location", "location.href", "location.search",
                  "location.hash", "document.URL", "document.referrer"],
        description="Browser location data",
    ),
    SourcePattern(
        name="dom_input",
        language="javascript",
        node_type=NodeType.CALL,
        patterns=["document.getElementById", "document.querySelector",
                  "document.getElementsByClassName", "input.value",
                  "element.value", "element.getAttribute", "element.dataset"],
        description="DOM input values",
    ),
]

JS_SINKS = [
    SinkPattern(
        name="dom_manipulation",
        language="javascript",
        node_type=NodeType.CALL,
        patterns=["innerHTML", "outerHTML", "document.write", "document.writeln",
                  "insertAdjacentHTML", "jQuery.html"],
        vuln_type="xss",
        description="DOM manipulation (XSS sink)",
    ),
    SinkPattern(
        name="eval_execution",
        language="javascript",
        node_type=NodeType.CALL,
        patterns=["eval", "Function", "setTimeout", "setInterval",
                  "new Function", "setImmediate"],
        vuln_type="rce",
        description="Dynamic code evaluation",
    ),
    SinkPattern(
        name="sql_execution",
        language="javascript",
        node_type=NodeType.CALL,
        patterns=["query", "execute", "raw", "$queryRaw", "$executeRaw",
                  "sequelize.query", "knex.raw"],
        vuln_type="sqli",
        description="SQL query execution",
    ),
    SinkPattern(
        name="ssrf_fetch",
        language="javascript",
        node_type=NodeType.CALL,
        patterns=["fetch", "axios.get", "axios.post", "axios.put",
                  "http.get", "http.post", "https.get", "https.post",
                  "request", "got", "superagent"],
        vuln_type="ssrf",
        description="HTTP client requests",
    ),
    SinkPattern(
        name="command_execution",
        language="javascript",
        node_type=NodeType.CALL,
        patterns=["exec", "execSync", "spawn", "spawnSync", "execFile",
                  "child_process.exec", "child_process.spawn"],
        vuln_type="rce",
        description="OS command execution",
    ),
    SinkPattern(
        name="template_rendering",
        language="javascript",
        node_type=NodeType.CALL,
        patterns=["ejs.render", "pug.render", "handlebars.compile",
                  "nunjucks.render", "mustache.render"],
        vuln_type="ssti",
        description="Template rendering",
    ),
]


class DataFlowAnalyzer:
    """
    Analyzes data flow in a CPG to find source-to-sink paths.
    
    Usage:
        analyzer = DataFlowAnalyzer()
        paths = analyzer.analyze(cpg)
        for path in paths:
            print(f"{path.vuln_type}: {path.source_node.name} → {path.sink_node.name}")
    """
    
    def __init__(self, custom_sources=None, custom_sinks=None, custom_sanitizers=None):
        self.sources = {
            "python": PYTHON_SOURCES,
            "javascript": JS_SOURCES,
            "typescript": JS_SOURCES,  # Same as JS
        }
        self.sinks = {
            "python": PYTHON_SINKS,
            "javascript": JS_SINKS,
            "typescript": JS_SINKS,
        }
        self.sanitizers = {
            "python": PYTHON_SANITIZERS,
        }
        
        # Add custom patterns
        if custom_sources:
            for lang, patterns in custom_sources.items():
                self.sources.setdefault(lang, []).extend(patterns)
        if custom_sinks:
            for lang, patterns in custom_sinks.items():
                self.sinks.setdefault(lang, []).extend(patterns)
        if custom_sanitizers:
            for lang, patterns in custom_sanitizers.items():
                self.sanitizers.setdefault(lang, []).extend(patterns)
    
    def analyze(self, cpg: CPG) -> list[TaintPath]:
        """
        Analyze CPG for tainted data flow paths.
        
        Returns list of TaintPath objects representing source→sink paths.
        """
        # Step 1: Mark sources and sinks in the CPG
        self._identify_sources_and_sinks(cpg)
        
        # Step 2: Propagate taint through data flow
        self._propagate_taint(cpg)
        
        # Step 3: Check for sanitizers along paths
        self._check_sanitizers(cpg)
        
        # Step 4: Find all source→sink paths
        taint_paths = self._find_taint_paths(cpg)
        
        return taint_paths
    
    def _identify_sources_and_sinks(self, cpg: CPG) -> None:
        """Mark source and sink nodes in the CPG."""
        for node_id, node in cpg.nodes.items():
            language = node.properties.get("language", "all")
            
            # Check sources
            for source_pattern in self.sources.get(language, []):
                if self._matches_pattern(node, source_pattern):
                    node.is_source = True
                    node.taint_level = TaintLevel.TAINTED.value
                    break
            
            # Check sinks
            for sink_pattern in self.sinks.get(language, []):
                if self._matches_pattern(node, sink_pattern):
                    node.is_sink = True
                    break
            
            # Check sanitizers
            for sanitizer_pattern in self.sanitizers.get(language, []):
                if self._matches_sanitizer(node, sanitizer_pattern):
                    node.is_sanitizer = True
                    break
    
    def _matches_pattern(self, node: CPGNode, pattern) -> bool:
        """Check if a node matches a source/sink pattern."""
        if node.node_type != pattern.node_type:
            return False
        
        node_name = node.name.lower()
        code = node.code.lower()
        
        for p in pattern.patterns:
            p_lower = p.lower()
            if p_lower in node_name or p_lower in code:
                return True
        
        return False
    
    def _matches_sanitizer(self, node: CPGNode, pattern: SanitizerPattern) -> bool:
        """Check if a node matches a sanitizer pattern."""
        node_name = node.name.lower()
        code = node.code.lower()
        
        for p in pattern.patterns:
            p_lower = p.lower()
            if p_lower in node_name or p_lower in code:
                return True
        
        return False
    
    def _propagate_taint(self, cpg: CPG) -> None:
        """Propagate taint through data flow edges."""
        # BFS from all tainted nodes
        tainted_nodes = set()
        queue = []
        
        for node_id, node in cpg.nodes.items():
            if node.taint_level >= TaintLevel.TAINTED.value:
                tainted_nodes.add(node_id)
                queue.append(node_id)
        
        while queue:
            current_id = queue.pop(0)
            current_node = cpg.get_node(current_id)
            if not current_node:
                continue
            
            # Follow data flow edges (REACHES)
            for edge in cpg.get_edges_from(current_id, EdgeType.REACHES):
                target = cpg.get_node(edge.target_id)
                if target and target.id not in tainted_nodes:
                    target.taint_level = TaintLevel.PROPAGATED.value
                    tainted_nodes.add(target.id)
                    queue.append(target.id)
            
            # Follow call arguments (if tainted var passed to function)
            for edge in cpg.get_edges_from(current_id, EdgeType.CALLS):
                target = cpg.get_node(edge.target_id)
                if target and target.id not in tainted_nodes:
                    # Mark function as potentially receiving tainted data
                    target.taint_level = TaintLevel.PROPAGATED.value
                    tainted_nodes.add(target.id)
                    queue.append(target.id)
    
    def _check_sanitizers(self, cpg: CPG) -> None:
        """Check if tainted data passes through sanitizers before reaching sinks."""
        for node_id, node in cpg.nodes.items():
            if not node.is_sanitizer:
                continue
            
            # Find nodes that feed into this sanitizer
            for edge in cpg.get_edges_to(node_id, EdgeType.REACHES):
                source = cpg.get_node(edge.source_id)
                if source and source.taint_level >= TaintLevel.TAINTED.value:
                    # Data passes through sanitizer
                    source.taint_level = TaintLevel.SANITIZED.value
            
            # Find nodes that receive sanitized data
            for edge in cpg.get_edges_from(node_id, EdgeType.REACHES):
                target = cpg.get_node(edge.target_id)
                if target:
                    target.taint_level = TaintLevel.SANITIZED.value
    
    def _find_taint_paths(self, cpg: CPG) -> list[TaintPath]:
        """Find all paths from sources to sinks."""
        paths = []
        
        for sink_id, sink_node in cpg.nodes.items():
            if not sink_node.is_sink:
                continue
            
            # Get sink's vulnerability type
            language = sink_node.properties.get("language", "all")
            sink_patterns = self.sinks.get(language, [])
            
            vuln_type = "unknown"
            for sp in sink_patterns:
                if self._matches_pattern(sink_node, sp):
                    vuln_type = sp.vuln_type
                    break
            
            # BFS backwards from sink to find sources
            visited = set()
            queue = [(sink_id, [sink_id])]
            
            while queue:
                current_id, path = queue.pop(0)
                
                if current_id in visited:
                    continue
                visited.add(current_id)
                
                current_node = cpg.get_node(current_id)
                if not current_node:
                    continue
                
                # If we reached a source, record the path
                if current_node.is_source:
                    is_sanitized = any(
                        cpg.get_node(nid) and cpg.get_node(nid).is_sanitizer
                        for nid in path
                    )
                    
                    sanitizer_nodes = [
                        cpg.get_node(nid) for nid in path
                        if cpg.get_node(nid) and cpg.get_node(nid).is_sanitizer
                    ]
                    
                    taint_path = TaintPath(
                        source_node=current_node,
                        sink_node=sink_node,
                        path=list(reversed(path)),
                        vuln_type=vuln_type,
                        is_sanitized=is_sanitized,
                        sanitizer_nodes=[s for s in sanitizer_nodes if s],
                        confidence=0.3 if is_sanitized else 0.8,
                        description=(
                            f"Tainted data flows from '{current_node.name}' "
                            f"({current_node.file_path}:{current_node.line_start}) "
                            f"to '{sink_node.name}' "
                            f"({sink_node.file_path}:{sink_node.line_start})"
                        ),
                    )
                    paths.append(taint_path)
                    continue
                
                # Follow data flow edges backwards
                for edge in cpg.get_edges_to(current_id, EdgeType.REACHES):
                    if edge.source_id not in visited:
                        queue.append((edge.source_id, path + [edge.source_id]))
                
                # Follow child edges backwards (for structural containment)
                for edge in cpg.get_edges_to(current_id, EdgeType.CHILD):
                    if edge.source_id not in visited:
                        queue.append((edge.source_id, path + [edge.source_id]))
        
        # Sort by confidence (highest first)
        paths.sort(key=lambda p: p.confidence, reverse=True)
        
        # Deduplicate
        return self._deduplicate_paths(paths)
    
    def _deduplicate_paths(self, paths: list[TaintPath]) -> list[TaintPath]:
        """Remove duplicate taint paths."""
        seen = set()
        unique = []
        
        for path in paths:
            key = (
                path.source_node.id,
                path.sink_node.id,
                path.vuln_type,
            )
            if key not in seen:
                seen.add(key)
                unique.append(path)
        
        return unique
