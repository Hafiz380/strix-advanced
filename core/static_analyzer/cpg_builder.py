"""
Code Property Graph (CPG) Builder
=================================
Builds a combined graph representation of source code:
  - AST (Abstract Syntax Tree)
  - CFG (Control Flow Graph)  
  - PDG (Program Dependence Graph - data flow)
  - Combined CPG = AST + CFG + PDG

Uses tree-sitter for fast, multi-language AST parsing.
"""

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class NodeType(Enum):
    """CPG node types."""
    # AST nodes
    FUNCTION = "function"
    METHOD = "method"
    CLASS = "class"
    VARIABLE = "variable"
    PARAMETER = "parameter"
    LITERAL = "literal"
    CALL = "call"
    RETURN = "return"
    ASSIGNMENT = "assignment"
    IF = "if"
    WHILE = "while"
    FOR = "for"
    TRY = "try"
    IMPORT = "import"
    DECORATOR = "decorator"
    UNKNOWN = "unknown"


class EdgeType(Enum):
    """CPG edge types."""
    # AST edges
    CHILD = "child"              # AST parent-child
    CONTAINS = "contains"        # Structural containment
    
    # CFG edges
    FLOWS_TO = "flows_to"        # Control flow
    CONDITIONAL_TRUE = "cond_true"
    CONDITIONAL_FALSE = "cond_false"
    
    # Data flow edges
    DEFINES = "defines"          # Variable definition
    USES = "uses"                # Variable usage
    REACHES = "reaches"          # Definition reaches usage
    TAINTED_BY = "tainted_by"    # Taint propagation
    SANITIZED_BY = "sanitized_by" # Sanitization
    
    # Call graph edges
    CALLS = "calls"              # Function call
    CALLED_BY = "called_by"      # Reverse call
    
    # Import/dependency edges
    IMPORTS = "imports"
    DEPENDS_ON = "depends_on"


@dataclass
class CPGNode:
    """A node in the Code Property Graph."""
    id: str
    node_type: NodeType
    name: str
    file_path: str
    line_start: int
    line_end: int
    col_start: int = 0
    col_end: int = 0
    code: str = ""
    properties: dict[str, Any] = field(default_factory=dict)
    
    # Analysis results (filled during analysis)
    is_source: bool = False
    is_sink: bool = False
    is_sanitizer: bool = False
    taint_level: int = 0  # 0=clean, 1=tainted, 2=propagated
    
    def __hash__(self):
        return hash(self.id)
    
    def __eq__(self, other):
        if isinstance(other, CPGNode):
            return self.id == other.id
        return False


@dataclass
class CPGEdge:
    """An edge in the Code Property Graph."""
    source_id: str
    target_id: str
    edge_type: EdgeType
    properties: dict[str, Any] = field(default_factory=dict)
    
    def __hash__(self):
        return hash((self.source_id, self.target_id, self.edge_type))


@dataclass
class CPG:
    """The complete Code Property Graph for a codebase."""
    nodes: dict[str, CPGNode] = field(default_factory=dict)
    edges: list[CPGEdge] = field(default_factory=list)
    file_index: dict[str, list[str]] = field(default_factory=dict)  # file → node_ids
    function_index: dict[str, str] = field(default_factory=dict)    # func_name → node_id
    class_index: dict[str, str] = field(default_factory=dict)       # class_name → node_id
    call_graph: dict[str, list[str]] = field(default_factory=dict)  # caller → [callees]
    
    def add_node(self, node: CPGNode) -> None:
        self.nodes[node.id] = node
        if node.file_path not in self.file_index:
            self.file_index[node.file_path] = []
        self.file_index[node.file_path].append(node.id)
        
        if node.node_type in (NodeType.FUNCTION, NodeType.METHOD):
            self.function_index[node.name] = node.id
        elif node.node_type == NodeType.CLASS:
            self.class_index[node.name] = node.id
    
    def add_edge(self, edge: CPGEdge) -> None:
        self.edges.append(edge)
        if edge.edge_type == EdgeType.CALLS:
            if edge.source_id not in self.call_graph:
                self.call_graph[edge.source_id] = []
            self.call_graph[edge.source_id].append(edge.target_id)
    
    def get_node(self, node_id: str) -> Optional[CPGNode]:
        return self.nodes.get(node_id)
    
    def get_edges_from(self, node_id: str, edge_type: Optional[EdgeType] = None) -> list[CPGEdge]:
        result = []
        for edge in self.edges:
            if edge.source_id == node_id:
                if edge_type is None or edge.edge_type == edge_type:
                    result.append(edge)
        return result
    
    def get_edges_to(self, node_id: str, edge_type: Optional[EdgeType] = None) -> list[CPGEdge]:
        result = []
        for edge in self.edges:
            if edge.target_id == node_id:
                if edge_type is None or edge.edge_type == edge_type:
                    result.append(edge)
        return result
    
    def get_callees(self, function_id: str) -> list[CPGNode]:
        """Get all functions called by this function."""
        callees = []
        for edge in self.edges:
            if edge.source_id == function_id and edge.edge_type == EdgeType.CALLS:
                target = self.nodes.get(edge.target_id)
                if target:
                    callees.append(target)
        return callees
    
    def get_callers(self, function_id: str) -> list[CPGNode]:
        """Get all functions that call this function."""
        callers = []
        for edge in self.edges:
            if edge.target_id == function_id and edge.edge_type == EdgeType.CALLS:
                source = self.nodes.get(edge.source_id)
                if source:
                    callers.append(source)
        return callers
    
    def get_data_dependencies(self, node_id: str) -> list[CPGNode]:
        """Get all nodes that this node's value flows to."""
        deps = []
        for edge in self.edges:
            if edge.source_id == node_id and edge.edge_type == EdgeType.REACHES:
                target = self.nodes.get(edge.target_id)
                if target:
                    deps.append(target)
        return deps
    
    def get_reverse_data_dependencies(self, node_id: str) -> list[CPGNode]:
        """Get all nodes whose values flow into this node."""
        deps = []
        for edge in self.edges:
            if edge.target_id == node_id and edge.edge_type == EdgeType.REACHES:
                source = self.nodes.get(edge.source_id)
                if source:
                    deps.append(source)
        return deps
    
    def to_dict(self) -> dict[str, Any]:
        """Serialize CPG to dictionary."""
        return {
            "nodes": [
                {
                    "id": n.id,
                    "type": n.node_type.value,
                    "name": n.name,
                    "file": n.file_path,
                    "line": n.line_start,
                    "code": n.code[:200],
                    "is_source": n.is_source,
                    "is_sink": n.is_sink,
                    "is_sanitizer": n.is_sanitizer,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "from": e.source_id,
                    "to": e.target_id,
                    "type": e.edge_type.value,
                }
                for e in self.edges
            ],
            "stats": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "files": len(self.file_index),
                "functions": len(self.function_index),
                "classes": len(self.class_index),
            }
        }


class CPGBuilder:
    """
    Builds a Code Property Graph from source code.
    
    Usage:
        builder = CPGBuilder()
        cpg = builder.build("/path/to/project")
        # or
        cpg = builder.build_from_files(["file1.py", "file2.js"])
    """
    
    SUPPORTED_EXTENSIONS = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".go": "go",
        ".java": "java",
        ".php": "php",
        ".rb": "ruby",
    }
    
    def __init__(self):
        self._parsers = {}
        self._init_parsers()
    
    def _init_parsers(self):
        """Initialize tree-sitter parsers for supported languages."""
        try:
            import tree_sitter
            import tree_sitter_python
            import tree_sitter_javascript
            import tree_sitter_typescript
            import tree_sitter_go
            import tree_sitter_java
            
            self._available = True
            
            # Map language names to tree-sitter language modules
            self._lang_modules = {
                "python": tree_sitter_python,
                "javascript": tree_sitter_javascript,
                "typescript": tree_sitter_typescript,
                "go": tree_sitter_go,
                "java": tree_sitter_java,
            }
            
        except ImportError as e:
            self._available = False
            self._init_error = str(e)
    
    def is_available(self) -> bool:
        """Check if tree-sitter is available."""
        return getattr(self, '_available', False)
    
    def get_init_error(self) -> str:
        """Get initialization error message."""
        return getattr(self, '_init_error', 'Unknown error')
    
    def _get_parser(self, language: str):
        """Get or create a tree-sitter parser for a language."""
        if language in self._parsers:
            return self._parsers[language]
        
        if not self._available:
            raise RuntimeError(f"tree-sitter not available: {self._init_error}")
        
        lang_module = self._lang_modules.get(language)
        if not lang_module:
            raise ValueError(f"Unsupported language: {language}")
        
        import tree_sitter
        parser = tree_sitter.Parser(tree_sitter.Language(lang_module.language()))
        self._parsers[language] = parser
        return parser
    
    def _detect_language(self, file_path: str) -> Optional[str]:
        """Detect language from file extension."""
        ext = Path(file_path).suffix.lower()
        return self.SUPPORTED_EXTENSIONS.get(ext)
    
    def build(self, project_path: str, exclude_patterns: Optional[list[str]] = None) -> CPG:
        """
        Build CPG for an entire project directory.
        
        Args:
            project_path: Path to project root
            exclude_patterns: Glob patterns to exclude (e.g., ["node_modules", "*.test.*"])
        
        Returns:
            CPG object with all nodes and edges
        """
        if not self.is_available():
            raise RuntimeError(f"Static analysis not available: {self.get_init_error()}")
        
        project_path = Path(project_path)
        if not project_path.exists():
            raise FileNotFoundError(f"Project path not found: {project_path}")
        
        # Default exclusions
        if exclude_patterns is None:
            exclude_patterns = [
                "node_modules", ".git", "__pycache__", ".venv", "venv",
                "dist", "build", ".next", "target", "vendor",
                "*.min.js", "*.bundle.js", "*.map",
                "test_*", "*_test.py", "*.test.*", "*.spec.*",
            ]
        
        # Collect source files
        source_files = []
        for root, dirs, files in os.walk(project_path):
            # Filter directories
            rel_root = Path(root).relative_to(project_path)
            dirs[:] = [d for d in dirs if not self._should_exclude(str(rel_root / d), exclude_patterns)]
            
            for file in files:
                file_path = Path(root) / file
                rel_path = str(file_path.relative_to(project_path))
                
                if self._should_exclude(rel_path, exclude_patterns):
                    continue
                
                language = self._detect_language(file)
                if language:
                    source_files.append((str(file_path), language))
        
        if not source_files:
            raise ValueError(f"No supported source files found in {project_path}")
        
        return self.build_from_files(source_files)
    
    def build_from_files(self, files: list[tuple[str, str]]) -> CPG:
        """
        Build CPG from a list of (file_path, language) tuples.
        
        Args:
            files: List of (file_path, language) tuples
        
        Returns:
            CPG object
        """
        if not self.is_available():
            raise RuntimeError(f"Static analysis not available: {self.get_init_error()}")
        
        cpg = CPG()
        node_counter = 0
        
        for file_path, language in files:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    source_code = f.read()
            except (OSError, UnicodeDecodeError):
                continue
            
            parser = self._get_parser(language)
            tree = parser.parse(source_code.encode("utf-8"))
            
            # Extract nodes from AST
            file_nodes, file_edges = self._extract_from_ast(
                tree.root_node, source_code, file_path, language, node_counter
            )
            
            for node in file_nodes:
                cpg.add_node(node)
            for edge in file_edges:
                cpg.add_edge(edge)
            
            node_counter += len(file_nodes)
        
        # Build data flow edges (definition-use chains)
        self._build_data_flow_edges(cpg)
        
        return cpg
    
    def _should_exclude(self, rel_path: str, patterns: list[str]) -> bool:
        """Check if path matches any exclusion pattern."""
        from fnmatch import fnmatch
        path_parts = Path(rel_path).parts
        
        for pattern in patterns:
            if fnmatch(rel_path, pattern):
                return True
            if fnmatch(Path(rel_path).name, pattern):
                return True
            for part in path_parts:
                if fnmatch(part, pattern):
                    return True
        return False
    
    def _extract_from_ast(
        self,
        node,
        source_code: str,
        file_path: str,
        language: str,
        id_offset: int,
    ) -> tuple[list[CPGNode], list[CPGEdge]]:
        """Extract CPG nodes and edges from a tree-sitter AST node."""
        nodes = []
        edges = []
        source_lines = source_code.split("\n")
        
        # Walk the AST
        stack = [(node, None)]  # (tree_node, parent_cpg_id)
        
        while stack:
            ts_node, parent_id = stack.pop()
            
            # Map tree-sitter node types to CPG node types
            cpg_type = self._map_node_type(ts_node, language)
            
            if cpg_type != NodeType.UNKNOWN:
                node_id = f"n{id_offset + len(nodes)}"
                
                # Extract code snippet
                start_line = ts_node.start_point[0]
                end_line = ts_node.end_point[0]
                code = "\n".join(source_lines[start_line:end_line + 1]) if start_line < len(source_lines) else ""
                
                # Extract name
                name = self._extract_name(ts_node, language, source_code)
                
                cpg_node = CPGNode(
                    id=node_id,
                    node_type=cpg_type,
                    name=name,
                    file_path=file_path,
                    line_start=start_line + 1,  # 1-indexed
                    line_end=end_line + 1,
                    col_start=ts_node.start_point[1],
                    col_end=ts_node.end_point[1],
                    code=code,
                    properties={"ts_type": ts_node.type, "language": language},
                )
                
                nodes.append(cpg_node)
                
                # Add parent-child edge
                if parent_id:
                    edges.append(CPGEdge(
                        source_id=parent_id,
                        target_id=node_id,
                        edge_type=EdgeType.CHILD,
                    ))
                
                parent_id = node_id
            
            # Push children (in reverse for correct order)
            for child in reversed(ts_node.children):
                stack.append((child, parent_id))
        
        return nodes, edges
    
    def _map_node_type(self, ts_node, language: str) -> NodeType:
        """Map tree-sitter node type to CPG node type."""
        type_map = {
            # Python
            "function_definition": NodeType.FUNCTION,
            "async_function_definition": NodeType.FUNCTION,
            "class_definition": NodeType.CLASS,
            "assignment": NodeType.ASSIGNMENT,
            "augmented_assignment": NodeType.ASSIGNMENT,
            "return_statement": NodeType.RETURN,
            "if_statement": NodeType.IF,
            "while_statement": NodeType.WHILE,
            "for_statement": NodeType.FOR,
            "try_statement": NodeType.TRY,
            "import_statement": NodeType.IMPORT,
            "import_from_statement": NodeType.IMPORT,
            "decorator": NodeType.DECORATOR,
            "call": NodeType.CALL,
            
            # JavaScript/TypeScript
            "function_declaration": NodeType.FUNCTION,
            "arrow_function": NodeType.FUNCTION,
            "method_definition": NodeType.METHOD,
            "class_declaration": NodeType.CLASS,
            "lexical_declaration": NodeType.ASSIGNMENT,
            "variable_declaration": NodeType.ASSIGNMENT,
            "return_statement": NodeType.RETURN,
            "if_statement": NodeType.IF,
            "while_statement": NodeType.WHILE,
            "for_statement": NodeType.FOR,
            "try_statement": NodeType.TRY,
            "import_statement": NodeType.IMPORT,
            "call_expression": NodeType.CALL,
            
            # Go
            "function_declaration": NodeType.FUNCTION,
            "method_declaration": NodeType.METHOD,
            "type_declaration": NodeType.CLASS,
            "short_var_declaration": NodeType.ASSIGNMENT,
            "var_declaration": NodeType.ASSIGNMENT,
            "return_statement": NodeType.RETURN,
            "if_statement": NodeType.IF,
            "for_statement": NodeType.FOR,
            "call_expression": NodeType.CALL,
            
            # Java
            "method_declaration": NodeType.METHOD,
            "constructor_declaration": NodeType.METHOD,
            "class_declaration": NodeType.CLASS,
            "local_variable_declaration": NodeType.ASSIGNMENT,
            "return_statement": NodeType.RETURN,
            "if_statement": NodeType.IF,
            "while_statement": NodeType.WHILE,
            "for_statement": NodeType.FOR,
            "try_statement": NodeType.TRY,
            "import_declaration": NodeType.IMPORT,
            "method_invocation": NodeType.CALL,
        }
        
        return type_map.get(ts_node.type, NodeType.UNKNOWN)
    
    def _extract_name(self, ts_node, language: str, source_code: str) -> str:
        """Extract the name of a node (function name, variable name, etc.)."""
        # Look for name/identifier child
        for child in ts_node.children:
            if child.type in ("identifier", "name", "type_identifier"):
                return source_code[child.start_byte:child.end_byte].decode("utf-8", errors="ignore")
            
            # JavaScript: property_identifier for method names
            if child.type == "property_identifier":
                return source_code[child.start_byte:child.end_byte].decode("utf-8", errors="ignore")
            
            # Python: dotted_name for imports
            if child.type == "dotted_name":
                return source_code[child.start_byte:child.end_byte].decode("utf-8", errors="ignore")
        
        return ts_node.type
    
    def _build_data_flow_edges(self, cpg: CPG) -> None:
        """Build definition-use chains (data flow edges) in the CPG."""
        # Track variable definitions per function scope
        # This is a simplified version - a full implementation would use
        # reaching definitions analysis
        
        for func_id, func_name in cpg.function_index.items():
            func_node = cpg.get_node(func_id)
            if not func_node:
                continue
            
            # Get all nodes in this function
            func_children = self._get_function_nodes(cpg, func_id)
            
            # Track definitions and uses
            definitions = {}  # var_name → [defining_node_ids]
            
            for node in func_children:
                if node.node_type == NodeType.ASSIGNMENT:
                    # Extract defined variable name
                    var_name = self._extract_assignment_target(node, cpg)
                    if var_name:
                        definitions.setdefault(var_name, []).append(node.id)
                
                elif node.node_type == NodeType.CALL:
                    # Check if arguments use defined variables
                    self._link_call_arguments(node, definitions, cpg)
    
    def _get_function_nodes(self, cpg: CPG, func_id: str) -> list[CPGNode]:
        """Get all descendant nodes of a function."""
        nodes = []
        visited = set()
        queue = [func_id]
        
        while queue:
            current_id = queue.pop(0)
            if current_id in visited:
                continue
            visited.add(current_id)
            
            node = cpg.get_node(current_id)
            if node and node.id != func_id:
                nodes.append(node)
            
            for edge in cpg.get_edges_from(current_id, EdgeType.CHILD):
                queue.append(edge.target_id)
        
        return nodes
    
    def _extract_assignment_target(self, node: CPGNode, cpg: CPG) -> Optional[str]:
        """Extract the variable name being assigned to."""
        for edge in cpg.get_edges_from(node.id, EdgeType.CHILD):
            child = cpg.get_node(edge.target_id)
            if child and child.node_type == NodeType.VARIABLE:
                return child.name
        return node.name if node.node_type == NodeType.VARIABLE else None
    
    def _link_call_arguments(
        self,
        call_node: CPGNode,
        definitions: dict[str, list[str]],
        cpg: CPG,
    ) -> None:
        """Link call arguments to their definitions."""
        # This is simplified - full implementation would parse call arguments
        # and link them to reaching definitions
        pass
