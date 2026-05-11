"""
Sanitizer Analyzer
==================
LLM-guided analysis of whether sanitizers are actually effective.
Unlike pattern-matching alone, this uses AI to understand context.

For example:
  - html.escape() on user input before innerHTML = effective sanitizer
  - html.escape() on user input before SQL query = NOT effective sanitizer
  - re.match() with weak regex = NOT effective sanitizer
"""

from dataclasses import dataclass
from typing import Any, Optional

from .cpg_builder import CPG, CPGNode
from .data_flow import TaintPath


@dataclass
class SanitizerValidation:
    """Result of validating a sanitizer's effectiveness."""
    sanitizer_node: CPGNode
    taint_path: TaintPath
    is_effective: bool
    confidence: float  # 0.0 to 1.0
    reasoning: str
    recommendation: str = ""


class SanitizerAnalyzer:
    """
    Uses LLM to validate whether sanitizers are effective in context.
    
    This is the key differentiator from simple pattern matching:
    - Pattern matching says "this function is a sanitizer"
    - LLM analysis says "this sanitizer is effective FOR THIS SPECIFIC USE CASE"
    
    Usage:
        analyzer = SanitizerAnalyzer(llm_provider="openai/gpt-4")
        validations = analyzer.validate_sanitizers(cpg, taint_paths)
    """
    
    def __init__(self, llm_provider: Optional[str] = None, llm_api_key: Optional[str] = None):
        self.llm_provider = llm_provider
        self.llm_api_key = llm_api_key
        self._llm = None
    
    def _get_llm(self):
        """Initialize LLM client lazily."""
        if self._llm is not None:
            return self._llm
        
        try:
            import litellm
            self._llm = litellm
            return self._llm
        except ImportError:
            return None
    
    def validate_sanitizers(
        self,
        cpg: CPG,
        taint_paths: list[TaintPath],
    ) -> list[SanitizerValidation]:
        """
        Validate all sanitizers found in taint paths.
        
        For each path with a sanitizer, asks the LLM:
        "Given this source, this sanitizer, and this sink, is the sanitizer effective?"
        """
        validations = []
        
        for path in taint_paths:
            if not path.is_sanitized:
                continue
            
            for sanitizer_node in path.sanitizer_nodes:
                validation = self._validate_single_sanitizer(cpg, path, sanitizer_node)
                if validation:
                    validations.append(validation)
        
        return validations
    
    def _validate_single_sanitizer(
        self,
        cpg: CPG,
        path: TaintPath,
        sanitizer_node: CPGNode,
    ) -> Optional[SanitizerValidation]:
        """Validate a single sanitizer in context."""
        # Build context for LLM
        context = self._build_analysis_context(cpg, path, sanitizer_node)
        
        # Try LLM validation
        llm = self._get_llm()
        if llm and self.llm_api_key:
            return self._llm_validate(context, sanitizer_node, path)
        
        # Fallback: heuristic validation
        return self._heuristic_validate(context, sanitizer_node, path)
    
    def _build_analysis_context(
        self,
        cpg: CPG,
        path: TaintPath,
        sanitizer_node: CPGNode,
    ) -> dict[str, Any]:
        """Build context about the taint path for analysis."""
        # Get source code context
        source_code = self._get_surrounding_code(cpg, path.source_node)
        sink_code = self._get_surrounding_code(cpg, path.sink_node)
        sanitizer_code = sanitizer_node.code
        
        # Get the function containing the sanitizer
        containing_func = self._find_containing_function(cpg, sanitizer_node)
        
        return {
            "source": {
                "name": path.source_node.name,
                "file": path.source_node.file_path,
                "line": path.source_node.line_start,
                "code": source_code,
                "type": "user_input",
            },
            "sanitizer": {
                "name": sanitizer_node.name,
                "file": sanitizer_node.file_path,
                "line": sanitizer_node.line_start,
                "code": sanitizer_code,
                "containing_function": containing_func.name if containing_func else None,
            },
            "sink": {
                "name": path.sink_node.name,
                "file": path.sink_node.file_path,
                "line": path.sink_node.line_start,
                "code": sink_code,
                "vuln_type": path.vuln_type,
            },
            "path_length": len(path.path),
        }
    
    def _get_surrounding_code(self, cpg: CPG, node: CPGNode, context_lines: int = 5) -> str:
        """Get source code surrounding a node."""
        try:
            with open(node.file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            
            start = max(0, node.line_start - 1 - context_lines)
            end = min(len(lines), node.line_end + context_lines)
            
            code_lines = []
            for i in range(start, end):
                marker = ">>>" if node.line_start - 1 <= i < node.line_end else "   "
                code_lines.append(f"{marker} {i+1:4d} | {lines[i].rstrip()}")
            
            return "\n".join(code_lines)
        except (OSError, IndexError):
            return node.code
    
    def _find_containing_function(self, cpg: CPG, node: CPGNode) -> Optional[CPGNode]:
        """Find the function containing a given node."""
        # Walk up the AST to find the enclosing function
        for edge in cpg.get_edges_to(node.id):
            parent = cpg.get_node(edge.source_id)
            if parent and parent.node_type in (
                __import__('core.static_analyzer.cpg_builder', fromlist=['NodeType']).NodeType.FUNCTION,
                __import__('core.static_analyzer.cpg_builder', fromlist=['NodeType']).NodeType.METHOD,
            ):
                return parent
        return None
    
    def _llm_validate(
        self,
        context: dict[str, Any],
        sanitizer_node: CPGNode,
        path: TaintPath,
    ) -> Optional[SanitizerValidation]:
        """Use LLM to validate sanitizer effectiveness."""
        prompt = self._build_validation_prompt(context)
        
        try:
            llm = self._get_llm()
            response = llm.completion(
                model=self.llm_provider,
                api_key=self.llm_api_key,
                messages=[
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
                max_tokens=500,
            )
            
            result = response.choices[0].message.content
            return self._parse_llm_response(result, sanitizer_node, path)
            
        except Exception:
            # Fallback to heuristic
            return self._heuristic_validate(context, sanitizer_node, path)
    
    def _get_system_prompt(self) -> str:
        return """You are a security expert analyzing code for vulnerabilities.
Your task is to determine if a sanitizer function is EFFECTIVE at preventing 
a specific vulnerability type when used between a data source and a dangerous sink.

Consider:
1. Does the sanitizer actually clean/escape the dangerous characters for THIS specific vulnerability?
2. Is the sanitizer applied at the right point in the data flow?
3. Could the sanitizer be bypassed (e.g., double encoding, edge cases)?
4. Is the regex/pattern strong enough to catch all malicious input?

Respond in JSON format:
{
    "is_effective": true/false,
    "confidence": 0.0-1.0,
    "reasoning": "brief explanation",
    "recommendation": "what to do instead if not effective"
}"""
    
    def _build_validation_prompt(self, context: dict[str, Any]) -> str:
        return f"""Analyze if this sanitizer is effective:

SOURCE (untrusted input):
- Function: {context['source']['name']}
- File: {context['source']['file']}:{context['source']['line']}
- Code:
```
{context['source']['code']}
```

SANITIZER:
- Function: {context['sanitizer']['name']}
- File: {context['sanitizer']['file']}:{context['sanitizer']['line']}
- Code:
```
{context['sanitizer']['code']}
```

SINK (dangerous operation):
- Function: {context['sink']['name']}
- File: {context['sink']['file']}:{context['sink']['line']}
- Vulnerability type: {context['sink']['vuln_type']}
- Code:
```
{context['sink']['code']}
```

Is the sanitizer effective at preventing {context['sink']['vuln_type']} in this specific context?"""
    
    def _parse_llm_response(
        self,
        response: str,
        sanitizer_node: CPGNode,
        path: TaintPath,
    ) -> Optional[SanitizerValidation]:
        """Parse LLM response into SanitizerValidation."""
        import json
        
        try:
            # Try to extract JSON from response
            json_start = response.find("{")
            json_end = response.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                data = json.loads(response[json_start:json_end])
                
                return SanitizerValidation(
                    sanitizer_node=sanitizer_node,
                    taint_path=path,
                    is_effective=data.get("is_effective", False),
                    confidence=data.get("confidence", 0.5),
                    reasoning=data.get("reasoning", ""),
                    recommendation=data.get("recommendation", ""),
                )
        except (json.JSONDecodeError, KeyError):
            pass
        
        return None
    
    def _heuristic_validate(
        self,
        context: dict[str, Any],
        sanitizer_node: CPGNode,
        path: TaintPath,
    ) -> SanitizerValidation:
        """
        Heuristic validation when LLM is not available.
        Uses simple rules to determine sanitizer effectiveness.
        """
        sanitizer_name = sanitizer_node.name.lower()
        vuln_type = path.vuln_type
        
        # Rules: which sanitizers work for which vulnerability types
        effective_map = {
            "xss": ["escape", "bleach", "sanitize", "encode", "markupsafe"],
            "sqli": ["parameterized", "bindparam", "prepared", "placeholder", "escape_string"],
            "rce": ["shlex", "quote", "escape", "whitelist"],
            "ssti": ["sandbox", "escape", "safe"],
            "path_traversal": ["abspath", "realpath", "resolve", "secure_filename", "basename"],
            "ssrf": ["urlparse", "whitelist", "allowlist", "is_safe"],
            "open_redirect": ["is_safe_url", "urlparse", "whitelist"],
        }
        
        effective_keywords = effective_map.get(vuln_type, [])
        is_effective = any(kw in sanitizer_name for kw in effective_keywords)
        
        return SanitizerValidation(
            sanitizer_node=sanitizer_node,
            taint_path=path,
            is_effective=is_effective,
            confidence=0.6 if is_effective else 0.4,
            reasoning=f"Heuristic: '{sanitizer_node.name}' {'matches' if is_effective else 'does not match'} known effective patterns for {vuln_type}",
            recommendation="" if is_effective else f"Use a dedicated {vuln_type} sanitizer instead",
        )
