"""
API Discovery Engine
=====================
Automatically discovers API endpoints, schemas, and parameters.

Capabilities:
- Swagger/OpenAPI spec discovery
- GraphQL introspection
- REST endpoint enumeration
- Parameter fuzzing
- Authentication detection
- Rate limit detection
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urljoin


@dataclass
class APIEndpoint:
    """Discovered API endpoint."""
    url: str
    method: str = "GET"
    parameters: list[dict] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    auth_required: bool = False
    rate_limit: Optional[int] = None
    response_schema: dict = field(default_factory=dict)
    content_type: str = ""
    description: str = ""
    source: str = ""  # "swagger", "graphql", "brute_force", "crawler"


@dataclass
class APISchema:
    """API schema from OpenAPI/Swagger."""
    title: str = ""
    version: str = ""
    base_url: str = ""
    endpoints: list[APIEndpoint] = field(default_factory=list)
    auth_schemes: list[dict] = field(default_factory=list)
    models: dict[str, dict] = field(default_factory=dict)


class APIDiscovery:
    """
    Discovers and documents API endpoints.
    
    Usage:
        discovery = APIDiscovery(http_client=client)
        
        # Full discovery
        schema = await discovery.discover("https://api.target.com")
        
        # Just GraphQL
        gql = await discovery.introspect_graphql("https://target.com/graphql")
        
        # Fuzz discovered endpoints
        results = await discovery.fuzz_endpoints(schema.endpoints)
    """
    
    # Common API paths
    COMMON_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/rest", "/rest/v1", "/rest/v2",
        "/graphql", "/graphiql", "/playground",
        "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
        "/api-docs", "/docs", "/redoc",
        "/health", "/status", "/metrics", "/info",
        "/version", "/ping",
    ]
    
    # Common endpoint patterns
    RESOURCE_PATTERNS = [
        "/users", "/user", "/accounts", "/account",
        "/auth", "/login", "/register", "/signup",
        "/tokens", "/refresh", "/logout",
        "/admin", "/dashboard", "/settings",
        "/products", "/items", "/orders", "/cart",
        "/payments", "/billing", "/invoices",
        "/files", "/upload", "/download", "/images",
        "/search", "/query", "/filter",
        "/notifications", "/messages", "/comments",
        "/reports", "/analytics", "/stats",
        "/webhooks", "/callbacks", "/events",
        "/jobs", "/tasks", "/queues",
        "/config", "/preferences", "/profile",
    ]
    
    def __init__(self, http_client=None):
        self.http = http_client
    
    async def discover(self, base_url: str, depth: str = "standard") -> APISchema:
        """
        Full API discovery.
        
        Args:
            base_url: Base URL of the API
            depth: "quick", "standard", or "deep"
        """
        schema = APISchema(base_url=base_url)
        endpoints = []
        
        # 1. Try OpenAPI/Swagger spec
        spec_endpoints = await self._discover_from_spec(base_url)
        endpoints.extend(spec_endpoints)
        if spec_endpoints:
            schema.title = "Discovered API"
        
        # 2. Try GraphQL introspection
        gql_endpoints = await self._discover_graphql(base_url)
        endpoints.extend(gql_endpoints)
        
        # 3. Brute-force common paths
        brute_endpoints = await self._brute_force_paths(base_url)
        endpoints.extend(brute_endpoints)
        
        # 4. Crawl for API endpoints
        if depth in ("standard", "deep"):
            crawled = await self._crawl_api(base_url)
            endpoints.extend(crawled)
        
        # 5. JavaScript analysis
        js_endpoints = await self._extract_from_js(base_url)
        endpoints.extend(js_endpoints)
        
        # Deduplicate
        seen = set()
        unique = []
        for ep in endpoints:
            key = f"{ep.method}:{ep.url}"
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        
        schema.endpoints = unique
        return schema
    
    async def _discover_from_spec(self, base_url: str) -> list[APIEndpoint]:
        """Discover endpoints from OpenAPI/Swagger spec."""
        if not self.http:
            return []
        
        spec_paths = [
            "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
            "/api-docs", "/docs/swagger.json", "/v1/swagger.json",
            "/api/swagger.json", "/api/openapi.json",
        ]
        
        for path in spec_paths:
            try:
                url = urljoin(base_url, path)
                response = await self.http.get(url, timeout=10)
                
                if response.status_code == 200:
                    try:
                        spec = response.json()
                        return self._parse_openapi_spec(spec, base_url)
                    except json.JSONDecodeError:
                        # Try YAML
                        try:
                            import yaml
                            spec = yaml.safe_load(response.text)
                            return self._parse_openapi_spec(spec, base_url)
                        except Exception:
                            pass
            except Exception:
                continue
        
        return []
    
    def _parse_openapi_spec(self, spec: dict, base_url: str) -> list[APIEndpoint]:
        """Parse OpenAPI/Swagger spec into endpoints."""
        endpoints = []
        
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                    continue
                
                params = []
                for param in details.get("parameters", []):
                    params.append({
                        "name": param.get("name", ""),
                        "in": param.get("in", ""),
                        "required": param.get("required", False),
                        "type": param.get("schema", {}).get("type", ""),
                    })
                
                # Request body
                request_body = details.get("requestBody", {})
                if request_body:
                    for content_type, content in request_body.get("content", {}).items():
                        schema = content.get("schema", {})
                        if "properties" in schema:
                            for prop_name, prop_schema in schema["properties"].items():
                                params.append({
                                    "name": prop_name,
                                    "in": "body",
                                    "required": prop_name in schema.get("required", []),
                                    "type": prop_schema.get("type", ""),
                                })
                
                endpoint = APIEndpoint(
                    url=urljoin(base_url, path),
                    method=method.upper(),
                    parameters=params,
                    description=details.get("summary", details.get("description", "")),
                    source="swagger",
                    auth_required=bool(details.get("security")),
                )
                endpoints.append(endpoint)
        
        return endpoints
    
    async def _discover_graphql(self, base_url: str) -> list[APIEndpoint]:
        """Discover GraphQL endpoints via introspection."""
        if not self.http:
            return []
        
        gql_paths = ["/graphql", "/gql", "/query", "/api/graphql"]
        
        for path in gql_paths:
            try:
                url = urljoin(base_url, path)
                
                # Introspection query
                introspection = {
                    "query": """
                    {
                        __schema {
                            queryType { name }
                            mutationType { name }
                            types {
                                name
                                fields {
                                    name
                                    args { name type { name kind ofType { name } } }
                                }
                            }
                        }
                    }
                    """
                }
                
                response = await self.http.post(url, json=introspection, timeout=15)
                
                if response.status_code == 200:
                    data = response.json()
                    if "data" in data and "__schema" in data["data"]:
                        return self._parse_graphql_schema(data["data"]["__schema"], url)
            except Exception:
                continue
        
        return []
    
    def _parse_graphql_schema(self, schema: dict, endpoint_url: str) -> list[APIEndpoint]:
        """Parse GraphQL schema into endpoints."""
        endpoints = []
        
        # Query types
        query_type = schema.get("queryType", {}).get("name", "Query")
        mutation_type = schema.get("mutationType", {}).get("name", "Mutation")
        
        for type_info in schema.get("types", []):
            type_name = type_info.get("name", "")
            
            if type_name in (query_type, mutation_type, "__Schema", "__Type", "__Field", "__InputValue", "__EnumValue", "__Directive"):
                continue
            
            # Skip introspection types
            if type_name.startswith("__"):
                continue
            
            for field in type_info.get("fields", []):
                field_name = field.get("name", "")
                args = []
                
                for arg in field.get("args", []):
                    args.append({
                        "name": arg.get("name", ""),
                        "type": arg.get("type", {}).get("name", "") or arg.get("type", {}).get("ofType", {}).get("name", ""),
                    })
                
                method = "POST" if type_name == mutation_type else "POST"  # GraphQL always POST
                
                endpoint = APIEndpoint(
                    url=endpoint_url,
                    method="POST",
                    parameters=[{"name": a["name"], "in": "graphql", "type": a["type"]} for a in args],
                    description=f"GraphQL {'mutation' if type_name == mutation_type else 'query'}: {field_name}",
                    source="graphql",
                )
                endpoints.append(endpoint)
        
        return endpoints
    
    async def _brute_force_paths(self, base_url: str) -> list[APIEndpoint]:
        """Brute-force common API paths."""
        if not self.http:
            return []
        
        endpoints = []
        
        for path in self.COMMON_PATHS + self.RESOURCE_PATTERNS:
            try:
                url = urljoin(base_url, path)
                response = await self.http.get(url, timeout=5, follow_redirects=False)
                
                if response.status_code in (200, 201, 204, 401, 403):
                    # Check if it looks like an API
                    content_type = response.headers.get("content-type", "")
                    is_api = (
                        "json" in content_type or
                        "xml" in content_type or
                        response.status_code in (401, 403)
                    )
                    
                    if is_api:
                        endpoints.append(APIEndpoint(
                            url=url,
                            method="GET",
                            auth_required=response.status_code in (401, 403),
                            source="brute_force",
                            content_type=content_type,
                        ))
                        
                        # Also try POST
                        try:
                            post_response = await self.http.post(url, json={}, timeout=5)
                            if post_response.status_code not in (404, 405):
                                endpoints.append(APIEndpoint(
                                    url=url,
                                    method="POST",
                                    auth_required=post_response.status_code in (401, 403),
                                    source="brute_force",
                                ))
                        except Exception:
                            pass
            except Exception:
                continue
        
        return endpoints
    
    async def _crawl_api(self, base_url: str) -> list[APIEndpoint]:
        """Crawl the API for linked endpoints."""
        if not self.http:
            return []
        
        endpoints = []
        visited = set()
        queue = [base_url]
        
        while queue and len(visited) < 50:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            
            try:
                response = await self.http.get(url, timeout=10)
                
                if response.status_code == 200:
                    # Look for links in JSON responses
                    try:
                        data = response.json()
                        self._extract_links_from_json(data, url, endpoints, queue, visited)
                    except json.JSONDecodeError:
                        pass
                    
                    # Look for links in HTML
                    links = re.findall(r'href=["\']([^"\']+)["\']', response.text)
                    for link in links:
                        full_url = urljoin(url, link)
                        if full_url.startswith(base_url) and full_url not in visited:
                            queue.append(full_url)
            except Exception:
                continue
        
        return endpoints
    
    def _extract_links_from_json(self, data: Any, base: str, endpoints: list, queue: list, visited: set):
        """Extract API links from JSON response."""
        if isinstance(data, dict):
            for key, value in data.items():
                if key in ("href", "url", "link", "self", "next", "prev", "first", "last"):
                    if isinstance(value, str) and value.startswith(("http://", "https://", "/")):
                        full_url = urljoin(base, value) if value.startswith("/") else value
                        if full_url not in visited:
                            queue.append(full_url)
                elif isinstance(value, (dict, list)):
                    self._extract_links_from_json(value, base, endpoints, queue, visited)
        elif isinstance(data, list):
            for item in data:
                self._extract_links_from_json(item, base, endpoints, queue, visited)
    
    async def _extract_from_js(self, base_url: str) -> list[APIEndpoint]:
        """Extract API endpoints from JavaScript files."""
        if not self.http:
            return []
        
        endpoints = []
        
        try:
            response = await self.http.get(base_url, timeout=10)
            
            # Find JS files
            js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', response.text)
            
            for js_url in js_urls[:10]:  # Limit to 10 JS files
                full_url = urljoin(base_url, js_url)
                
                try:
                    js_response = await self.http.get(full_url, timeout=10)
                    
                    # Extract API paths from JS
                    # Common patterns: fetch("/api/..."), axios.get("/api/..."), "/api/..."
                    api_patterns = re.findall(
                        r'["\']/(api|rest|graphql|v[0-9]+)/[^"\']*["\']',
                        js_response.text
                    )
                    
                    for match in api_patterns:
                        path = match.strip("'\"")
                        endpoints.append(APIEndpoint(
                            url=urljoin(base_url, path),
                            method="GET",
                            source="javascript",
                        ))
                    
                    # Also look for full URLs
                    full_urls = re.findall(
                        r'https?://[^\s"\'`]+(?:api|rest|graphql|v[0-9]+)[^\s"\'`]*',
                        js_response.text
                    )
                    
                    for url in full_urls[:20]:
                        endpoints.append(APIEndpoint(
                            url=url,
                            method="GET",
                            source="javascript",
                        ))
                        
                except Exception:
                    continue
        except Exception:
            pass
        
        return endpoints
    
    async def fuzz_endpoints(self, endpoints: list[APIEndpoint]) -> list[dict]:
        """Fuzz discovered endpoints for vulnerabilities."""
        results = []
        
        for ep in endpoints:
            if ep.method == "GET":
                # Test for IDOR
                result = await self._fuzz_idor(ep)
                if result:
                    results.append(result)
                
                # Test for injection
                result = await self._fuzz_injection(ep)
                if result:
                    results.append(result)
        
        return results
    
    async def _fuzz_idor(self, endpoint: APIEndpoint) -> Optional[dict]:
        """Fuzz endpoint for IDOR."""
        # Placeholder
        return None
    
    async def _fuzz_injection(self, endpoint: APIEndpoint) -> Optional[dict]:
        """Fuzz endpoint for injection."""
        # Placeholder
        return None
    
    def generate_report(self, schema: APISchema) -> str:
        """Generate API discovery report."""
        report = f"""# 🔌 API Discovery Report

**Base URL:** {schema.base_url}
**Endpoints Found:** {len(schema.endpoints)}

| # | Method | URL | Source | Auth Required |
|---|--------|-----|--------|---------------|
"""
        
        for i, ep in enumerate(schema.endpoints, 1):
            auth = "🔒" if ep.auth_required else ""
            report += f"| {i} | {ep.method} | {ep.url} | {ep.source} | {auth} |\n"
        
        return report
