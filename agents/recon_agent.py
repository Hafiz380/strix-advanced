"""
Recon Agent
============
Specialized in reconnaissance and attack surface discovery.

Responsibilities:
- Subdomain enumeration
- Port scanning
- Technology fingerprinting
- API endpoint discovery
- Directory bruteforcing
- JavaScript analysis
- Cloud asset discovery
"""

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ReconTarget:
    """Target for reconnaissance."""
    url: str
    target_type: str = "url"  # "url", "domain", "ip", "cidr"
    scope: list[str] = field(default_factory=list)  # In-scope domains/IPs
    exclusions: list[str] = field(default_factory=list)
    credentials: dict[str, str] = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)


@dataclass
class ReconResult:
    """Reconnaissance findings."""
    target: str
    subdomains: list[str] = field(default_factory=list)
    open_ports: list[dict] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    cloud_assets: list[str] = field(default_factory=list)
    interesting_files: list[str] = field(default_factory=list)
    dns_records: dict[str, list[str]] = field(default_factory=dict)
    http_headers: dict[str, str] = field(default_factory=dict)
    cookies: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


class ReconAgent:
    """
    Automated reconnaissance agent.
    
    Usage:
        agent = ReconAgent()
        result = await agent.recon("https://target.com")
        print(f"Found {len(result.subdomains)} subdomains, {len(result.endpoints)} endpoints")
    """
    
    def __init__(self, http_client=None, tools_path: str = "/usr/bin"):
        self.http = http_client
        self.tools_path = tools_path
    
    async def recon(self, target: str, depth: str = "standard") -> ReconResult:
        """
        Run reconnaissance on a target.
        
        Args:
            target: URL, domain, IP, or CIDR
            depth: "quick", "standard", or "deep"
        """
        result = ReconResult(target=target)
        
        # Detect target type
        target_type = self._detect_target_type(target)
        
        # Run recon phases based on depth
        if depth in ("standard", "deep"):
            result.subdomains = await self._enumerate_subdomains(target)
            result.dns_records = await self._dns_enum(target)
        
        if depth == "deep":
            result.open_ports = await self._port_scan(target)
            result.cloud_assets = await self._cloud_enum(target)
        
        # Always do these
        result.technologies = await self._fingerprint_tech(target)
        result.endpoints = await self._discover_endpoints(target)
        result.js_files = await self._find_js_files(target)
        result.api_endpoints = await self._discover_api(target)
        result.http_headers = await self._get_headers(target)
        result.interesting_files = await self._find_interesting_files(target)
        
        return result
    
    async def _enumerate_subdomains(self, target: str) -> list[str]:
        """Enumerate subdomains using multiple techniques."""
        import subprocess
        import asyncio
        
        domain = self._extract_domain(target)
        subdomains = set()
        
        # Certificate Transparency
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", f"https://crt.sh/?q=%.{domain}&output=json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            if stdout:
                import json
                entries = json.loads(stdout)
                for entry in entries:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and "*" not in sub:
                            subdomains.add(sub)
        except Exception:
            pass
        
        # DNS brute-force (common subdomains)
        common_subs = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging",
            "test", "blog", "shop", "app", "portal", "cdn", "static",
            "media", "img", "images", "assets", "docs", "support",
            "help", "status", "monitor", "grafana", "kibana", "jenkins",
            "gitlab", "jira", "confluence", "bitbucket", "nexus",
        ]
        
        import asyncio
        
        async def check_subdomain(sub: str) -> Optional[str]:
            fqdn = f"{sub}.{domain}"
            try:
                proc = await asyncio.create_subprocess_exec(
                    "dig", "+short", fqdn,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                if stdout and stdout.strip():
                    return fqdn
            except Exception:
                pass
            return None
        
        tasks = [check_subdomain(sub) for sub in common_subs]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, str):
                subdomains.add(r)
        
        return sorted(subdomains)
    
    async def _dns_enum(self, target: str) -> dict[str, list[str]]:
        """DNS enumeration."""
        import asyncio
        
        domain = self._extract_domain(target)
        records = {}
        
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        
        for rtype in record_types:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "dig", "+short", domain, rtype,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                if stdout:
                    records[rtype] = [line.strip() for line in stdout.decode().split("\n") if line.strip()]
            except Exception:
                pass
        
        return records
    
    async def _port_scan(self, target: str) -> list[dict]:
        """Port scan using nmap or custom scanner."""
        # Placeholder - would use nmap or custom scanner
        return []
    
    async def _fingerprint_tech(self, target: str) -> list[str]:
        """Fingerprint technologies from HTTP headers and HTML."""
        technologies = []
        
        if not self.http:
            return technologies
        
        try:
            response = await self.http.get(target)
            headers = dict(response.headers)
            body = response.text.lower()
            
            # Server header
            server = headers.get("server", "")
            if server:
                technologies.append(f"Server: {server}")
            
            # X-Powered-By
            powered_by = headers.get("x-powered-by", "")
            if powered_by:
                technologies.append(f"Powered-By: {powered_by}")
            
            # Framework detection from headers
            header_fingerprints = {
                "x-aspnet-version": "ASP.NET",
                "x-aspnetmvc-version": "ASP.NET MVC",
                "x-drupal-cache": "Drupal",
                "x-generator": "Generator",
                "x-powered-by": "Express",
            }
            
            for header, tech in header_fingerprints.items():
                if header in headers:
                    technologies.append(tech)
            
            # Body fingerprints
            body_fingerprints = {
                "wp-content": "WordPress",
                "joomla": "Joomla",
                "drupal": "Drupal",
                "react": "React",
                "vue": "Vue.js",
                "angular": "Angular",
                "next": "Next.js",
                "nuxt": "Nuxt.js",
                "django": "Django",
                "flask": "Flask",
                "laravel": "Laravel",
                "rails": "Ruby on Rails",
                "spring": "Spring Boot",
                "express": "Express.js",
                "fastapi": "FastAPI",
            }
            
            for fingerprint, tech in body_fingerprints.items():
                if fingerprint in body:
                    technologies.append(tech)
            
        except Exception:
            pass
        
        return list(set(technologies))
    
    async def _discover_endpoints(self, target: str) -> list[str]:
        """Discover endpoints from HTML, JavaScript, and robots.txt."""
        endpoints = set()
        
        if not self.http:
            return []
        
        try:
            # Main page
            response = await self.http.get(target)
            
            # Extract links from HTML
            import re
            links = re.findall(r'href=["\']([^"\']+)["\']', response.text)
            for link in links:
                if link.startswith(("http://", "https://", "/")):
                    endpoints.add(link)
            
            # robots.txt
            try:
                robots = await self.http.get(f"{target.rstrip('/')}/robots.txt")
                if robots.status_code == 200:
                    for line in robots.text.split("\n"):
                        if line.lower().startswith(("disallow:", "allow:")):
                            path = line.split(":", 1)[1].strip()
                            if path:
                                endpoints.add(path)
            except Exception:
                pass
            
            # sitemap.xml
            try:
                sitemap = await self.http.get(f"{target.rstrip('/')}/sitemap.xml")
                if sitemap.status_code == 200:
                    urls = re.findall(r'<loc>([^<]+)</loc>', sitemap.text)
                    endpoints.update(urls)
            except Exception:
                pass
            
        except Exception:
            pass
        
        return sorted(endpoints)
    
    async def _find_js_files(self, target: str) -> list[str]:
        """Find JavaScript files."""
        import re
        
        if not self.http:
            return []
        
        try:
            response = await self.http.get(target)
            js_files = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', response.text)
            return [self._resolve_url(target, js) for js in js_files]
        except Exception:
            return []
    
    async def _discover_api(self, target: str) -> list[str]:
        """Discover API endpoints."""
        api_endpoints = set()
        
        if not self.http:
            return []
        
        # Common API paths
        api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/graphql", "/graphiql",
            "/swagger", "/swagger.json", "/swagger/ui",
            "/api-docs", "/openapi.json", "/openapi.yaml",
            "/rest", "/rpc",
        ]
        
        for path in api_paths:
            try:
                url = f"{target.rstrip('/')}{path}"
                response = await self.http.get(url)
                if response.status_code in (200, 401, 403):
                    api_endpoints.add(url)
            except Exception:
                pass
        
        return sorted(api_endpoints)
    
    async def _get_headers(self, target: str) -> dict[str, str]:
        """Get HTTP headers."""
        if not self.http:
            return {}
        
        try:
            response = await self.http.get(target)
            return dict(response.headers)
        except Exception:
            return {}
    
    async def _find_interesting_files(self, target: str) -> list[str]:
        """Find interesting files (configs, backups, etc.)."""
        interesting = []
        
        if not self.http:
            return []
        
        paths = [
            "/.env", "/.git/config", "/.gitignore",
            "/config.json", "/config.yml", "/config.yaml",
            "/wp-config.php", "/settings.py", "/database.yml",
            "/backup.zip", "/backup.sql", "/dump.sql",
            "/phpinfo.php", "/info.php",
            "/.htaccess", "/web.config",
            "/crossdomain.xml", "/clientaccesspolicy.xml",
            "/security.txt", "/.well-known/security.txt",
        ]
        
        for path in paths:
            try:
                url = f"{target.rstrip('/')}{path}"
                response = await self.http.get(url, follow_redirects=False)
                if response.status_code == 200:
                    content_type = response.headers.get("content-type", "")
                    # Filter out HTML error pages
                    if "text/html" not in content_type or len(response.text) < 10000:
                        interesting.append(url)
            except Exception:
                pass
        
        return interesting
    
    async def _cloud_enum(self, target: str) -> list[str]:
        """Enumerate cloud assets (S3 buckets, etc.)."""
        # Placeholder
        return []
    
    def _extract_domain(self, target: str) -> str:
        """Extract domain from URL."""
        from urllib.parse import urlparse
        parsed = urlparse(target)
        return parsed.netloc or parsed.path.split("/")[0]
    
    def _detect_target_type(self, target: str) -> str:
        """Detect target type."""
        import re
        if re.match(r'^\d+\.\d+\.\d+\.\d+(/\d+)?$', target):
            return "cidr" if "/" in target else "ip"
        elif target.startswith(("http://", "https://")):
            return "url"
        else:
            return "domain"
    
    def _resolve_url(self, base: str, relative: str) -> str:
        """Resolve relative URL to absolute."""
        from urllib.parse import urljoin
        return urljoin(base, relative)
    
    def generate_report(self, result: ReconResult) -> str:
        """Generate markdown report."""
        report = f"""# 🔍 Reconnaissance Report

**Target:** {result.target}

## Subdomains ({len(result.subdomains)})
"""
        for sub in result.subdomains:
            report += f"- {sub}\n"
        
        report += f"""
## Technologies ({len(result.technologies)})
"""
        for tech in result.technologies:
            report += f"- {tech}\n"
        
        report += f"""
## Endpoints ({len(result.endpoints)})
"""
        for ep in result.endpoints[:50]:
            report += f"- {ep}\n"
        
        report += f"""
## API Endpoints ({len(result.api_endpoints)})
"""
        for api in result.api_endpoints:
            report += f"- {api}\n"
        
        report += f"""
## JavaScript Files ({len(result.js_files)})
"""
        for js in result.js_files:
            report += f"- {js}\n"
        
        report += f"""
## Interesting Files ({len(result.interesting_files)})
"""
        for f in result.interesting_files:
            report += f"- ⚠️ {f}\n"
        
        return report
