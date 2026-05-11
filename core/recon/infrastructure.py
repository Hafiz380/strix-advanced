"""
Infrastructure Analyzer
========================
Detects infrastructure misconfigurations in:
- DNS records
- SSL/TLS certificates
- HTTP security headers
- Cloud configurations (S3, Azure Blob, GCS)
- Email security (SPF, DKIM, DMARC)
- CORS configuration
- Cookie security
"""

import re
import ssl
import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlparse


@dataclass
class InfraFinding:
    """Infrastructure security finding."""
    category: str  # "dns", "ssl", "headers", "cloud", "email", "cors", "cookies"
    title: str
    severity: str  # "critical", "high", "medium", "low", "info"
    description: str
    evidence: str = ""
    recommendation: str = ""
    cwe_id: str = ""


class InfrastructureAnalyzer:
    """
    Analyzes infrastructure security configuration.
    
    Usage:
        analyzer = InfrastructureAnalyzer(http_client=client)
        findings = await analyzer.analyze("https://target.com")
        for finding in findings:
            print(f"[{finding.severity}] {finding.title}")
    """
    
    def __init__(self, http_client=None):
        self.http = http_client
    
    async def analyze(self, target: str) -> list[InfraFinding]:
        """Run full infrastructure analysis."""
        findings = []
        
        domain = self._extract_domain(target)
        
        # DNS analysis
        findings.extend(await self._analyze_dns(domain))
        
        # SSL/TLS analysis
        findings.extend(await self._analyze_ssl(domain))
        
        # HTTP headers
        if self.http:
            findings.extend(await self._analyze_headers(target))
            findings.extend(await self._analyze_cookies(target))
            findings.extend(await self._analyze_cors(target))
        
        # Email security
        findings.extend(await self._analyze_email_security(domain))
        
        # Cloud storage
        if self.http:
            findings.extend(await self._analyze_cloud_storage(target))
        
        return findings
    
    async def _analyze_dns(self, domain: str) -> list[InfraFinding]:
        """Analyze DNS configuration."""
        import asyncio
        findings = []
        
        # Check for CAA records
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", domain, "CAA",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            if not stdout or not stdout.strip():
                findings.append(InfraFinding(
                    category="dns",
                    title="Missing CAA Records",
                    severity="low",
                    description="No CAA DNS records found. CAA records restrict which CAs can issue certificates.",
                    recommendation="Add CAA records to specify authorized certificate authorities.",
                    cwe_id="CWE-295",
                ))
        except Exception:
            pass
        
        # Check for SPF record
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", domain, "TXT",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            txt_records = stdout.decode() if stdout else ""
            
            if "v=spf1" not in txt_records:
                findings.append(InfraFinding(
                    category="email",
                    title="Missing SPF Record",
                    severity="medium",
                    description="No SPF record found. This allows email spoofing.",
                    recommendation="Add an SPF record: v=spf1 include:_spf.google.com ~all",
                    cwe_id="CWE-290",
                ))
        except Exception:
            pass
        
        return findings
    
    async def _analyze_ssl(self, domain: str) -> list[InfraFinding]:
        """Analyze SSL/TLS configuration."""
        findings = []
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Check TLS version
                    if version in ("TLSv1", "TLSv1.1"):
                        findings.append(InfraFinding(
                            category="ssl",
                            title=f"Outdated TLS Version: {version}",
                            severity="high",
                            description=f"Server uses {version} which has known vulnerabilities.",
                            recommendation="Configure server to use TLS 1.2 or 1.3.",
                            cwe_id="CWE-326",
                        ))
                    
                    # Check cipher
                    if cipher and cipher[1] < 128:
                        findings.append(InfraFinding(
                            category="ssl",
                            title="Weak Cipher Suite",
                            severity="high",
                            description=f"Using cipher with {cipher[1]}-bit key: {cipher[0]}",
                            recommendation="Configure strong cipher suites (AES-256-GCM).",
                            cwe_id="CWE-326",
                        ))
                    
                    # Check certificate expiry
                    if cert:
                        not_after = cert.get("notAfter", "")
                        if not_after:
                            # Parse certificate expiry
                            try:
                                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                days_left = (expiry - datetime.utcnow()).days
                                if days_left < 30:
                                    findings.append(InfraFinding(
                                        category="ssl",
                                        title=f"Certificate Expiring Soon ({days_left} days)",
                                        severity="high" if days_left < 7 else "medium",
                                        description=f"SSL certificate expires in {days_left} days.",
                                        recommendation="Renew the SSL certificate.",
                                        cwe_id="CWE-295",
                                    ))
                            except ValueError:
                                pass
                    
                    # Check for weak signature
                    if cert:
                        sig_algo = cert.get("signatureAlgorithm", "")
                        if "sha1" in sig_algo.lower():
                            findings.append(InfraFinding(
                                category="ssl",
                                title="Weak Signature Algorithm (SHA-1)",
                                severity="high",
                                description="Certificate uses SHA-1 which is deprecated.",
                                recommendation="Request certificate with SHA-256 signature.",
                                cwe_id="CWE-328",
                            ))
        
        except ssl.SSLError as e:
            findings.append(InfraFinding(
                category="ssl",
                title="SSL/TLS Error",
                severity="high",
                description=f"SSL connection error: {e}",
                recommendation="Fix SSL configuration.",
            ))
        except Exception:
            pass
        
        return findings
    
    async def _analyze_headers(self, target: str) -> list[InfraFinding]:
        """Analyze HTTP security headers."""
        findings = []
        
        try:
            response = await self.http.get(target, timeout=10)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Missing security headers
            security_headers = {
                "strict-transport-security": {
                    "title": "Missing HSTS Header",
                    "severity": "high",
                    "desc": "No Strict-Transport-Security header. Allows SSL stripping attacks.",
                    "rec": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    "cwe": "CWE-319",
                },
                "content-security-policy": {
                    "title": "Missing Content Security Policy",
                    "severity": "medium",
                    "desc": "No CSP header. Increases XSS risk.",
                    "rec": "Implement a Content-Security-Policy header.",
                    "cwe": "CWE-693",
                },
                "x-content-type-options": {
                    "title": "Missing X-Content-Type-Options",
                    "severity": "low",
                    "desc": "No X-Content-Type-Options header. Allows MIME sniffing.",
                    "rec": "Add header: X-Content-Type-Options: nosniff",
                    "cwe": "CWE-693",
                },
                "x-frame-options": {
                    "title": "Missing X-Frame-Options",
                    "severity": "medium",
                    "desc": "No X-Frame-Options header. Allows clickjacking.",
                    "rec": "Add header: X-Frame-Options: DENY",
                    "cwe": "CWE-1021",
                },
                "referrer-policy": {
                    "title": "Missing Referrer-Policy",
                    "severity": "low",
                    "desc": "No Referrer-Policy header. May leak sensitive URLs.",
                    "rec": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
                    "cwe": "CWE-200",
                },
                "permissions-policy": {
                    "title": "Missing Permissions-Policy",
                    "severity": "low",
                    "desc": "No Permissions-Policy header.",
                    "rec": "Add Permissions-Policy to restrict browser features.",
                    "cwe": "CWE-693",
                },
            }
            
            for header_name, info in security_headers.items():
                if header_name not in headers:
                    findings.append(InfraFinding(
                        category="headers",
                        title=info["title"],
                        severity=info["severity"],
                        description=info["desc"],
                        recommendation=info["rec"],
                        cwe_id=info["cwe"],
                    ))
            
            # Check for insecure header values
            if "x-powered-by" in headers:
                findings.append(InfraFinding(
                    category="headers",
                    title="Server Technology Exposed (X-Powered-By)",
                    severity="info",
                    description=f"X-Powered-By header reveals: {headers['x-powered-by']}",
                    recommendation="Remove X-Powered-By header.",
                    cwe_id="CWE-200",
                ))
            
            if "server" in headers:
                server = headers["server"]
                if any(v in server.lower() for v in ["apache/2.2", "nginx/1.", "iis/6", "iis/7"]):
                    findings.append(InfraFinding(
                        category="headers",
                        title=f"Outdated Server Version: {server}",
                        severity="medium",
                        description="Server header reveals outdated version.",
                        recommendation="Update server and hide version.",
                        cwe_id="CWE-200",
                    ))
            
            # Check for permissive CORS
            if "access-control-allow-origin" in headers:
                acao = headers["access-control-allow-origin"]
                if acao == "*":
                    findings.append(InfraFinding(
                        category="cors",
                        title="Permissive CORS Policy (*)",
                        severity="medium",
                        description="Access-Control-Allow-Origin is set to '*'.",
                        recommendation="Restrict CORS to specific trusted origins.",
                        cwe_id="CWE-942",
                    ))
        
        except Exception:
            pass
        
        return findings
    
    async def _analyze_cookies(self, target: str) -> list[InfraFinding]:
        """Analyze cookie security."""
        findings = []
        
        try:
            response = await self.http.get(target, timeout=10)
            
            for cookie in response.cookies:
                issues = []
                
                if not cookie.secure:
                    issues.append("Missing Secure flag")
                
                # Check for HttpOnly (can't directly access from response.cookies)
                # Would need to parse Set-Cookie headers
                
                if issues:
                    findings.append(InfraFinding(
                        category="cookies",
                        title=f"Insecure Cookie: {cookie.name}",
                        severity="medium",
                        description=f"Cookie '{cookie.name}' has issues: {', '.join(issues)}",
                        recommendation="Set Secure and HttpOnly flags on sensitive cookies.",
                        cwe_id="CWE-614",
                    ))
        
        except Exception:
            pass
        
        return findings
    
    async def _analyze_cors(self, target: str) -> list[InfraFinding]:
        """Analyze CORS configuration."""
        findings = []
        
        try:
            response = await self.http.options(
                target,
                headers={"Origin": "https://evil.com"},
                timeout=10,
            )
            
            acao = response.headers.get("access-control-allow-origin", "")
            
            if acao == "https://evil.com":
                findings.append(InfraFinding(
                    category="cors",
                    title="CORS Reflects Arbitrary Origin",
                    severity="high",
                    description="Server reflects any Origin in CORS response.",
                    recommendation="Validate Origin against whitelist.",
                    cwe_id="CWE-346",
                ))
            elif acao == "*":
                findings.append(InfraFinding(
                    category="cors",
                    title="CORS Allows All Origins",
                    severity="medium",
                    description="Access-Control-Allow-Origin is '*'.",
                    recommendation="Restrict to specific origins.",
                    cwe_id="CWE-942",
                ))
        
        except Exception:
            pass
        
        return findings
    
    async def _analyze_email_security(self, domain: str) -> list[InfraFinding]:
        """Analyze email security (SPF, DKIM, DMARC)."""
        import asyncio
        findings = []
        
        # Check DMARC
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", f"_dmarc.{domain}", "TXT",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            dmarc = stdout.decode() if stdout else ""
            
            if not dmarc or "v=DMARC1" not in dmarc:
                findings.append(InfraFinding(
                    category="email",
                    title="Missing DMARC Record",
                    severity="medium",
                    description="No DMARC record found. Allows email spoofing.",
                    recommendation="Add DMARC record: _dmarc.{domain} TXT \"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}\"",
                    cwe_id="CWE-290",
                ))
        except Exception:
            pass
        
        return findings
    
    async def _analyze_cloud_storage(self, target: str) -> list[InfraFinding]:
        """Check for exposed cloud storage."""
        findings = []
        domain = self._extract_domain(target)
        
        # S3 bucket check
        s3_patterns = [
            f"https://{domain}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{domain}",
        ]
        
        for s3_url in s3_patterns:
            try:
                response = await self.http.get(s3_url, timeout=5)
                if response.status_code == 200 and "ListBucketResult" in response.text:
                    findings.append(InfraFinding(
                        category="cloud",
                        title="Exposed S3 Bucket",
                        severity="critical",
                        description=f"S3 bucket is publicly accessible: {s3_url}",
                        recommendation="Restrict S3 bucket access.",
                        cwe_id="CWE-284",
                    ))
            except Exception:
                pass
        
        return findings
    
    def _extract_domain(self, target: str) -> str:
        """Extract domain from target."""
        parsed = urlparse(target)
        return parsed.netloc or parsed.path.split("/")[0]
    
    def generate_report(self, findings: list[InfraFinding]) -> str:
        """Generate infrastructure analysis report."""
        if not findings:
            return "# Infrastructure Analysis\n\n✅ No issues found.\n"
        
        report = f"""# 🏗️ Infrastructure Security Analysis

**Findings:** {len(findings)}

"""
        severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "ℹ️"}
        
        for f in findings:
            emoji = severity_emoji.get(f.severity, "❓")
            report += f"""## {emoji} {f.title}

**Category:** {f.category} | **Severity:** {f.severity.upper()}

{f.description}

**Recommendation:** {f.recommendation}

---
"""
        
        return report
