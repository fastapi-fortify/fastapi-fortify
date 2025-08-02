"""
Web Application Firewall (WAF) protection for FastAPI Guard

This module provides comprehensive protection against common web attacks
including SQL injection, XSS, path traversal, and command injection.
"""
import re
import logging
from typing import List, Dict, Pattern, Optional
from fastapi import Request

from fastapi_fortify.utils.security_utils import SecurityDecision

logger = logging.getLogger(__name__)


class SecurityPatterns:
    """Security patterns for detecting various attack types"""
    
    # SQL Injection patterns
    SQL_INJECTION = [
        r"(?i)(union\s+select|select.*from|insert\s+into|delete\s+from|drop\s+table)",
        r"(?i)(['\"]\s*;\s*drop|['\"]\s*;\s*delete|['\"]\s*;\s*insert)",
        r"(?i)(or\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?|and\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?)",
        r"(?i)(\|\|\s*'|concat\s*\()",
        r"(?i)(having\s+1\s*=\s*1|group\s+by.*having)",
        r"(?i)(waitfor\s+delay|benchmark\s*\(|sleep\s*\()",
    ]
    
    # Cross-Site Scripting (XSS) patterns
    XSS_PATTERNS = [
        r"(?i)(<script[^>]*>|</script>|javascript:|vbscript:|onload\s*=|onerror\s*=)",
        r"(?i)(alert\s*\(|confirm\s*\(|prompt\s*\()",
        r"(?i)(<iframe|<object|<embed|<applet)",
        r"(?i)(document\.cookie|document\.location|window\.location)",
        r"(?i)(eval\s*\(|setTimeout\s*\(|setInterval\s*\()",
        r"(?i)(expression\s*\(|url\s*\(.*javascript)",
    ]
    
    # Path traversal patterns
    PATH_TRAVERSAL = [
        r"(\.\./){2,}",
        r"(?i)(\\\.\\\.\\|/\.\./).*(/etc/|/proc/|/sys/)",
        r"(?i)(file://|ftp://)",
        r"(?i)(\.\./.*\.\./.*\.\./)",
        r"(?i)(\.\.\\.*\.\.\\.*\.\.\\)",
    ]
    
    # Command injection patterns
    COMMAND_INJECTION = [
        r"(?i)(;\s*(cat|ls|pwd|whoami|id|uname)|&&\s*(cat|ls|pwd))",
        r"(?i)(\|\s*(nc|netcat|wget|curl|ping))",
        r"(?i)(exec\s*\(|system\s*\(|passthru\s*\()",
        r"(?i)(`.*`|\$\(.*\))",
        r"(?i)(sh\s+-c|bash\s+-c|cmd\s+/c)",
    ]
    
    # Remote code execution patterns
    REMOTE_CODE_EXECUTION = [
        r"(?i)(eval\s*\(|exec\s*\(|system\s*\()",
        r"(?i)(proc_open|shell_exec|passthru)",
        r"(?i)(__import__|getattr|setattr)",
        r"(?i)(os\.system|os\.popen|subprocess\.)",
    ]
    
    # Local file inclusion patterns  
    LOCAL_FILE_INCLUSION = [
        r"(?i)(include\s*\(|require\s*\(|include_once\s*\()",
        r"(?i)(\.\./).*\.(php|asp|jsp|py)",
        r"(?i)(/etc/passwd|/etc/shadow|/proc/self/environ)",
        r"(?i)(boot\.ini|win\.ini|system32)",
    ]
    
    # Common exploit paths
    EXPLOIT_PATHS = [
        r"(?i)(/wp-admin/|/wp-content/|/wp-includes/)",
        r"(?i)(/phpmyadmin/|/admin/|/administrator/)",
        r"(?i)(\.php$|\.asp$|\.aspx$|\.jsp$)",
        r"(?i)(/\.env|/\.git/|/\.svn/|/\.DS_Store)",
        r"(?i)(phpinfo\.php|test\.php|shell\.php|webshell\.php)",
        r"(?i)(/config/|/backup/|/dump/|/log/)",
    ]
    
    # Bot and scanner patterns
    BOT_USER_AGENTS = [
        r"(?i)(bot|crawler|spider|scraper)",
        r"(?i)(curl|wget|python-requests|http)",
        r"(?i)(nikto|sqlmap|burp|nessus|acunetix)",
        r"(?i)(masscan|nmap|zap|w3af|dirb)",
        r"(?i)(gobuster|dirbuster|wpscan|joomscan)",
    ]


class WAFProtection:
    """
    Web Application Firewall for detecting and blocking malicious requests
    
    This class provides comprehensive protection against:
    - SQL Injection attacks
    - Cross-Site Scripting (XSS)
    - Path traversal attempts
    - Command injection
    - Remote code execution
    - Local file inclusion
    - Common exploit attempts
    """
    
    def __init__(
        self,
        custom_patterns: Optional[List[str]] = None,
        exclusions: Optional[List[str]] = None,
        block_mode: bool = True,
        case_sensitive: bool = False
    ):
        """
        Initialize WAF protection
        
        Args:
            custom_patterns: Additional regex patterns to check
            exclusions: Path patterns to exclude from WAF checks  
            block_mode: If True, block requests; if False, log only
            case_sensitive: Whether pattern matching is case sensitive
        """
        self.custom_patterns = custom_patterns or []
        self.exclusions = exclusions or []
        self.block_mode = block_mode
        self.case_sensitive = case_sensitive
        
        # Compile all patterns for performance
        self._compiled_patterns = self._compile_patterns()
        
        logger.info(f"WAF Protection initialized - Block mode: {block_mode}")
    
    def _compile_patterns(self) -> Dict[str, List[Pattern]]:
        """Compile all regex patterns for better performance"""
        flags = 0 if self.case_sensitive else re.IGNORECASE
        
        compiled = {}
        
        # Compile built-in patterns
        for pattern_type, patterns in [
            ("sql_injection", SecurityPatterns.SQL_INJECTION),
            ("xss", SecurityPatterns.XSS_PATTERNS),
            ("path_traversal", SecurityPatterns.PATH_TRAVERSAL),
            ("command_injection", SecurityPatterns.COMMAND_INJECTION),
            ("rce", SecurityPatterns.REMOTE_CODE_EXECUTION),
            ("lfi", SecurityPatterns.LOCAL_FILE_INCLUSION),
            ("exploit_paths", SecurityPatterns.EXPLOIT_PATHS),
        ]:
            compiled[pattern_type] = []
            for pattern in patterns:
                try:
                    compiled[pattern_type].append(re.compile(pattern, flags))
                except re.error as e:
                    logger.warning(f"Invalid regex pattern in {pattern_type}: {pattern} - {e}")
        
        # Compile custom patterns
        compiled["custom"] = []
        for pattern in self.custom_patterns:
            try:
                compiled["custom"].append(re.compile(pattern, flags))
            except re.error as e:
                logger.warning(f"Invalid custom regex pattern: {pattern} - {e}")
        
        return compiled
    
    async def analyze_request(self, request: Request) -> SecurityDecision:
        """
        Analyze request for malicious patterns
        
        Args:
            request: FastAPI Request object
            
        Returns:
            SecurityDecision indicating if request should be allowed
        """
        path = str(request.url.path)
        
        # Check if path is excluded from WAF
        if self._is_excluded(path):
            return SecurityDecision.allow(
                reason="Path excluded from WAF checks",
                rule_type="waf_exclusion",
                path=path
            )
        
        # Analyze URL path
        path_result = self._analyze_path(path)
        if not path_result.allowed:
            return path_result
        
        # Analyze query parameters
        query = str(request.url.query) if request.url.query else ""
        if query:
            query_result = self._analyze_query_params(query)
            if not query_result.allowed:
                return query_result
        
        # Analyze request headers (for XSS in headers)
        headers_result = self._analyze_headers(dict(request.headers))
        if not headers_result.allowed:
            return headers_result
        
        # Analyze request body (if present and not too large)
        if request.method in ["POST", "PUT", "PATCH"]:
            body_result = await self._analyze_request_body(request)
            if not body_result.allowed:
                return body_result
        
        return SecurityDecision.allow(
            reason="Request passed WAF analysis",
            rule_type="waf",
            checks_performed=["path", "query", "headers", "body"]
        )
    
    def _is_excluded(self, path: str) -> bool:
        """Check if path is excluded from WAF checks"""
        for exclusion in self.exclusions:
            if self._path_matches_pattern(path, exclusion):
                return True
        return False
    
    def _path_matches_pattern(self, path: str, pattern: str) -> bool:
        """Check if path matches pattern (supports wildcards)"""
        # Convert shell-style wildcards to regex
        regex_pattern = pattern.replace("*", ".*").replace("?", ".")
        regex_pattern = f"^{regex_pattern}$"
        
        try:
            flags = 0 if self.case_sensitive else re.IGNORECASE
            return bool(re.match(regex_pattern, path, flags))
        except re.error:
            return False
    
    def _analyze_path(self, path: str) -> SecurityDecision:
        """Analyze URL path for malicious patterns"""
        
        # Check exploit paths first (most specific)
        for pattern in self._compiled_patterns["exploit_paths"]:
            if pattern.search(path):
                return SecurityDecision.block(
                    reason=f"Exploit path detected: {path}",
                    rule_type="waf_exploit_path",
                    confidence=0.95,
                    path=path,
                    pattern_type="exploit_path"
                )
        
        # Check path traversal
        for pattern in self._compiled_patterns["path_traversal"]:
            if pattern.search(path):
                return SecurityDecision.block(
                    reason=f"Path traversal attempt: {path}",
                    rule_type="waf_path_traversal",
                    confidence=0.9,
                    path=path,
                    pattern_type="path_traversal"
                )
        
        # Check for LFI attempts in path
        for pattern in self._compiled_patterns["lfi"]:
            if pattern.search(path):
                return SecurityDecision.block(
                    reason=f"Local file inclusion attempt: {path}",
                    rule_type="waf_lfi",
                    confidence=0.9,
                    path=path,
                    pattern_type="lfi"
                )
        
        return SecurityDecision.allow(
            reason="Path analysis passed",
            rule_type="waf_path",
            path=path
        )
    
    def _analyze_query_params(self, query: str) -> SecurityDecision:
        """Analyze query parameters for injection attempts"""
        
        # Check SQL injection
        for pattern in self._compiled_patterns["sql_injection"]:
            if pattern.search(query):
                return SecurityDecision.block(
                    reason=f"SQL injection attempt in query",
                    rule_type="waf_sqli",
                    confidence=0.9,
                    query_snippet=query[:100],
                    pattern_type="sql_injection"
                )
        
        # Check XSS
        for pattern in self._compiled_patterns["xss"]:
            if pattern.search(query):
                return SecurityDecision.block(
                    reason=f"XSS attempt in query",
                    rule_type="waf_xss",
                    confidence=0.9,
                    query_snippet=query[:100],
                    pattern_type="xss"
                )
        
        # Check command injection
        for pattern in self._compiled_patterns["command_injection"]:
            if pattern.search(query):
                return SecurityDecision.block(
                    reason=f"Command injection attempt",
                    rule_type="waf_command_injection",
                    confidence=0.9,
                    query_snippet=query[:100],
                    pattern_type="command_injection"
                )
        
        # Check RCE
        for pattern in self._compiled_patterns["rce"]:
            if pattern.search(query):
                return SecurityDecision.block(
                    reason=f"Remote code execution attempt",
                    rule_type="waf_rce",
                    confidence=0.95,
                    query_snippet=query[:100],
                    pattern_type="rce"
                )
        
        # Check custom patterns
        for pattern in self._compiled_patterns["custom"]:
            if pattern.search(query):
                return SecurityDecision.block(
                    reason=f"Custom security pattern matched",
                    rule_type="waf_custom",
                    confidence=0.8,
                    query_snippet=query[:100],
                    pattern_type="custom"
                )
        
        return SecurityDecision.allow(
            reason="Query parameters analysis passed",
            rule_type="waf_query"
        )
    
    def _analyze_headers(self, headers: Dict[str, str]) -> SecurityDecision:
        """Analyze request headers for malicious content"""
        
        # Headers that commonly contain user input
        suspicious_headers = [
            "user-agent", "referer", "x-forwarded-for", 
            "x-real-ip", "x-forwarded-host", "host"
        ]
        
        for header_name, header_value in headers.items():
            if header_name.lower() in suspicious_headers:
                
                # Check for XSS in headers
                for pattern in self._compiled_patterns["xss"]:
                    if pattern.search(header_value):
                        return SecurityDecision.block(
                            reason=f"XSS attempt in header: {header_name}",
                            rule_type="waf_header_xss",
                            confidence=0.8,
                            header_name=header_name,
                            header_snippet=header_value[:100],
                            pattern_type="xss"
                        )
                
                # Check for command injection in headers
                for pattern in self._compiled_patterns["command_injection"]:
                    if pattern.search(header_value):
                        return SecurityDecision.block(
                            reason=f"Command injection attempt in header: {header_name}",
                            rule_type="waf_header_injection",
                            confidence=0.8,
                            header_name=header_name,
                            header_snippet=header_value[:100],
                            pattern_type="command_injection"
                        )
        
        return SecurityDecision.allow(
            reason="Headers analysis passed",
            rule_type="waf_headers"
        )
    
    async def _analyze_request_body(self, request: Request) -> SecurityDecision:
        """Analyze request body for malicious content"""
        
        try:
            # Get content type
            content_type = request.headers.get("content-type", "").lower()
            
            # Only analyze text-based content types
            if not any(ct in content_type for ct in [
                "application/json", "application/x-www-form-urlencoded", 
                "text/", "application/xml"
            ]):
                return SecurityDecision.allow(
                    reason="Non-text content type, skipping body analysis",
                    rule_type="waf_body",
                    content_type=content_type
                )
            
            # Read body (with size limit)
            body = await request.body()
            
            # Skip if body is too large (avoid DoS)
            max_body_size = 1024 * 1024  # 1MB
            if len(body) > max_body_size:
                return SecurityDecision.allow(
                    reason="Request body too large for analysis",
                    rule_type="waf_body",
                    body_size=len(body)
                )
            
            # Convert to string for analysis
            try:
                body_str = body.decode('utf-8')
            except UnicodeDecodeError:
                # Binary content, skip analysis
                return SecurityDecision.allow(
                    reason="Binary content, skipping body analysis", 
                    rule_type="waf_body"
                )
            
            # Analyze body content with all patterns
            for pattern_type, patterns in self._compiled_patterns.items():
                if pattern_type == "exploit_paths":
                    continue  # Skip path patterns for body
                    
                for pattern in patterns:
                    if pattern.search(body_str):
                        return SecurityDecision.block(
                            reason=f"{pattern_type.replace('_', ' ').title()} attempt in request body",
                            rule_type=f"waf_body_{pattern_type}",
                            confidence=0.85,
                            body_snippet=body_str[:200],
                            pattern_type=pattern_type
                        )
            
            return SecurityDecision.allow(
                reason="Request body analysis passed",
                rule_type="waf_body",
                body_size=len(body)
            )
            
        except Exception as e:
            logger.warning(f"Error analyzing request body: {e}")
            # Fail open by default
            return SecurityDecision.allow(
                reason="Body analysis error, allowing request",
                rule_type="waf_body",
                error=str(e)
            )
    
    def add_custom_pattern(self, pattern: str, pattern_type: str = "custom") -> bool:
        """
        Add a custom security pattern
        
        Args:
            pattern: Regex pattern to add
            pattern_type: Type of pattern (for organization)
            
        Returns:
            True if pattern was added successfully, False if invalid
        """
        try:
            flags = 0 if self.case_sensitive else re.IGNORECASE
            compiled_pattern = re.compile(pattern, flags)
            
            if pattern_type not in self._compiled_patterns:
                self._compiled_patterns[pattern_type] = []
            
            self._compiled_patterns[pattern_type].append(compiled_pattern)
            
            logger.info(f"Added custom WAF pattern: {pattern}")
            return True
            
        except re.error as e:
            logger.error(f"Invalid regex pattern: {pattern} - {e}")
            return False
    
    def get_pattern_stats(self) -> Dict[str, int]:
        """Get statistics about loaded patterns"""
        return {
            pattern_type: len(patterns) 
            for pattern_type, patterns in self._compiled_patterns.items()
        }
    
    def test_pattern_against_string(self, test_string: str) -> List[Dict[str, str]]:
        """
        Test a string against all patterns (useful for debugging)
        
        Args:
            test_string: String to test
            
        Returns:
            List of matches with pattern type and details
        """
        matches = []
        
        for pattern_type, patterns in self._compiled_patterns.items():
            for i, pattern in enumerate(patterns):
                if pattern.search(test_string):
                    matches.append({
                        "pattern_type": pattern_type,
                        "pattern_index": i,
                        "pattern": pattern.pattern,
                        "match": pattern.search(test_string).group(0)
                    })
        
        return matches


# Factory function for easy WAF creation
def create_waf_protection(
    security_level: str = "balanced",
    custom_patterns: Optional[List[str]] = None,
    **kwargs
) -> WAFProtection:
    """
    Create WAF protection with predefined security levels
    
    Args:
        security_level: "permissive", "balanced", or "strict"
        custom_patterns: Additional patterns to include
        **kwargs: Additional WAFProtection arguments
        
    Returns:
        Configured WAFProtection instance
    """
    if security_level == "permissive":
        # Only block obvious attacks
        return WAFProtection(
            custom_patterns=custom_patterns,
            block_mode=True,
            **kwargs
        )
    elif security_level == "strict":
        # Block aggressively, including potential false positives
        strict_patterns = [
            r"(?i)(select|insert|update|delete|drop|create|alter)",  # Any SQL keywords
            r"(?i)(<[^>]*>)",  # Any HTML tags
            r"(\.\./|\.\.\\)",  # Any path traversal
        ]
        all_patterns = (custom_patterns or []) + strict_patterns
        return WAFProtection(
            custom_patterns=all_patterns,
            block_mode=True,
            **kwargs
        )
    else:  # balanced (default)
        return WAFProtection(
            custom_patterns=custom_patterns,
            block_mode=True,
            **kwargs
        )