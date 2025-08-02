"""
Bot Detection for FastAPI Guard

Advanced bot detection using user agent analysis, behavioral patterns,
and request fingerprinting to identify and block automated traffic.
"""
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass
import re

import user_agents

from fastapi_fortify.utils.security_utils import SecurityDecision

logger = logging.getLogger(__name__)


@dataclass
class RequestPattern:
    """Tracks request patterns for behavioral analysis"""
    ip: str
    timestamps: List[float]
    paths: List[str]
    user_agents: Set[str]
    
    def add_request(self, path: str, user_agent: str):
        """Add new request to pattern"""
        current_time = time.time()
        self.timestamps.append(current_time)
        self.paths.append(path)
        self.user_agents.add(user_agent)
        
        # Keep only recent data (last 10 minutes)
        cutoff = current_time - 600
        self.timestamps = [ts for ts in self.timestamps if ts > cutoff]
        
        # Keep only recent paths (last 50 requests)
        if len(self.paths) > 50:
            self.paths = self.paths[-50:]


class BotSignatures:
    """Known bot signatures and patterns"""
    
    # Known malicious bot user agents
    MALICIOUS_BOTS = [
        r"(?i)(sqlmap|nikto|w3af|burpsuite|acunetix)",
        r"(?i)(nessus|openvas|nuclei|gobuster|dirb)",
        r"(?i)(masscan|nmap|zap|wpscan|joomscan)",
        r"(?i)(scrapy|selenium|phantomjs|headless)",
        r"(?i)(python-requests|curl|wget|httpx)",
        r"(?i)(bot|crawler|spider|scraper)(?!.*google|.*bing)",
    ]
    
    # Legitimate search engine bots (whitelist)
    LEGITIMATE_BOTS = [
        r"(?i)googlebot",
        r"(?i)bingbot",
        r"(?i)slurp",  # Yahoo
        r"(?i)duckduckbot",
        r"(?i)baiduspider",
        r"(?i)yandexbot",
        r"(?i)twitterbot",
        r"(?i)facebookexternalhit",
        r"(?i)linkedinbot",
        r"(?i)whatsapp",
        r"(?i)telegrambot",
    ]
    
    # Suspicious user agent patterns
    SUSPICIOUS_PATTERNS = [
        r"^$",  # Empty user agent
        r"^\s*$",  # Whitespace only
        r"^Mozilla/5\.0$",  # Incomplete Mozilla string
        r"^User-Agent$",  # Literally "User-Agent"
        r"(?i)test",  # Contains "test"
        r"(?i)(hack|exploit|attack|inject)",
        r"^.{1,10}$",  # Too short (less than 10 characters)
        r".{500,}",  # Too long (over 500 characters)
    ]
    
    # Known automation tools
    AUTOMATION_TOOLS = [
        r"(?i)(postman|insomnia|httpie)",
        r"(?i)(rest-client|api-client)",
        r"(?i)(automation|testing|monitor)",
        r"(?i)(uptime|status|health|check)",
    ]


class BotDetector:
    """
    Advanced bot detection system
    
    Uses multiple techniques:
    1. User agent analysis
    2. Request pattern analysis  
    3. Behavioral fingerprinting
    4. Rate-based detection
    """
    
    def __init__(
        self,
        mode: str = "balanced",
        allow_search_bots: bool = True,
        custom_patterns: Optional[List[str]] = None,
        block_empty_user_agents: bool = True,
        request_threshold: int = 30,
        time_window: int = 300
    ):
        """
        Initialize bot detector
        
        Args:
            mode: Detection mode - "permissive", "balanced", or "strict"
            allow_search_bots: Whether to allow legitimate search engine bots
            custom_patterns: Additional bot patterns to detect
            block_empty_user_agents: Whether to block empty/missing user agents
            request_threshold: Max requests per IP in time window
            time_window: Time window in seconds for rate analysis
        """
        self.mode = mode
        self.allow_search_bots = allow_search_bots
        self.custom_patterns = custom_patterns or []
        self.block_empty_user_agents = block_empty_user_agents
        self.request_threshold = request_threshold
        self.time_window = time_window
        
        # Request pattern tracking
        self.request_patterns: Dict[str, RequestPattern] = {}
        self.last_cleanup = time.time()
        self.cleanup_interval = 300  # 5 minutes
        
        # Compile patterns for performance
        self._compile_patterns()
        
        logger.info(f"Bot detector initialized - Mode: {mode}, Search bots: {allow_search_bots}")
    
    def _compile_patterns(self):
        """Compile regex patterns for better performance"""
        self.compiled_malicious = [re.compile(p) for p in BotSignatures.MALICIOUS_BOTS]
        self.compiled_legitimate = [re.compile(p) for p in BotSignatures.LEGITIMATE_BOTS]
        self.compiled_suspicious = [re.compile(p) for p in BotSignatures.SUSPICIOUS_PATTERNS]
        self.compiled_automation = [re.compile(p) for p in BotSignatures.AUTOMATION_TOOLS]
        self.compiled_custom = [re.compile(p) for p in self.custom_patterns]
    
    def analyze_user_agent(self, user_agent: str) -> SecurityDecision:
        """
        Analyze user agent string for bot patterns
        
        Args:
            user_agent: User agent string from request
            
        Returns:
            SecurityDecision indicating if request should be allowed
        """
        if not user_agent:
            user_agent = ""
        
        user_agent = user_agent.strip()
        
        # 1. Check for empty/missing user agent
        if self.block_empty_user_agents and not user_agent:
            return SecurityDecision.block(
                reason="Empty or missing user agent",
                rule_type="bot_empty_ua",
                confidence=0.9,
                user_agent=user_agent
            )
        
        # 2. Check for legitimate search engine bots (whitelist)
        if self.allow_search_bots:
            for pattern in self.compiled_legitimate:
                if pattern.search(user_agent):
                    return SecurityDecision.allow(
                        reason=f"Legitimate search engine bot detected",
                        rule_type="bot_legitimate",
                        confidence=0.95,
                        user_agent=user_agent,
                        bot_type="search_engine"
                    )
        
        # 3. Check for known malicious bots
        for pattern in self.compiled_malicious:
            if pattern.search(user_agent):
                return SecurityDecision.block(
                    reason=f"Malicious bot user agent detected",
                    rule_type="bot_malicious",
                    confidence=0.95,
                    user_agent=user_agent[:100],
                    bot_type="malicious"
                )
        
        # 4. Check for suspicious patterns
        for pattern in self.compiled_suspicious:
            if pattern.search(user_agent):
                return SecurityDecision.block(
                    reason=f"Suspicious user agent pattern",
                    rule_type="bot_suspicious",
                    confidence=0.8,
                    user_agent=user_agent[:100],
                    bot_type="suspicious"
                )
        
        # 5. Check for automation tools (mode-dependent)
        if self.mode in ["balanced", "strict"]:
            for pattern in self.compiled_automation:
                if pattern.search(user_agent):
                    return SecurityDecision.block(
                        reason=f"Automation tool detected",
                        rule_type="bot_automation",
                        confidence=0.7,
                        user_agent=user_agent[:100],
                        bot_type="automation"
                    )
        
        # 6. Check custom patterns
        for pattern in self.compiled_custom:
            if pattern.search(user_agent):
                return SecurityDecision.block(
                    reason=f"Custom bot pattern matched",
                    rule_type="bot_custom",
                    confidence=0.8,
                    user_agent=user_agent[:100],
                    bot_type="custom"
                )
        
        # 7. Advanced user agent analysis
        advanced_result = self._advanced_user_agent_analysis(user_agent)
        if not advanced_result.allowed:
            return advanced_result
        
        return SecurityDecision.allow(
            reason="User agent appears legitimate",
            rule_type="bot_detection",
            confidence=0.7,
            user_agent=user_agent[:100]
        )
    
    def _advanced_user_agent_analysis(self, user_agent: str) -> SecurityDecision:
        """Advanced user agent analysis using user-agents library"""
        try:
            parsed_ua = user_agents.parse(user_agent)
            
            # Check if user-agents library identifies it as a bot
            if parsed_ua.is_bot and not self.allow_search_bots:
                return SecurityDecision.block(
                    reason=f"Bot detected by user agent parser: {parsed_ua.browser.family}",
                    rule_type="bot_parsed",
                    confidence=0.9,
                    user_agent=user_agent[:100],
                    bot_family=parsed_ua.browser.family
                )
            
            # In strict mode, be more aggressive
            if self.mode == "strict":
                # Block if no OS information (common in bots)
                if not parsed_ua.os.family or parsed_ua.os.family == "Other":
                    return SecurityDecision.block(
                        reason="No OS information in user agent (suspicious)",
                        rule_type="bot_no_os",
                        confidence=0.6,
                        user_agent=user_agent[:100]
                    )
                
                # Block very old browsers (often used by bots)
                if parsed_ua.browser.version and len(parsed_ua.browser.version) > 0:
                    try:
                        major_version = int(parsed_ua.browser.version[0])
                        if parsed_ua.browser.family == "Chrome" and major_version < 70:
                            return SecurityDecision.block(
                                reason="Very old browser version (suspicious)",
                                rule_type="bot_old_browser",
                                confidence=0.5,
                                user_agent=user_agent[:100],
                                browser_version=major_version
                            )
                    except (ValueError, IndexError):
                        pass
            
        except Exception as e:
            logger.debug(f"Error parsing user agent: {e}")
        
        return SecurityDecision.allow(
            reason="Advanced user agent analysis passed",
            rule_type="bot_advanced_ua"
        )
    
    def analyze_request_pattern(self, ip: str, path: str, user_agent: str = "") -> SecurityDecision:
        """
        Analyze request patterns for bot behavior
        
        Args:
            ip: Client IP address
            path: Request path
            user_agent: User agent string
            
        Returns:
            SecurityDecision indicating if request should be allowed
        """
        self._cleanup_expired_patterns()
        
        # Initialize or update request pattern for this IP
        if ip not in self.request_patterns:
            self.request_patterns[ip] = RequestPattern(
                ip=ip,
                timestamps=[],
                paths=[],
                user_agents=set()
            )
        
        pattern = self.request_patterns[ip]
        pattern.add_request(path, user_agent)
        
        # 1. Check request rate
        recent_requests = len([ts for ts in pattern.timestamps if ts > time.time() - self.time_window])
        if recent_requests > self.request_threshold:
            return SecurityDecision.block(
                reason=f"Too many requests: {recent_requests} in {self.time_window}s",
                rule_type="bot_rate_limit",
                confidence=0.9,
                ip=ip,
                request_count=recent_requests,
                time_window=self.time_window
            )
        
        # 2. Check for scanning behavior
        scanning_result = self._detect_scanning_behavior(pattern)
        if not scanning_result.allowed:
            return scanning_result
        
        # 3. Check for suspicious user agent rotation
        ua_rotation_result = self._detect_user_agent_rotation(pattern)
        if not ua_rotation_result.allowed:
            return ua_rotation_result
        
        # 4. Check for bot-like path patterns
        path_pattern_result = self._detect_bot_path_patterns(pattern)
        if not path_pattern_result.allowed:
            return path_pattern_result
        
        return SecurityDecision.allow(
            reason="Request pattern appears normal",
            rule_type="bot_pattern_analysis",
            confidence=0.7,
            ip=ip,
            recent_requests=recent_requests
        )
    
    def _detect_scanning_behavior(self, pattern: RequestPattern) -> SecurityDecision:
        """Detect directory/vulnerability scanning behavior"""
        recent_paths = pattern.paths[-20:]  # Last 20 requests
        
        # Common scan patterns
        scan_indicators = [
            r"(?i)(/admin|/wp-admin|/phpmyadmin)",
            r"(?i)(/\.env|/\.git|/config|/backup)",
            r"(?i)(/test|/debug|/info|/status)",
            r"(?i)(\.php|\.asp|\.jsp|\.cgi)$",
            r"(?i)(/robots\.txt|/sitemap\.xml)",
        ]
        
        scan_matches = 0
        for path in recent_paths:
            for indicator in scan_indicators:
                if re.search(indicator, path):
                    scan_matches += 1
                    break
        
        # If more than 50% of recent requests match scan patterns
        if len(recent_paths) >= 5 and scan_matches / len(recent_paths) > 0.5:
            return SecurityDecision.block(
                reason=f"Directory scanning detected: {scan_matches}/{len(recent_paths)} suspicious paths",
                rule_type="bot_scanning",
                confidence=0.85,
                ip=pattern.ip,
                scan_matches=scan_matches,
                total_requests=len(recent_paths),
                sample_paths=recent_paths[-5:]
            )
        
        # Sequential path enumeration (common in automated scans)
        if len(recent_paths) >= 10:
            sequential_patterns = 0
            for i in range(len(recent_paths) - 1):
                path1 = recent_paths[i]
                path2 = recent_paths[i + 1]
                # Check if paths are similar but with incrementing numbers/patterns
                if self._are_sequential_paths(path1, path2):
                    sequential_patterns += 1
            
            if sequential_patterns >= 3:  # Multiple sequential patterns
                return SecurityDecision.block(
                    reason=f"Sequential path enumeration detected",
                    rule_type="bot_enumeration",
                    confidence=0.8,
                    ip=pattern.ip,
                    sequential_patterns=sequential_patterns
                )
        
        return SecurityDecision.allow(
            reason="No scanning behavior detected",
            rule_type="bot_scan_check"
        )
    
    def _are_sequential_paths(self, path1: str, path2: str) -> bool:
        """Check if two paths appear to be sequential (e.g., /page1, /page2)"""
        # Simple heuristic: paths are similar but with different numbers
        import difflib
        similarity = difflib.SequenceMatcher(None, path1, path2).ratio()
        
        # If paths are very similar (>80%) and contain numbers
        if similarity > 0.8:
            # Extract all numbers from both paths
            nums1 = re.findall(r'\d+', path1)
            nums2 = re.findall(r'\d+', path2)
            
            if nums1 and nums2 and len(nums1) == len(nums2):
                # Check if any number incremented by 1
                for n1, n2 in zip(nums1, nums2):
                    try:
                        if int(n2) == int(n1) + 1:
                            return True
                    except ValueError:
                        continue
        
        return False
    
    def _detect_user_agent_rotation(self, pattern: RequestPattern) -> SecurityDecision:
        """Detect suspicious user agent rotation"""
        if len(pattern.user_agents) <= 1:
            return SecurityDecision.allow(
                reason="Consistent user agent",
                rule_type="bot_ua_rotation"
            )
        
        # Multiple user agents from same IP is suspicious
        ua_count = len(pattern.user_agents)
        request_count = len(pattern.timestamps)
        
        # If using more than 3 different UAs, or UA:request ratio > 0.3
        if ua_count > 3 or (request_count > 0 and ua_count / request_count > 0.3):
            return SecurityDecision.block(
                reason=f"User agent rotation detected: {ua_count} different UAs",
                rule_type="bot_ua_rotation",
                confidence=0.7,
                ip=pattern.ip,
                user_agent_count=ua_count,
                request_count=request_count,
                sample_user_agents=list(pattern.user_agents)[:3]
            )
        
        return SecurityDecision.allow(
            reason="Normal user agent variation",
            rule_type="bot_ua_rotation"
        )
    
    def _detect_bot_path_patterns(self, pattern: RequestPattern) -> SecurityDecision:
        """Detect bot-like path access patterns"""
        recent_paths = pattern.paths[-15:]
        
        if len(recent_paths) < 5:
            return SecurityDecision.allow(
                reason="Insufficient path data",
                rule_type="bot_path_patterns"
            )
        
        # Check for common bot behaviors
        
        # 1. Accessing only API endpoints (no human browsing)
        api_paths = sum(1 for path in recent_paths if '/api/' in path)
        if api_paths == len(recent_paths) and len(recent_paths) >= 5:
            # This might be legitimate API usage, so lower confidence
            return SecurityDecision.block(
                reason="Accessing only API endpoints (bot-like)",
                rule_type="bot_api_only",
                confidence=0.6,
                ip=pattern.ip,
                api_path_ratio=api_paths / len(recent_paths)
            )
        
        # 2. Never accessing common user pages
        user_indicators = ['/login', '/register', '/profile', '/settings', '/dashboard', '/home', '/about']
        has_user_paths = any(any(indicator in path for indicator in user_indicators) 
                           for path in recent_paths)
        
        # 3. High ratio of 404/error-prone paths
        error_prone_paths = ['/wp-admin', '/admin', '/phpmyadmin', '/.env', '/config']
        error_paths = sum(1 for path in recent_paths 
                         if any(error_path in path for error_path in error_prone_paths))
        
        if error_paths >= len(recent_paths) * 0.6:  # 60% error-prone paths
            return SecurityDecision.block(
                reason="High ratio of error-prone path access",
                rule_type="bot_error_paths",
                confidence=0.8,
                ip=pattern.ip,
                error_path_ratio=error_paths / len(recent_paths)
            )
        
        return SecurityDecision.allow(
            reason="Path patterns appear normal",
            rule_type="bot_path_patterns"
        )
    
    def _cleanup_expired_patterns(self):
        """Clean up expired request patterns"""
        current_time = time.time()
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        expired_ips = []
        cutoff_time = current_time - (self.time_window * 2)  # Keep data for 2x time window
        
        for ip, pattern in self.request_patterns.items():
            # Remove old timestamps
            pattern.timestamps = [ts for ts in pattern.timestamps if ts > cutoff_time]
            
            # If no recent activity, mark for removal
            if not pattern.timestamps:
                expired_ips.append(ip)
        
        # Remove expired patterns
        for ip in expired_ips:
            del self.request_patterns[ip]
        
        self.last_cleanup = current_time
        
        if expired_ips:
            logger.debug(f"Cleaned up {len(expired_ips)} expired request patterns")
    
    def add_custom_pattern(self, pattern: str) -> bool:
        """
        Add custom bot detection pattern
        
        Args:
            pattern: Regex pattern to detect bots
            
        Returns:
            True if pattern added successfully
        """
        try:
            compiled = re.compile(pattern)
            self.compiled_custom.append(compiled)
            self.custom_patterns.append(pattern)
            logger.info(f"Added custom bot pattern: {pattern}")
            return True
        except re.error as e:
            logger.error(f"Invalid bot pattern: {pattern} - {e}")
            return False
    
    def get_detection_stats(self) -> Dict[str, any]:
        """Get bot detection statistics"""
        return {
            "mode": self.mode,
            "allow_search_bots": self.allow_search_bots,
            "tracked_ips": len(self.request_patterns),
            "custom_patterns": len(self.custom_patterns),
            "request_threshold": self.request_threshold,
            "time_window": self.time_window,
            "active_patterns": {
                "malicious": len(self.compiled_malicious),
                "legitimate": len(self.compiled_legitimate),
                "suspicious": len(self.compiled_suspicious),
                "automation": len(self.compiled_automation),
                "custom": len(self.compiled_custom)
            }
        }
    
    def analyze_ip_reputation(self, ip: str) -> Dict[str, any]:
        """Get reputation analysis for an IP"""
        if ip not in self.request_patterns:
            return {"status": "unknown", "requests": 0}
        
        pattern = self.request_patterns[ip]
        recent_requests = len([ts for ts in pattern.timestamps if ts > time.time() - self.time_window])
        
        return {
            "status": "tracked",
            "total_requests": len(pattern.timestamps),
            "recent_requests": recent_requests,
            "unique_paths": len(set(pattern.paths)),
            "unique_user_agents": len(pattern.user_agents),
            "request_rate": recent_requests / (self.time_window / 60),  # requests per minute
            "sample_paths": pattern.paths[-5:],
            "sample_user_agents": list(pattern.user_agents)[:3]
        }


# Factory functions for common configurations
def create_bot_detector(
    security_level: str = "balanced",
    allow_search_engines: bool = True,
    **kwargs
) -> BotDetector:
    """
    Create bot detector with predefined security levels
    
    Args:
        security_level: "permissive", "balanced", or "strict"
        allow_search_engines: Whether to allow legitimate search bots
        **kwargs: Additional BotDetector arguments
        
    Returns:
        Configured BotDetector instance
    """
    if security_level == "permissive":
        return BotDetector(
            mode="permissive",
            allow_search_bots=allow_search_engines,
            block_empty_user_agents=False,
            request_threshold=100,  # Higher threshold
            **kwargs
        )
    elif security_level == "strict":
        return BotDetector(
            mode="strict", 
            allow_search_bots=allow_search_engines,
            block_empty_user_agents=True,
            request_threshold=15,  # Lower threshold
            **kwargs
        )
    else:  # balanced
        return BotDetector(
            mode="balanced",
            allow_search_bots=allow_search_engines,
            block_empty_user_agents=True,
            request_threshold=30,
            **kwargs
        )