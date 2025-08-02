"""
Core security middleware for FastAPI Guard

This module provides the main SecurityMiddleware class that orchestrates
all security components (WAF, rate limiting, bot detection, etc.)
"""
import logging
import time
from datetime import datetime
from typing import Optional, Dict, Any, Callable
from ipaddress import ip_address, ip_network, AddressValueError

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from fastapi_fortify.config.settings import SecurityConfig, create_default_config
from fastapi_fortify.protection.waf import WAFProtection
from fastapi_fortify.protection.bot_detection import BotDetector  
from fastapi_fortify.protection.ip_blocklist import IPBlocklistManager
from fastapi_fortify.middleware.rate_limiter import MemoryRateLimiter
from fastapi_fortify.monitoring.auth_monitor import AuthMonitor
from fastapi_fortify.utils.ip_utils import get_client_ip
from fastapi_fortify.utils.security_utils import SecurityDecision

logger = logging.getLogger(__name__)


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Main security middleware that orchestrates all protection mechanisms
    
    This middleware provides:
    - Web Application Firewall (WAF) protection
    - Rate limiting with configurable rules
    - Bot detection and blocking
    - IP blocklist management
    - Authentication monitoring
    - Security event logging
    
    Usage:
        from fastapi import FastAPI
        from fastapi_fortify import SecurityMiddleware
        
        app = FastAPI()
        app.add_middleware(SecurityMiddleware)  # Uses default config
        
        # Or with custom config:
        from fastapi_fortify import SecurityConfig
        config = SecurityConfig(enable_bot_detection=False)
        app.add_middleware(SecurityMiddleware, config=config)
    """
    
    def __init__(
        self, 
        app: ASGIApp, 
        config: Optional[SecurityConfig] = None,
        custom_error_handler: Optional[Callable] = None
    ):
        super().__init__(app)
        
        # Configuration
        self.config = config or create_default_config()
        self.custom_error_handler = custom_error_handler
        
        # Initialize protection components
        self._init_components()
        
        # Performance tracking
        self._request_count = 0
        self._blocked_count = 0
        self._start_time = time.time()
        
        logger.info(f"FastAPI Guard initialized - Environment: {self.config.environment}")
    
    def _init_components(self):
        """Initialize all security components"""
        
        # WAF Protection
        if self.config.enable_waf:
            self.waf = WAFProtection(
                custom_patterns=self.config.custom_waf_patterns,
                exclusions=self.config.waf_exclusions,
                block_mode=self.config.waf_block_mode
            )
        else:
            self.waf = None
        
        # Rate Limiting
        if self.config.enable_rate_limiting:
            # TODO: Support Redis rate limiter based on config
            self.rate_limiter = MemoryRateLimiter(
                cache_size=self.config.cache_size,
                cleanup_interval=300
            )
        else:
            self.rate_limiter = None
        
        # Bot Detection
        if self.config.enable_bot_detection:
            self.bot_detector = BotDetector(
                mode=self.config.bot_detection_mode,
                allow_search_bots=self.config.allow_search_bots,
                custom_patterns=self.config.custom_bot_patterns,
                block_empty_user_agents=self.config.block_empty_user_agents
            )
        else:
            self.bot_detector = None
        
        # IP Blocklist Management
        if self.config.enable_ip_blocking:
            self.ip_blocklist = IPBlocklistManager(
                static_blocklist_file=self.config.static_blocklist_file,
                threat_feeds=self.config.threat_intelligence_feeds,
                auto_block_threshold=self.config.auto_block_threshold,
                whitelist_ips=self.config.whitelist_ips,
                block_private_networks=self.config.block_private_networks
            )
        else:
            self.ip_blocklist = None
        
        # Authentication Monitoring
        if self.config.enable_auth_monitoring:
            self.auth_monitor = AuthMonitor()  # Use default parameters for now
        else:
            self.auth_monitor = None
    
    
    async def dispatch(self, request: Request, call_next):
        """Main request processing pipeline"""
        start_time = time.time()
        self._request_count += 1
        
        # Extract client information
        client_ip = get_client_ip(request)
        user_agent = request.headers.get("user-agent", "")
        path = str(request.url.path)
        method = request.method
        
        # Create request context for logging
        request_context = {
            "ip": client_ip,
            "user_agent": user_agent,
            "path": path,
            "method": method,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        try:
            # Security pipeline - each check can block the request
            security_result = await self._run_security_pipeline(
                request, client_ip, user_agent, path, method
            )
            
            if not security_result.allowed:
                return await self._handle_blocked_request(
                    security_result, request_context, start_time
                )
            
            # Request passed all security checks - process normally
            response = await call_next(request)
            
            # Add security headers to response
            self._add_security_headers(response, security_result)
            
            # Log successful request (if configured)
            if self.config.log_all_requests:
                processing_time = (time.time() - start_time) * 1000
                logger.info(
                    f"Request allowed: {method} {path} from {client_ip} "
                    f"({processing_time:.2f}ms)"
                )
            
            return response
            
        except Exception as e:
            # Handle middleware errors
            return await self._handle_middleware_error(e, request_context, start_time)
    
    async def _run_security_pipeline(
        self, 
        request: Request, 
        client_ip: str, 
        user_agent: str, 
        path: str, 
        method: str
    ) -> SecurityDecision:
        """Run all security checks in order of priority"""
        
        # 1. IP Blocklist Check (highest priority)
        if self.ip_blocklist:
            is_blocked, block_reason = self.ip_blocklist.is_blocked(client_ip)
            if is_blocked:
                return SecurityDecision(
                    allowed=False,
                    reason=f"IP blocked: {block_reason}",
                    rule_type="ip_blocklist",
                    confidence=1.0,
                    metadata={"ip": client_ip, "block_reason": block_reason}
                )
        
        # 2. Whitelist Check (skip other checks if whitelisted)
        if self._is_whitelisted_ip(client_ip):
            return SecurityDecision(
                allowed=True,
                reason="IP whitelisted",
                rule_type="whitelist",
                confidence=1.0,
                metadata={"ip": client_ip}
            )
        
        # 3. Rate Limiting Check
        if self.rate_limiter:
            rate_limit_result = await self._check_rate_limits(client_ip, path)
            if not rate_limit_result.allowed:
                return rate_limit_result
        
        # 4. WAF Protection Check
        if self.waf and not self._is_waf_excluded(path):
            waf_result = await self.waf.analyze_request(request)
            if not waf_result.allowed:
                return waf_result
        
        # 5. Bot Detection Check
        if self.bot_detector:
            bot_result = self.bot_detector.analyze_user_agent(user_agent)
            if not bot_result.allowed:
                return bot_result
            
            # Also check behavioral patterns
            pattern_result = self.bot_detector.analyze_request_pattern(client_ip, path)
            if not pattern_result.allowed:
                return pattern_result
        
        # All checks passed
        return SecurityDecision(
            allowed=True,
            reason="All security checks passed",
            rule_type="security_pipeline",
            confidence=0.9,
            metadata={"checks_run": self._get_enabled_checks()}
        )
    
    async def _check_rate_limits(self, client_ip: str, path: str) -> SecurityDecision:
        """Check rate limits for the request"""
        rate_config = self.config.get_rate_limit_for_path(path)
        
        if not rate_config:
            # No rate limit configured for this path
            return SecurityDecision(
                allowed=True,
                reason="No rate limit configured",
                rule_type="rate_limit",
                confidence=1.0
            )
        
        # Create rate limit key
        rate_key = f"{client_ip}:{path}"
        
        # Check rate limit
        allowed, rate_info = await self.rate_limiter.check_rate_limit(
            rate_key,
            rate_config["requests"],
            rate_config["window"]
        )
        
        if not allowed:
            return SecurityDecision(
                allowed=False,
                reason=f"Rate limit exceeded: {rate_config['requests']} requests per {rate_config['window']}s",
                rule_type="rate_limit",
                confidence=1.0,
                metadata={
                    "rate_limit": rate_config,
                    "current_requests": rate_info.requests,
                    "reset_time": rate_info.reset_time
                }
            )
        
        return SecurityDecision(
            allowed=True,
            reason="Within rate limits",
            rule_type="rate_limit",
            confidence=1.0,
            metadata={
                "remaining": rate_info.remaining,
                "reset_time": rate_info.reset_time
            }
        )
    
    def _is_whitelisted_ip(self, ip: str) -> bool:
        """Check if IP is in whitelist"""
        try:
            client_ip = ip_address(ip)
            for whitelist_entry in self.config.whitelist_ips:
                try:
                    if "/" in whitelist_entry:
                        # CIDR notation
                        if client_ip in ip_network(whitelist_entry, strict=False):
                            return True
                    else:
                        # Single IP
                        if client_ip == ip_address(whitelist_entry):
                            return True
                except (AddressValueError, ValueError):
                    continue
        except (AddressValueError, ValueError):
            pass
        
        return False
    
    def _is_waf_excluded(self, path: str) -> bool:
        """Check if path is excluded from WAF checks"""
        for exclusion in self.config.waf_exclusions:
            if self.config._path_matches_pattern(path, exclusion):
                return True
        return False
    
    def _get_enabled_checks(self) -> list:
        """Get list of enabled security checks"""
        checks = []
        if self.config.enable_ip_blocking:
            checks.append("ip_blocking")
        if self.config.enable_rate_limiting:
            checks.append("rate_limiting")
        if self.config.enable_waf:
            checks.append("waf")
        if self.config.enable_bot_detection:
            checks.append("bot_detection")
        return checks
    
    async def _handle_blocked_request(
        self, 
        security_result: SecurityDecision, 
        request_context: Dict[str, Any], 
        start_time: float
    ) -> JSONResponse:
        """Handle a blocked request"""
        self._blocked_count += 1
        processing_time = (time.time() - start_time) * 1000
        
        # Log blocked request
        if self.config.log_blocked_requests:
            logger.warning(
                f"Request blocked: {request_context['method']} {request_context['path']} "
                f"from {request_context['ip']} - {security_result.reason} "
                f"({processing_time:.2f}ms)"
            )
        
        # Determine HTTP status code
        status_code = self._get_status_code_for_rule_type(security_result.rule_type)
        
        # Create error response
        error_response = {
            "error": self._get_error_message_for_status(status_code),
            "message": self._get_safe_error_message(security_result),
            "timestamp": request_context["timestamp"]
        }
        
        # Add rate limit headers if applicable
        headers = {}
        if security_result.rule_type == "rate_limit" and security_result.metadata:
            if "reset_time" in security_result.metadata:
                headers["Retry-After"] = str(int(security_result.metadata["reset_time"] - time.time()))
            if "rate_limit" in security_result.metadata:
                rate_config = security_result.metadata["rate_limit"]
                headers["X-RateLimit-Limit"] = str(rate_config["requests"])
                headers["X-RateLimit-Window"] = str(rate_config["window"])
        
        # Add security headers
        headers.update({
            "X-Security-Status": "blocked",
            "X-Security-Rule": security_result.rule_type,
            "X-Security-Processing-Time": f"{processing_time:.2f}ms"
        })
        
        # Add library attribution (if enabled)
        if self.config.show_powered_by:
            headers["X-Powered-By"] = "FastAPI Guard"
        
        return JSONResponse(
            status_code=status_code,
            content=error_response,
            headers=headers
        )
    
    async def _handle_middleware_error(
        self, 
        error: Exception, 
        request_context: Dict[str, Any], 
        start_time: float
    ) -> JSONResponse:
        """Handle errors that occur within the middleware"""
        processing_time = (time.time() - start_time) * 1000
        
        logger.error(
            f"Security middleware error: {error} for {request_context['method']} "
            f"{request_context['path']} from {request_context['ip']} "
            f"({processing_time:.2f}ms)"
        )
        
        if self.config.fail_open:
            # In fail-open mode, let the request through
            # This is handled by calling call_next, but since we're in an error state,
            # we return a generic response
            return JSONResponse(
                status_code=500,
                content={
                    "error": "Internal Server Error", 
                    "message": "Security middleware encountered an error",
                    "timestamp": request_context["timestamp"]
                },
                headers={"X-Security-Status": "error"}
            )
        else:
            # In fail-closed mode, block the request
            return JSONResponse(
                status_code=503,
                content={
                    "error": "Service Unavailable",
                    "message": "Security system temporarily unavailable", 
                    "timestamp": request_context["timestamp"]
                },
                headers={"X-Security-Status": "error"}
            )
    
    def _add_security_headers(self, response: Response, security_result: SecurityDecision):
        """Add security headers to successful responses"""
        response.headers["X-Security-Status"] = "allowed"
        
        if security_result.metadata and "remaining" in security_result.metadata:
            response.headers["X-RateLimit-Remaining"] = str(security_result.metadata["remaining"])
        
        if self.config.show_powered_by:
            response.headers["X-Powered-By"] = "FastAPI Guard"
        
        if self.config.custom_server_header:
            response.headers["Server"] = self.config.custom_server_header
    
    def _get_status_code_for_rule_type(self, rule_type: str) -> int:
        """Get appropriate HTTP status code for rule type"""
        status_codes = {
            "ip_blocklist": 403,
            "rate_limit": 429,
            "waf": 403,
            "bot_detection": 403,
            "auth_monitoring": 429
        }
        return status_codes.get(rule_type, 403)
    
    def _get_error_message_for_status(self, status_code: int) -> str:
        """Get error message for HTTP status code"""
        messages = {
            403: "Forbidden",
            429: "Too Many Requests",
            500: "Internal Server Error",
            503: "Service Unavailable"
        }
        return messages.get(status_code, "Forbidden")
    
    def _get_safe_error_message(self, security_result: SecurityDecision) -> str:
        """Get safe error message that doesn't reveal too much about security"""
        if self.config.debug:
            return security_result.reason
        
        # Generic messages for production
        safe_messages = {
            "ip_blocklist": "Access denied from your location",
            "rate_limit": "Too many requests. Please try again later",
            "waf": "Invalid request format",
            "bot_detection": "Automated access not permitted",
            "auth_monitoring": "Authentication temporarily restricted"
        }
        return safe_messages.get(security_result.rule_type, "Access denied")
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get security statistics"""
        uptime = time.time() - self._start_time
        
        stats = {
            "uptime_seconds": uptime,
            "total_requests": self._request_count,
            "blocked_requests": self._blocked_count,
            "block_rate": self._blocked_count / max(self._request_count, 1),
            "requests_per_second": self._request_count / max(uptime, 1),
            "enabled_features": self._get_enabled_checks(),
            "environment": self.config.environment.value
        }
        
        # Add component-specific stats
        if self.ip_blocklist:
            stats.update(self.ip_blocklist.get_stats())
        
        if self.rate_limiter:
            stats["rate_limiter_cache_size"] = len(getattr(self.rate_limiter, "store", {}))
        
        return stats


# Factory function for easy middleware creation
def create_security_middleware(
    environment: str = "production",
    **config_overrides
) -> type:
    """
    Factory function to create SecurityMiddleware with environment-specific config
    
    Args:
        environment: Environment name (development, production, etc.)
        **config_overrides: Additional configuration overrides
    
    Returns:
        SecurityMiddleware class ready to be added to FastAPI app
    
    Usage:
        from fastapi import FastAPI
        from fastapi_fortify import create_security_middleware
        
        app = FastAPI()
        SecurityMiddleware = create_security_middleware("production")
        app.add_middleware(SecurityMiddleware)
    """
    from fastapi_fortify.config.presets import get_preset_config
    
    config = get_preset_config(environment, **config_overrides)
    
    class ConfiguredSecurityMiddleware(SecurityMiddleware):
        def __init__(self, app: ASGIApp):
            super().__init__(app, config=config)
    
    return ConfiguredSecurityMiddleware


# Convenience classes for common use cases
class DevelopmentSecurityMiddleware(SecurityMiddleware):
    """Security middleware pre-configured for development"""
    def __init__(self, app: ASGIApp):
        from fastapi_fortify.config.presets import DevelopmentConfig
        super().__init__(app, config=DevelopmentConfig())


class ProductionSecurityMiddleware(SecurityMiddleware):
    """Security middleware pre-configured for production"""
    def __init__(self, app: ASGIApp):
        from fastapi_fortify.config.presets import ProductionConfig
        super().__init__(app, config=ProductionConfig())


class HighSecurityMiddleware(SecurityMiddleware):
    """Security middleware pre-configured for high security environments"""
    def __init__(self, app: ASGIApp):
        from fastapi_fortify.config.presets import HighSecurityConfig
        super().__init__(app, config=HighSecurityConfig())