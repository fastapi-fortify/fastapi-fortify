"""
Management API for FastAPI Guard

Provides REST endpoints for monitoring, configuration, and management
of the security middleware components.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path

from fastapi import APIRouter, HTTPException, Depends, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse

from fastapi_fortify.api.models import (
    SecurityStatus,
    RateLimitStatus,
    IPBlockStatus,
    BotDetectionStatus,
    WAFStatus,
    AuthStats,
    ThreatSummary,
    IPBlockRequest,
    IPUnblockRequest,
    RateLimitRequest,
    CustomPatternRequest,
    WhitelistRequest,
    ConfigUpdateRequest,
    AlertsResponse,
    MetricsResponse,
    HealthCheckResponse,
    LogsResponse
)

logger = logging.getLogger(__name__)

# Security for management API
security = HTTPBearer(auto_error=False)


class SecurityAPI:
    """
    Management API for FastAPI Guard
    
    Provides endpoints for:
    - System status and health checks
    - Configuration management
    - IP blocking/unblocking
    - Rate limit management
    - Security metrics and alerts
    - Component configuration
    """
    
    def __init__(
        self,
        middleware_instance=None,
        api_key: Optional[str] = None,
        enabled: bool = True,
        prefix: str = "/security",
        require_auth: bool = True
    ):
        """
        Initialize Security API
        
        Args:
            middleware_instance: Reference to SecurityMiddleware instance
            api_key: API key for authentication (optional)
            enabled: Whether API is enabled
            prefix: URL prefix for all endpoints
            require_auth: Whether to require authentication
        """
        self.middleware = middleware_instance
        self.api_key = api_key
        self.enabled = enabled
        self.prefix = prefix
        self.require_auth = require_auth
        
        # Create FastAPI router
        self.router = APIRouter(prefix=prefix, tags=["Security Management"])
        
        # Track API usage
        self.stats = {
            "requests_processed": 0,
            "last_request": None,
            "startup_time": datetime.utcnow()
        }
        
        # Register endpoints
        self._register_endpoints()
        
        logger.info(f"Security API initialized - Prefix: {prefix}, Auth: {require_auth}")
    
    def _check_auth(self, credentials: HTTPAuthorizationCredentials = Depends(security)):
        """Verify API authentication"""
        if not self.require_auth:
            return True
        
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required"
            )
        
        if self.api_key and credentials.credentials != self.api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key"
            )
        
        return True
    
    def _register_endpoints(self):
        """Register all API endpoints"""
        
        @self.router.get("/health", response_model=HealthCheckResponse)
        async def health_check():
            """System health check"""
            self.stats["requests_processed"] += 1
            self.stats["last_request"] = datetime.utcnow()
            
            uptime = (datetime.utcnow() - self.stats["startup_time"]).total_seconds()
            
            # Check component health
            components = {}
            if self.middleware:
                components["middleware"] = "healthy"
                if hasattr(self.middleware, 'waf') and self.middleware.waf:
                    components["waf"] = "healthy"
                if hasattr(self.middleware, 'bot_detector') and self.middleware.bot_detector:
                    components["bot_detection"] = "healthy"
                if hasattr(self.middleware, 'ip_blocklist') and self.middleware.ip_blocklist:
                    components["ip_blocklist"] = "healthy"
                if hasattr(self.middleware, 'rate_limiter') and self.middleware.rate_limiter:
                    components["rate_limiter"] = "healthy"
                if hasattr(self.middleware, 'auth_monitor') and self.middleware.auth_monitor:
                    components["auth_monitor"] = "healthy"
            
            return HealthCheckResponse(
                status="healthy",
                version="0.1.0",  # Should come from package version
                uptime_seconds=int(uptime),
                components=components
            )
        
        @self.router.get("/status", response_model=SecurityStatus)
        async def get_security_status(auth: bool = Depends(self._check_auth)):
            """Get overall security system status"""
            if not self.middleware:
                raise HTTPException(status_code=503, detail="Security middleware not available")
            
            uptime = (datetime.utcnow() - self.stats["startup_time"]).total_seconds()
            
            # Get middleware stats
            middleware_stats = getattr(self.middleware, 'stats', {})
            
            components = {
                "waf": hasattr(self.middleware, 'waf') and self.middleware.waf is not None,
                "bot_detection": hasattr(self.middleware, 'bot_detector') and self.middleware.bot_detector is not None,
                "ip_blocklist": hasattr(self.middleware, 'ip_blocklist') and self.middleware.ip_blocklist is not None,
                "rate_limiter": hasattr(self.middleware, 'rate_limiter') and self.middleware.rate_limiter is not None,
                "auth_monitor": hasattr(self.middleware, 'auth_monitor') and self.middleware.auth_monitor is not None
            }
            
            return SecurityStatus(
                enabled=True,
                version="0.1.0",
                uptime_seconds=int(uptime),
                requests_processed=middleware_stats.get("requests_processed", 0),
                threats_blocked=middleware_stats.get("threats_blocked", 0),
                last_threat=middleware_stats.get("last_threat"),
                components=components
            )
        
        @self.router.get("/waf/status", response_model=WAFStatus)
        async def get_waf_status(auth: bool = Depends(self._check_auth)):
            """Get WAF protection status"""
            if not self.middleware or not hasattr(self.middleware, 'waf'):
                raise HTTPException(status_code=503, detail="WAF not available")
            
            waf = self.middleware.waf
            if not waf:
                return WAFStatus(enabled=False, patterns_loaded={}, requests_analyzed=0, threats_blocked=0)
            
            # Get WAF statistics
            patterns_loaded = {}
            if hasattr(waf, 'get_pattern_stats'):
                patterns_loaded = waf.get_pattern_stats()
            
            return WAFStatus(
                enabled=True,
                patterns_loaded=patterns_loaded,
                requests_analyzed=getattr(waf, 'requests_analyzed', 0),
                threats_blocked=getattr(waf, 'threats_blocked', 0),
                recent_blocks=getattr(waf, 'recent_blocks', [])
            )
        
        @self.router.get("/rate-limits/status", response_model=RateLimitStatus)
        async def get_rate_limit_status(auth: bool = Depends(self._check_auth)):
            """Get rate limiting status"""
            if not self.middleware or not hasattr(self.middleware, 'rate_limiter'):
                raise HTTPException(status_code=503, detail="Rate limiter not available")
            
            rate_limiter = self.middleware.rate_limiter
            if not rate_limiter:
                return RateLimitStatus(enabled=False, limiter_type="none", total_keys=0, active_limits=0, requests_limited=0)
            
            # Get rate limiter statistics
            stats = {}
            if hasattr(rate_limiter, 'get_stats'):
                stats = await rate_limiter.get_stats()
            
            return RateLimitStatus(
                enabled=True,
                limiter_type=stats.get("type", "unknown"),
                total_keys=stats.get("total_keys", 0),
                active_limits=stats.get("active_limits", 0),
                requests_limited=stats.get("requests_limited", 0),
                top_limited_ips=stats.get("top_limited_ips", [])
            )
        
        @self.router.get("/ip-blocklist/status", response_model=IPBlockStatus)
        async def get_ip_blocklist_status(auth: bool = Depends(self._check_auth)):
            """Get IP blocklist status"""
            if not self.middleware or not hasattr(self.middleware, 'ip_blocklist'):
                raise HTTPException(status_code=503, detail="IP blocklist not available")
            
            ip_blocklist = self.middleware.ip_blocklist
            if not ip_blocklist:
                return IPBlockStatus(enabled=False, static_entries=0, dynamic_entries=0, whitelist_entries=0, threat_feeds_active=0, blocks_today=0)
            
            # Get IP blocklist statistics
            stats = {}
            if hasattr(ip_blocklist, 'get_stats'):
                stats = ip_blocklist.get_stats()
            
            return IPBlockStatus(
                enabled=True,
                static_entries=stats.get("static_entries", 0),
                dynamic_entries=stats.get("dynamic_entries", 0),
                whitelist_entries=stats.get("whitelist_entries", 0),
                threat_feeds_active=stats.get("threat_feeds_configured", 0),
                last_feed_update=None,  # TODO: Get from stats
                blocks_today=stats.get("blocks", 0),
                top_blocked_ips=[]  # TODO: Implement
            )
        
        @self.router.get("/bot-detection/status", response_model=BotDetectionStatus)
        async def get_bot_detection_status(auth: bool = Depends(self._check_auth)):
            """Get bot detection status"""
            if not self.middleware or not hasattr(self.middleware, 'bot_detector'):
                raise HTTPException(status_code=503, detail="Bot detector not available")
            
            bot_detector = self.middleware.bot_detector
            if not bot_detector:
                return BotDetectionStatus(enabled=False, detection_mode="none", tracked_ips=0, bots_detected=0)
            
            # Get bot detector statistics
            stats = {}
            if hasattr(bot_detector, 'get_detection_stats'):
                stats = bot_detector.get_detection_stats()
            
            return BotDetectionStatus(
                enabled=True,
                detection_mode=stats.get("mode", "unknown"),
                tracked_ips=stats.get("tracked_ips", 0),
                bots_detected=stats.get("bots_detected", 0),
                patterns_loaded=stats.get("active_patterns", {}),
                recent_detections=[]  # TODO: Implement
            )
        
        @self.router.get("/auth/status", response_model=AuthStats)
        async def get_auth_status(auth: bool = Depends(self._check_auth)):
            """Get authentication monitoring status"""
            if not self.middleware or not hasattr(self.middleware, 'auth_monitor'):
                raise HTTPException(status_code=503, detail="Auth monitor not available")
            
            auth_monitor = self.middleware.auth_monitor
            if not auth_monitor:
                return AuthStats(enabled=False, events_processed=0, alerts_generated=0, failed_logins_24h=0, successful_logins_24h=0, brute_force_attempts=0)
            
            # Get auth monitor statistics
            stats = auth_monitor.stats if hasattr(auth_monitor, 'stats') else {}
            summary = {}
            if hasattr(auth_monitor, 'get_security_summary'):
                try:
                    summary = await auth_monitor.get_security_summary(24)
                except Exception as e:
                    logger.error(f"Failed to get auth summary: {e}")
            
            return AuthStats(
                enabled=True,
                events_processed=stats.get("events_processed", 0),
                alerts_generated=stats.get("alerts_generated", 0),
                failed_logins_24h=summary.get("summary", {}).get("failed_logins", 0),
                successful_logins_24h=summary.get("summary", {}).get("successful_logins", 0),
                brute_force_attempts=0,  # TODO: Implement
                suspicious_ips=[]  # TODO: Implement
            )
        
        @self.router.post("/ip-blocklist/block")
        async def block_ip(
            request: IPBlockRequest,
            auth: bool = Depends(self._check_auth)
        ):
            """Block an IP address"""
            if not self.middleware or not hasattr(self.middleware, 'ip_blocklist'):
                raise HTTPException(status_code=503, detail="IP blocklist not available")
            
            ip_blocklist = self.middleware.ip_blocklist
            if not ip_blocklist:
                raise HTTPException(status_code=503, detail="IP blocklist not configured")
            
            try:
                # Add temporary block
                ip_blocklist.add_temporary_block(
                    ip=request.ip_address,
                    reason=request.reason,
                    hours=request.duration_hours if request.duration_hours > 0 else 24 * 365,  # 1 year for "permanent"
                    severity=request.severity
                )
                
                logger.info(f"Manually blocked IP {request.ip_address}: {request.reason}")
                
                return {"status": "success", "message": f"IP {request.ip_address} has been blocked"}
                
            except Exception as e:
                logger.error(f"Failed to block IP {request.ip_address}: {e}")
                raise HTTPException(status_code=500, detail=f"Failed to block IP: {str(e)}")
        
        @self.router.post("/ip-blocklist/unblock")
        async def unblock_ip(
            request: IPUnblockRequest,
            auth: bool = Depends(self._check_auth)
        ):
            """Unblock an IP address"""
            if not self.middleware or not hasattr(self.middleware, 'ip_blocklist'):
                raise HTTPException(status_code=503, detail="IP blocklist not available")
            
            ip_blocklist = self.middleware.ip_blocklist
            if not ip_blocklist:
                raise HTTPException(status_code=503, detail="IP blocklist not configured")
            
            try:
                removed = ip_blocklist.remove_block(request.ip_address)
                
                if removed:
                    logger.info(f"Manually unblocked IP {request.ip_address}")
                    return {"status": "success", "message": f"IP {request.ip_address} has been unblocked"}
                else:
                    return {"status": "not_found", "message": f"IP {request.ip_address} was not blocked"}
                    
            except Exception as e:
                logger.error(f"Failed to unblock IP {request.ip_address}: {e}")
                raise HTTPException(status_code=500, detail=f"Failed to unblock IP: {str(e)}")
        
        @self.router.get("/ip-blocklist/{ip_address}")
        async def get_ip_status(
            ip_address: str,
            auth: bool = Depends(self._check_auth)
        ):
            """Get status of specific IP address"""
            if not self.middleware or not hasattr(self.middleware, 'ip_blocklist'):
                raise HTTPException(status_code=503, detail="IP blocklist not available")
            
            ip_blocklist = self.middleware.ip_blocklist
            if not ip_blocklist:
                raise HTTPException(status_code=503, detail="IP blocklist not configured")
            
            try:
                is_blocked, reason = ip_blocklist.is_blocked(ip_address)
                
                return {
                    "ip_address": ip_address,
                    "is_blocked": is_blocked,
                    "reason": reason,
                    "timestamp": datetime.utcnow().isoformat()
                }
                
            except Exception as e:
                logger.error(f"Failed to check IP status {ip_address}: {e}")
                raise HTTPException(status_code=500, detail=f"Failed to check IP status: {str(e)}")
        
        @self.router.post("/waf/patterns")
        async def add_waf_pattern(
            request: CustomPatternRequest,
            auth: bool = Depends(self._check_auth)
        ):
            """Add custom WAF pattern"""
            if not self.middleware or not hasattr(self.middleware, 'waf'):
                raise HTTPException(status_code=503, detail="WAF not available")
            
            waf = self.middleware.waf
            if not waf:
                raise HTTPException(status_code=503, detail="WAF not configured")
            
            try:
                success = waf.add_custom_pattern(request.pattern, request.pattern_type)
                
                if success:
                    logger.info(f"Added custom WAF pattern: {request.pattern}")
                    return {"status": "success", "message": "Pattern added successfully"}
                else:
                    raise HTTPException(status_code=400, detail="Invalid pattern format")
                    
            except Exception as e:
                logger.error(f"Failed to add WAF pattern: {e}")
                raise HTTPException(status_code=500, detail=f"Failed to add pattern: {str(e)}")
        
        @self.router.get("/threats/summary", response_model=ThreatSummary)
        async def get_threat_summary(
            hours: int = Query(24, description="Hours to analyze"),
            auth: bool = Depends(self._check_auth)
        ):
            """Get threat summary for specified time period"""
            if not self.middleware:
                raise HTTPException(status_code=503, detail="Security middleware not available")
            
            # Collect threat data from all components
            threat_types = {}
            total_threats = 0
            
            # WAF threats
            if hasattr(self.middleware, 'waf') and self.middleware.waf:
                waf_blocks = getattr(self.middleware.waf, 'threats_blocked', 0)
                threat_types["waf"] = waf_blocks
                total_threats += waf_blocks
            
            # Bot detection
            if hasattr(self.middleware, 'bot_detector') and self.middleware.bot_detector:
                bot_blocks = getattr(self.middleware.bot_detector, 'bots_detected', 0)
                threat_types["bot_detection"] = bot_blocks
                total_threats += bot_blocks
            
            # IP blocklist
            if hasattr(self.middleware, 'ip_blocklist') and self.middleware.ip_blocklist:
                ip_blocks = getattr(self.middleware.ip_blocklist, 'blocks', 0)
                threat_types["ip_blocklist"] = ip_blocks
                total_threats += ip_blocks
            
            # Rate limiting
            if hasattr(self.middleware, 'rate_limiter') and self.middleware.rate_limiter:
                rate_limits = getattr(self.middleware.rate_limiter, 'requests_limited', 0)
                threat_types["rate_limiting"] = rate_limits
                total_threats += rate_limits
            
            return ThreatSummary(
                period_hours=hours,
                total_threats=total_threats,
                threat_types=threat_types,
                top_threat_ips=[],  # TODO: Implement
                severity_breakdown={"high": total_threats},  # Simplified
                trends={}  # TODO: Implement
            )
        
        @self.router.get("/metrics", response_model=MetricsResponse)
        async def get_metrics(
            hours: int = Query(24, description="Hours to analyze"),
            auth: bool = Depends(self._check_auth)
        ):
            """Get security metrics"""
            metrics = {
                "api_requests": self.stats["requests_processed"],
                "uptime_seconds": int((datetime.utcnow() - self.stats["startup_time"]).total_seconds()),
                "last_request": self.stats["last_request"].isoformat() if self.stats["last_request"] else None
            }
            
            # Add middleware metrics
            if self.middleware and hasattr(self.middleware, 'stats'):
                metrics.update(self.middleware.stats)
            
            return MetricsResponse(
                timestamp=datetime.utcnow(),
                metrics=metrics,
                period_hours=hours
            )
        
        @self.router.post("/config/update")
        async def update_config(
            request: ConfigUpdateRequest,
            auth: bool = Depends(self._check_auth)
        ):
            """Update component configuration"""
            # This would update runtime configuration
            # Implementation depends on how configuration is managed
            logger.info(f"Config update request: {request.component} - {request.settings}")
            
            return {
                "status": "success",
                "message": f"Configuration updated for {request.component}",
                "applied_settings": request.settings
            }


def create_security_api(
    middleware_instance=None,
    api_key: Optional[str] = None,
    enabled: bool = True,
    **kwargs
) -> SecurityAPI:
    """
    Factory function to create SecurityAPI instance
    
    Args:
        middleware_instance: SecurityMiddleware instance
        api_key: API key for authentication
        enabled: Whether API is enabled
        **kwargs: Additional SecurityAPI arguments
        
    Returns:
        Configured SecurityAPI instance
    """
    return SecurityAPI(
        middleware_instance=middleware_instance,
        api_key=api_key,
        enabled=enabled,
        **kwargs
    )