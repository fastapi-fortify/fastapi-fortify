"""
API Models for FastAPI Guard Management Endpoints

Pydantic models for API requests and responses.
"""
from datetime import datetime
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class SecurityStatus(BaseModel):
    """Overall security system status"""
    enabled: bool
    version: str
    uptime_seconds: int
    requests_processed: int
    threats_blocked: int
    last_threat: Optional[datetime] = None
    components: Dict[str, bool] = Field(default_factory=dict)


class RateLimitStatus(BaseModel):
    """Rate limiting status and statistics"""
    enabled: bool
    limiter_type: str
    total_keys: int
    active_limits: int
    requests_limited: int
    top_limited_ips: List[Dict[str, Any]] = Field(default_factory=list)


class IPBlockStatus(BaseModel):
    """IP blocklist status and statistics"""
    enabled: bool
    static_entries: int
    dynamic_entries: int
    whitelist_entries: int
    threat_feeds_active: int
    last_feed_update: Optional[datetime] = None
    blocks_today: int
    top_blocked_ips: List[Dict[str, Any]] = Field(default_factory=list)


class BotDetectionStatus(BaseModel):
    """Bot detection status and statistics"""
    enabled: bool
    detection_mode: str
    tracked_ips: int
    bots_detected: int
    patterns_loaded: Dict[str, int] = Field(default_factory=dict)
    recent_detections: List[Dict[str, Any]] = Field(default_factory=list)


class WAFStatus(BaseModel):
    """WAF protection status and statistics"""
    enabled: bool
    patterns_loaded: Dict[str, int] = Field(default_factory=dict)
    requests_analyzed: int
    threats_blocked: int
    recent_blocks: List[Dict[str, Any]] = Field(default_factory=list)


class AuthStats(BaseModel):
    """Authentication monitoring statistics"""
    enabled: bool
    events_processed: int
    alerts_generated: int
    failed_logins_24h: int
    successful_logins_24h: int
    brute_force_attempts: int
    suspicious_ips: List[str] = Field(default_factory=list)


class ThreatSummary(BaseModel):
    """Summary of recent threats and security events"""
    period_hours: int = 24
    total_threats: int
    threat_types: Dict[str, int] = Field(default_factory=dict)
    top_threat_ips: List[Dict[str, Any]] = Field(default_factory=list)
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
    trends: Dict[str, List[int]] = Field(default_factory=dict)


class IPBlockRequest(BaseModel):
    """Request to block an IP address"""
    ip_address: str = Field(..., description="IP address or CIDR to block")
    reason: str = Field(..., description="Reason for blocking")
    duration_hours: int = Field(24, description="Duration in hours (0 for permanent)")
    severity: str = Field("medium", description="Severity level")


class IPUnblockRequest(BaseModel):
    """Request to unblock an IP address"""
    ip_address: str = Field(..., description="IP address to unblock")


class RateLimitRequest(BaseModel):
    """Request to set rate limit for IP"""
    ip_address: str = Field(..., description="IP address")
    limit: int = Field(..., description="Request limit")
    window_seconds: int = Field(3600, description="Time window in seconds")


class CustomPatternRequest(BaseModel):
    """Request to add custom security pattern"""
    pattern: str = Field(..., description="Regex pattern")
    pattern_type: str = Field("custom", description="Pattern type/category")
    description: Optional[str] = Field(None, description="Pattern description")


class WhitelistRequest(BaseModel):
    """Request to whitelist an IP or pattern"""
    ip_address: str = Field(..., description="IP address or CIDR to whitelist")
    reason: str = Field(..., description="Reason for whitelisting")
    permanent: bool = Field(True, description="Whether whitelist is permanent")


class ConfigUpdateRequest(BaseModel):
    """Request to update security configuration"""
    component: str = Field(..., description="Component to update (waf, bot_detection, etc.)")
    settings: Dict[str, Any] = Field(..., description="Settings to update")


class AlertsResponse(BaseModel):
    """Response with recent security alerts"""
    alerts: List[Dict[str, Any]] = Field(default_factory=list)
    total_count: int
    has_more: bool
    period_hours: int


class MetricsResponse(BaseModel):
    """Response with security metrics"""
    timestamp: datetime
    metrics: Dict[str, Any] = Field(default_factory=dict)
    period_hours: int


class HealthCheckResponse(BaseModel):
    """Health check response"""
    status: str = "healthy"
    version: str
    uptime_seconds: int
    components: Dict[str, str] = Field(default_factory=dict)
    last_error: Optional[str] = None


class LogsResponse(BaseModel):
    """Response with security logs"""
    logs: List[Dict[str, Any]] = Field(default_factory=list)
    total_count: int
    has_more: bool
    filters_applied: Dict[str, Any] = Field(default_factory=dict)