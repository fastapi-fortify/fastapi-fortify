"""
Configuration system for FastAPI Guard

Provides flexible configuration with environment-specific defaults,
validation, and easy customization.
"""
from datetime import timedelta
from enum import Enum
from typing import Dict, List, Optional, Union, Any, Callable
from dataclasses import dataclass, field
from pathlib import Path
import os

from pydantic import BaseModel, validator, Field


class SecurityEnvironment(str, Enum):
    """Security environment types"""
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


class LogLevel(str, Enum):
    """Logging levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class RateLimitRule:
    """Rate limit configuration for a specific path pattern"""
    requests: int
    window: int  # seconds
    per: str = "ip"  # "ip", "user", "custom"
    skip_successful: bool = False
    skip_failed: bool = False


@dataclass 
class ThreatFeed:
    """Threat intelligence feed configuration"""
    name: str
    url: str
    format: str = "text"  # "text", "json", "csv"
    update_interval: int = 3600  # seconds
    enabled: bool = True
    

class SecurityConfig(BaseModel):
    """
    Main configuration class for FastAPI Guard
    
    This provides a clean, validated configuration interface with
    sensible defaults for different environments.
    """
    
    # Environment
    environment: SecurityEnvironment = SecurityEnvironment.PRODUCTION
    debug: bool = False
    
    # Core feature toggles
    enable_waf: bool = True
    enable_rate_limiting: bool = True
    enable_bot_detection: bool = True
    enable_ip_blocking: bool = True
    enable_auth_monitoring: bool = True
    enable_management_api: bool = True
    
    # WAF Configuration
    waf_block_mode: bool = True  # False = monitor only
    custom_waf_patterns: List[str] = Field(default_factory=list)
    waf_exclusions: List[str] = Field(default_factory=list)  # Skip WAF for these paths
    
    # Rate Limiting
    rate_limits: Dict[str, Dict[str, Union[int, str]]] = Field(default_factory=dict)
    rate_limit_storage: str = "memory"  # "memory", "redis"
    rate_limit_headers: bool = True  # Add X-RateLimit-* headers
    
    # Bot Detection  
    bot_detection_mode: str = "strict"  # "permissive", "balanced", "strict"
    allow_search_bots: bool = True
    custom_bot_patterns: List[str] = Field(default_factory=list)
    block_empty_user_agents: bool = True
    
    # IP Blocking
    static_blocklist_file: Optional[str] = None
    threat_intelligence_feeds: List[Dict[str, Any]] = Field(default_factory=list)
    auto_block_threshold: int = 5  # Auto-block after N violations
    block_private_networks: bool = False
    whitelist_ips: List[str] = Field(default_factory=list)
    
    # Authentication Monitoring
    auth_failure_threshold: int = 5
    auth_failure_window: int = 300  # seconds
    auth_webhook_endpoints: Dict[str, str] = Field(default_factory=dict)
    
    # Management API
    management_api_prefix: str = "/security"
    management_api_auth: bool = False  # Require auth for management endpoints
    
    # Performance
    cache_size: int = 10000
    cache_ttl: int = 300  # seconds
    max_request_size: int = 10 * 1024 * 1024  # 10MB
    
    # Logging
    log_level: LogLevel = LogLevel.INFO
    log_blocked_requests: bool = True
    log_all_requests: bool = False
    
    # Advanced
    fail_open: bool = True  # Continue if security checks fail
    custom_error_responses: Dict[int, Dict[str, Any]] = Field(default_factory=dict)
    
    # Macrosia branding (can be disabled)
    show_powered_by: bool = True
    custom_server_header: Optional[str] = None
    
    class Config:
        use_enum_values = True
        validate_assignment = True
        extra = "forbid"  # Prevent typos in config
    
    @validator("rate_limits")
    def validate_rate_limits(cls, v):
        """Validate rate limit configuration"""
        for path, config in v.items():
            if "requests" not in config or "window" not in config:
                raise ValueError(f"Rate limit for {path} must have 'requests' and 'window'")
            if config["requests"] <= 0 or config["window"] <= 0:
                raise ValueError(f"Rate limit values must be positive for {path}")
        return v
    
    @validator("threat_intelligence_feeds")
    def validate_threat_feeds(cls, v):
        """Validate threat intelligence feed configuration"""
        for feed in v:
            if "url" not in feed:
                raise ValueError("Threat feed must have 'url'")
            if "name" not in feed:
                feed["name"] = feed["url"]  # Default name to URL
        return v
    
    @validator("whitelist_ips")
    def validate_whitelist_ips(cls, v):
        """Validate whitelist IP addresses"""
        from ipaddress import ip_address, ip_network, AddressValueError
        
        validated = []
        for ip in v:
            try:
                if "/" in ip:
                    ip_network(ip, strict=False)  # CIDR notation
                else:
                    ip_address(ip)  # Single IP
                validated.append(ip)
            except AddressValueError:
                raise ValueError(f"Invalid IP address in whitelist: {ip}")
        return validated
    
    def get_rate_limit_for_path(self, path: str) -> Optional[Dict[str, Union[int, str]]]:
        """Get rate limit configuration for a specific path"""
        # Exact match first
        if path in self.rate_limits:
            return self.rate_limits[path]
        
        # Pattern matching
        for pattern, config in self.rate_limits.items():
            if self._path_matches_pattern(path, pattern):
                return config
        
        return None
    
    def _path_matches_pattern(self, path: str, pattern: str) -> bool:
        """Check if path matches pattern (supports wildcards)"""
        import re
        
        # Convert shell-style wildcards to regex
        regex_pattern = pattern.replace("*", ".*").replace("?", ".")
        regex_pattern = f"^{regex_pattern}$"
        
        try:
            return bool(re.match(regex_pattern, path))
        except re.error:
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary"""
        return self.dict()
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityConfig":
        """Create config from dictionary"""
        return cls(**data)
    
    @classmethod
    def from_environment(cls, env: Optional[str] = None) -> "SecurityConfig":
        """Create config based on environment variables"""
        if env is None:
            env = os.getenv("ENVIRONMENT", "production").lower()
        
        # Import here to avoid circular imports
        from fastapi_fortify.config.presets import get_preset_config
        return get_preset_config(env)


def create_default_config(environment: str = "production") -> SecurityConfig:
    """Create default configuration for environment"""
    if environment == "development":
        return SecurityConfig(
            environment=SecurityEnvironment.DEVELOPMENT,
            debug=True,
            enable_rate_limiting=False,  # Disabled in dev
            enable_bot_detection=False,  # Disabled in dev  
            log_level=LogLevel.DEBUG,
            log_all_requests=True,
            show_powered_by=True,
            rate_limits={
                "/api/auth/*": {"requests": 100, "window": 60},
                "/api/*": {"requests": 1000, "window": 60},
                "*": {"requests": 10000, "window": 60}
            },
            whitelist_ips=["127.0.0.1", "::1", "192.168.0.0/16"]
        )
    
    elif environment == "testing":
        return SecurityConfig(
            environment=SecurityEnvironment.TESTING,
            debug=True,
            enable_rate_limiting=False,
            enable_bot_detection=False,
            enable_ip_blocking=False,
            enable_auth_monitoring=False,
            log_level=LogLevel.WARNING,
            show_powered_by=False,
            fail_open=True
        )
    
    elif environment == "staging":
        return SecurityConfig(
            environment=SecurityEnvironment.STAGING,
            debug=False,
            enable_waf=True,
            enable_rate_limiting=True,
            enable_bot_detection=True,
            enable_ip_blocking=True,
            log_level=LogLevel.INFO,
            rate_limits={
                "/api/auth/*": {"requests": 20, "window": 60},
                "/api/*": {"requests": 200, "window": 60},
                "*": {"requests": 500, "window": 60}
            }
        )
    
    else:  # production
        return SecurityConfig(
            environment=SecurityEnvironment.PRODUCTION,  
            debug=False,
            enable_waf=True,
            enable_rate_limiting=True,
            enable_bot_detection=True,
            enable_ip_blocking=True,
            enable_auth_monitoring=True,
            log_level=LogLevel.INFO,
            log_blocked_requests=True,
            log_all_requests=False,
            rate_limits={
                "/api/auth/*": {"requests": 10, "window": 60},
                "/api/*": {"requests": 100, "window": 60},
                "*": {"requests": 200, "window": 60}
            },
            threat_intelligence_feeds=[
                {
                    "name": "emerging_threats",
                    "url": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
                    "format": "text",
                    "update_interval": 3600
                }
            ],
            whitelist_ips=["127.0.0.1", "::1"]
        )