"""
Configuration presets for common use cases
This module provides pre-configured security settings for different
environments and use cases, making it easy to get started quickly.
"""
from typing import Dict, Any
from fastapi_fortify.config.settings import SecurityConfig, SecurityEnvironment, LogLevel


class DevelopmentConfig(SecurityConfig):
    """Development environment configuration - permissive settings for testing"""
    
    def __init__(self, **kwargs):
        defaults = {
            "environment": SecurityEnvironment.DEVELOPMENT,
            "debug": True,
            "enable_waf": True,
            "enable_rate_limiting": False,  # Disabled for easier development
            "enable_bot_detection": False,  # Disabled for easier development
            "enable_ip_blocking": True,      # Enabled for testing
            "enable_auth_monitoring": True,
            "log_level": LogLevel.DEBUG,
            "log_all_requests": True,
            "show_powered_by": True,
            "fail_open": True,
            "rate_limits": {
                "/api/auth/*": {"requests": 1000, "window": 60},
                "/api/*": {"requests": 10000, "window": 60},
                "*": {"requests": 100000, "window": 60}
            },
            "whitelist_ips": ["127.0.0.1", "::1", "192.168.0.0/16", "10.0.0.0/8"],
            "bot_detection_mode": "permissive",
            "allow_search_bots": True
        }
        defaults.update(kwargs)
        super().__init__(**defaults)


class ProductionConfig(SecurityConfig):
    """Production environment configuration - strict security settings"""
    
    def __init__(self, **kwargs):
        defaults = {
            "environment": SecurityEnvironment.PRODUCTION,
            "debug": False,
            "enable_waf": True,
            "enable_rate_limiting": True,
            "enable_bot_detection": True,
            "enable_ip_blocking": True,
            "enable_auth_monitoring": True,
            "enable_management_api": True,
            "log_level": LogLevel.INFO,
            "log_blocked_requests": True,
            "log_all_requests": False,
            "show_powered_by": True,
            "fail_open": False,  # Fail closed in production
            "rate_limits": {
                "/api/auth/*": {"requests": 10, "window": 60},
                "/api/*": {"requests": 100, "window": 60},
                "*": {"requests": 200, "window": 60}
            },
            "threat_intelligence_feeds": [
                {
                    "name": "emerging_threats_compromised",
                    "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                    "format": "text",
                    "update_interval": 3600
                }
            ],
            "whitelist_ips": ["127.0.0.1", "::1"],
            "bot_detection_mode": "strict",
            "block_empty_user_agents": True,
            "auto_block_threshold": 5,
            "auth_failure_threshold": 5,
            "auth_failure_window": 300
        }
        defaults.update(kwargs)
        super().__init__(**defaults)


class HighSecurityConfig(SecurityConfig):
    """High security configuration for sensitive applications"""
    
    def __init__(self, **kwargs):
        defaults = {
            "environment": SecurityEnvironment.PRODUCTION,
            "debug": False,
            "enable_waf": True,
            "enable_rate_limiting": True, 
            "enable_bot_detection": True,
            "enable_ip_blocking": True,
            "enable_auth_monitoring": True,
            "enable_management_api": False,  # Disabled for security
            "log_level": LogLevel.WARNING,
            "log_blocked_requests": True,
            "log_all_requests": True,  # Log everything
            "show_powered_by": False,  # Don't reveal technology stack
            "fail_open": False,  # Always fail closed
            "waf_block_mode": True,
            "rate_limits": {
                "/api/auth/*": {"requests": 5, "window": 60},   # Very strict auth limits
                "/api/*": {"requests": 50, "window": 60},       # Strict API limits
                "*": {"requests": 100, "window": 60}            # Strict default limits
            },
            "threat_intelligence_feeds": [
                {
                    "name": "emerging_threats_compromised",
                    "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                    "format": "text",
                    "update_interval": 1800  # Update every 30 minutes
                },
                {
                    "name": "spamhaus_drop",
                    "url": "https://www.spamhaus.org/drop/drop.txt", 
                    "format": "text",
                    "update_interval": 3600
                }
            ],
            "whitelist_ips": [],  # No default whitelist
            "bot_detection_mode": "strict",
            "allow_search_bots": False,  # Block all bots
            "block_empty_user_agents": True,
            "block_private_networks": True,
            "auto_block_threshold": 3,  # Lower threshold
            "auth_failure_threshold": 3,  # Lower threshold
            "auth_failure_window": 600,  # Longer window
            "management_api_auth": True,  # Require auth if enabled
            "cache_ttl": 600,  # Longer cache for performance
            "custom_server_header": "WebServer"  # Generic server header
        }
        defaults.update(kwargs)
        super().__init__(**defaults)


class APIOnlyConfig(SecurityConfig):
    """Configuration optimized for API-only applications"""
    
    def __init__(self, **kwargs):
        defaults = {
            "environment": SecurityEnvironment.PRODUCTION,
            "debug": False,
            "enable_waf": True,
            "enable_rate_limiting": True,
            "enable_bot_detection": True,
            "enable_ip_blocking": True,
            "enable_auth_monitoring": True,
            "enable_management_api": True,
            "log_level": LogLevel.INFO,
            "show_powered_by": True,
            "rate_limits": {
                "/api/v1/auth/*": {"requests": 20, "window": 60},
                "/api/v1/*": {"requests": 1000, "window": 60},
                "/api/*": {"requests": 500, "window": 60},
                "*": {"requests": 100, "window": 60}  # Very low for non-API routes
            },
            "custom_waf_patterns": [
                # API-specific patterns
                r"(?i)(\.\.\/|\.\.\\)",  # Path traversal in API calls
                r"(?i)(eval\s*\(|exec\s*\()",  # Code injection
            ],
            "bot_detection_mode": "balanced",
            "allow_search_bots": False,  # APIs don't need search bots
            "block_empty_user_agents": True,
            "management_api_prefix": "/admin/security"
        }
        defaults.update(kwargs)
        super().__init__(**defaults)


class TestingConfig(SecurityConfig):
    """Configuration for testing environments"""
    
    def __init__(self, **kwargs):
        defaults = {
            "environment": SecurityEnvironment.TESTING,
            "debug": True,
            "enable_waf": True,  # Keep enabled for testing
            "enable_rate_limiting": False,  # Disabled for faster tests
            "enable_bot_detection": False,  # Disabled for easier testing
            "enable_ip_blocking": False,  # Disabled for testing
            "enable_auth_monitoring": False,  # Disabled for testing
            "enable_management_api": True,  # Enabled for testing management API
            "log_level": LogLevel.CRITICAL,  # Minimal logging during tests
            "log_blocked_requests": False,
            "log_all_requests": False,
            "show_powered_by": False,
            "fail_open": True,  # Always fail open in tests
            "rate_limits": {},  # No rate limits in testing
            "threat_intelligence_feeds": [],  # No external feeds in testing
            "whitelist_ips": ["127.0.0.1", "::1", "0.0.0.0/0"],  # Allow everything
            "cache_ttl": 1,  # Very short cache for testing
            "management_api_auth": False  # No auth required for testing
        }
        defaults.update(kwargs)
        super().__init__(**defaults)


# Configuration registry
CONFIG_PRESETS: Dict[str, type] = {
    "development": DevelopmentConfig,
    "dev": DevelopmentConfig,
    "production": ProductionConfig,
    "prod": ProductionConfig,
    "high-security": HighSecurityConfig,
    "highsec": HighSecurityConfig,
    "api-only": APIOnlyConfig,
    "api": APIOnlyConfig,
    "testing": TestingConfig,
    "test": TestingConfig
}


def get_preset_config(preset_name: str, **overrides) -> SecurityConfig:
    """
    Get a preset configuration by name
    
    Args:
        preset_name: Name of the preset (development, production, etc.)
        **overrides: Additional configuration overrides
    
    Returns:
        SecurityConfig instance with preset + overrides applied
    
    Raises:
        ValueError: If preset_name is not recognized
    """
    preset_name = preset_name.lower().strip()
    
    if preset_name not in CONFIG_PRESETS:
        available = ", ".join(CONFIG_PRESETS.keys())
        raise ValueError(f"Unknown preset '{preset_name}'. Available: {available}")
    
    config_class = CONFIG_PRESETS[preset_name]
    return config_class(**overrides)


def list_presets() -> Dict[str, str]:
    """List available configuration presets with descriptions"""
    return {
        "development": "Development environment - permissive settings",
        "production": "Production environment - balanced security",
        "high-security": "High security - strict settings for sensitive apps",
        "api-only": "Optimized for API-only applications",
        "testing": "Testing environment - minimal restrictions"
    }


# Convenience functions for common use cases
def for_development(**overrides) -> SecurityConfig:
    """Get development configuration"""
    return DevelopmentConfig(**overrides)


def for_production(**overrides) -> SecurityConfig:
    """Get production configuration"""
    return ProductionConfig(**overrides)


def for_high_security(**overrides) -> SecurityConfig:
    """Get high security configuration"""
    return HighSecurityConfig(**overrides)


def for_api_only(**overrides) -> SecurityConfig:
    """Get API-only configuration"""
    return APIOnlyConfig(**overrides)


def for_testing(**overrides) -> SecurityConfig:
    """Get testing configuration"""
    return TestingConfig(**overrides)