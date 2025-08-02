"""
FastAPI Guard - Comprehensive Security Middleware for FastAPI Applications

Enterprise-grade security for FastAPI applications with zero configuration required.
Battle-tested with millions of requests in production environments.

🛡️ Features:
- WAF Protection (SQL injection, XSS, etc.)
- Advanced Rate Limiting
- Bot Detection & Blocking
- IP Blocklist Management
- Authentication Monitoring
- Threat Intelligence Integration
- Zero-Config Setup

Quick Start:
    from fastapi import FastAPI
    from fastapi_fortify import SecurityMiddleware
    
    app = FastAPI()
    app.add_middleware(SecurityMiddleware)  # That's it!
"""

__version__ = "0.1.0"
__author__ = "FastAPI Guard Contributors"
__email__ = "fastapi-guard@example.com"
__license__ = "Dual Licensed: MIT (Open Source) / Commercial (Enterprise)"
__url__ = "https://github.com/your-username/fastapi-guard"

# Core exports for simple usage
from fastapi_fortify.middleware.security import SecurityMiddleware
from fastapi_fortify.config.settings import SecurityConfig

# Convenience imports for common use cases
# from fastapi_fortify.middleware.security import (
#     create_security_middleware,
#     SecurityEnvironment
# )

# Configuration presets
from fastapi_fortify.config.presets import (
    DevelopmentConfig,
    ProductionConfig, 
    HighSecurityConfig
)

# Management and monitoring
from fastapi_fortify.api.management import SecurityAPI, create_security_api
from fastapi_fortify.monitoring.metrics import SecurityMetrics
from fastapi_fortify.monitoring import (
    AuthMonitor,
    create_auth_monitor,
    WebhookProcessor
)

# Utilities
from fastapi_fortify.utils.decorators import (
    require_auth,
    rate_limit,
    block_bots
)

# Version info
def get_version_info():
    """Get detailed version information"""
    return {
        "version": __version__,
        "author": __author__,
        "license": __license__,
        "github_url": __url__
    }

# All public exports
__all__ = [
    # Core components
    "SecurityMiddleware", 
    "SecurityConfig",
    # "create_security_middleware",
    # "SecurityEnvironment",
    
    # Configuration presets
    "DevelopmentConfig",
    "ProductionConfig", 
    "HighSecurityConfig",
    
    # Management and monitoring
    "SecurityAPI",
    "create_security_api",
    "SecurityMetrics",
    "AuthMonitor",
    "create_auth_monitor",
    "WebhookProcessor",
    
    # Utilities
    "require_auth",
    "rate_limit", 
    "block_bots",
    
    # Version
    "get_version_info",
    "__version__"
]