# API Reference

Complete API reference for FastAPI Guard classes, functions, and configuration options.

## Core Components

### SecurityMiddleware

The main security middleware class that orchestrates all security components.

```python
class SecurityMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        config: SecurityConfig = None,
        *,
        fail_open: bool = True,
        debug: bool = False
    )
```

**Parameters:**
- `app` (ASGIApp): The ASGI application to wrap
- `config` (SecurityConfig, optional): Security configuration
- `fail_open` (bool): Allow requests when components fail (default: True)
- `debug` (bool): Enable debug logging (default: False)

**Methods:**

#### `update_config(config_updates: Dict[str, Any]) -> None`
Update configuration at runtime.

#### `get_stats() -> Dict[str, Any]`
Get security statistics and metrics.

#### `reload_threat_feeds() -> None`
Reload threat intelligence feeds.

**Example:**
```python
from fastapi import FastAPI
from fastapi_fortify import SecurityMiddleware, SecurityConfig

app = FastAPI()
config = SecurityConfig(waf_enabled=True)
app.add_middleware(SecurityMiddleware, config=config)
```

---

### SecurityConfig

Configuration class for all security settings.

```python
class SecurityConfig(BaseSettings):
    # Core settings
    enabled: bool = True
    fail_open: bool = True
    excluded_paths: List[str] = []
    debug_mode: bool = False
    
    # WAF settings
    waf_enabled: bool = True
    waf_mode: str = "balanced"  # strict, balanced, permissive
    custom_waf_patterns: List[str] = []
    
    # Rate limiting
    rate_limiting_enabled: bool = True
    rate_limit_requests: int = 1000
    rate_limit_window: int = 3600
    
    # More settings...
```

**Class Methods:**

#### `from_env() -> SecurityConfig`
Create configuration from environment variables.

#### `from_file(file_path: str) -> SecurityConfig`
Load configuration from JSON/YAML file.

**Example:**
```python
# From environment
config = SecurityConfig.from_env()

# From file
config = SecurityConfig.from_file("security_config.json")

# Direct initialization
config = SecurityConfig(
    waf_enabled=True,
    rate_limit_requests=500,
    bot_detection_enabled=False
)
```

---

## WAF Protection

### WAFProtection

Web Application Firewall implementation.

```python
class WAFProtection:
    def __init__(
        self,
        mode: str = "balanced",
        custom_patterns: List[str] = None,
        exclusions: List[str] = None
    )
```

**Methods:**

#### `analyze_request(request: Request) -> SecurityDecision`
Analyze incoming request for threats.

#### `analyze_request_content(content: str) -> SecurityDecision`
Analyze request content for malicious patterns.

#### `add_custom_pattern(pattern: str, category: str) -> bool`
Add custom threat detection pattern.

#### `remove_pattern(pattern_id: str) -> bool`
Remove threat detection pattern.

#### `get_pattern_stats() -> Dict[str, int]`
Get statistics for pattern matches.

**Example:**
```python
from fastapi_fortify.protection.waf import WAFProtection

waf = WAFProtection(
    mode="strict",
    custom_patterns=[r"(?i)malicious_pattern"],
    exclusions=["/webhooks/*"]
)

# Analyze request
decision = waf.analyze_request(request)
if not decision.allowed:
    return HTTPException(403, decision.reason)
```

---

## Bot Detection

### BotDetector

Advanced bot detection system.

```python
class BotDetector:
    def __init__(
        self,
        mode: str = "balanced",
        allow_search_engines: bool = True,
        custom_patterns: List[str] = None
    )
```

**Methods:**

#### `analyze_request(request: Request) -> SecurityDecision`
Analyze request for bot behavior.

#### `is_bot(user_agent: str, ip: str = None) -> bool`
Quick bot check based on user agent.

#### `track_behavior(request: Request) -> None`
Track user behavior patterns.

#### `get_detection_stats() -> Dict[str, Any]`
Get bot detection statistics.

**Example:**
```python
from fastapi_fortify.protection.bot_detection import BotDetector

detector = BotDetector(
    mode="strict",
    allow_search_engines=True,
    custom_patterns=[r"(?i)badbot"]
)

if detector.is_bot(request.headers.get("user-agent")):
    return HTTPException(403, "Bot access denied")
```

---

## Rate Limiting

### Rate Limiter Classes

#### MemoryRateLimiter

In-memory rate limiter implementation.

```python
class MemoryRateLimiter:
    def __init__(
        self,
        cleanup_interval: int = 300,
        max_keys: int = 100000
    )
```

#### RedisRateLimiter

Redis-based distributed rate limiter.

```python
class RedisRateLimiter:
    def __init__(
        self,
        redis_url: str,
        key_prefix: str = "rl:",
        pool_size: int = 10
    )
```

#### SlidingWindowRateLimiter

Sliding window rate limiter implementation.

```python
class SlidingWindowRateLimiter:
    def __init__(
        self,
        window_size: int = 3600,
        precision: int = 60
    )
```

**Common Methods:**

#### `is_allowed(key: str, limit: int, window: int) -> bool`
Check if request is within rate limit.

#### `get_stats(key: str = None) -> Dict[str, Any]`
Get rate limiting statistics.

#### `reset(key: str) -> None`
Reset rate limit for specific key.

**Example:**
```python
from fastapi_fortify.middleware.rate_limiter import RedisRateLimiter

limiter = RedisRateLimiter(redis_url="redis://localhost:6379/1")

if not await limiter.is_allowed("user:123", 100, 3600):
    return HTTPException(429, "Rate limit exceeded")
```

---

## IP Management

### IPBlocklist

IP blocklist management system.

```python
class IPBlocklist:
    def __init__(
        self,
        static_blocks: List[str] = None,
        whitelist: List[str] = None,
        threat_feeds: List[str] = None
    )
```

**Methods:**

#### `is_blocked(ip: str) -> Tuple[bool, str]`
Check if IP is blocked and return reason.

#### `add_block(ip: str, reason: str, duration: int = None) -> None`
Add IP to blocklist.

#### `remove_block(ip: str) -> bool`
Remove IP from blocklist.

#### `add_to_whitelist(ip: str) -> None`
Add IP to whitelist.

#### `get_stats() -> Dict[str, Any]`
Get blocklist statistics.

#### `update_threat_feeds() -> None`
Update threat intelligence feeds.

**Example:**
```python
from fastapi_fortify.protection.ip_blocklist import IPBlocklist

blocklist = IPBlocklist(
    whitelist=["192.168.1.0/24"],
    threat_feeds=["https://example.com/threat-feed.txt"]
)

is_blocked, reason = blocklist.is_blocked("192.168.1.100")
if is_blocked:
    return HTTPException(403, f"IP blocked: {reason}")
```

---

## Authentication Monitoring

### AuthMonitor

Authentication event monitoring system.

```python
class AuthMonitor:
    def __init__(
        self,
        failed_login_threshold: int = 5,
        time_window: int = 900,
        notification_handlers: List[NotificationHandler] = None
    )
```

**Methods:**

#### `process_login_attempt(email: str, ip: str, user_agent: str, success: bool, **kwargs) -> None`
Process login attempt and check for threats.

#### `process_webhook(webhook_data: Dict[str, Any]) -> None`
Process authentication webhook (e.g., from Clerk).

#### `get_security_summary(hours: int = 24) -> Dict[str, Any]`
Get authentication security summary.

#### `is_brute_force_attack(identifier: str) -> bool`
Check if requests indicate brute force attack.

**Example:**
```python
from fastapi_fortify.monitoring.auth_monitor import create_auth_monitor

auth_monitor = create_auth_monitor(
    security_level="high",
    notifications=["webhook"],
    webhook_url="https://company.com/security-alerts"
)

await auth_monitor.process_login_attempt(
    email="user@example.com",
    ip="192.168.1.100",
    user_agent="Mozilla/5.0...",
    success=False
)
```

---

## Management API

### SecurityAPI

REST API for security management.

```python
class SecurityAPI:
    def __init__(
        self,
        middleware_instance: SecurityMiddleware = None,
        *,
        enabled: bool = True,
        prefix: str = "/security",
        require_auth: bool = True,
        api_key: str = None
    )
```

**Factory Function:**

#### `create_security_api(**kwargs) -> SecurityAPI`
Create security API instance.

**Available Endpoints:**

- `GET /security/health` - Health check
- `GET /security/status` - Overall security status
- `GET /security/waf/status` - WAF status
- `GET /security/rate-limits/status` - Rate limit status
- `GET /security/ip-blocklist/status` - IP blocklist status
- `GET /security/bot-detection/status` - Bot detection status
- `GET /security/auth/status` - Auth monitoring status
- `POST /security/ip-blocklist/block` - Block IP address
- `POST /security/ip-blocklist/unblock` - Unblock IP address
- `GET /security/ip-blocklist/{ip}` - Get IP status
- `POST /security/waf/patterns` - Add WAF pattern
- `GET /security/threats/summary` - Threat summary
- `GET /security/metrics` - Security metrics

**Example:**
```python
from fastapi_fortify.api.management import create_security_api

security_api = create_security_api(
    middleware_instance=middleware,
    api_key="your-secret-key",
    require_auth=True
)

app.include_router(security_api.router)
```

---

## Utility Functions

### IP Utilities

```python
from fastapi_fortify.utils.ip_utils import (
    get_client_ip,
    is_valid_ip,
    is_valid_cidr,
    ip_in_network,
    ip_matches_patterns,
    is_private_ip,
    is_public_ip,
    normalize_ip_list
)
```

#### `get_client_ip(request: Request) -> str`
Extract client IP from request headers.

#### `is_valid_ip(ip: str) -> bool`
Validate IP address format.

#### `ip_in_network(ip: str, network: str) -> bool`
Check if IP is in CIDR network.

### Security Decision

```python
from fastapi_fortify.utils.security_utils import SecurityDecision

class SecurityDecision:
    allowed: bool
    reason: str
    rule_type: str
    confidence: float
    metadata: Dict[str, Any]
    
    @classmethod
    def allow(cls, reason: str, **kwargs) -> 'SecurityDecision'
    
    @classmethod
    def block(cls, reason: str, **kwargs) -> 'SecurityDecision'
```

---

## Decorators

### Authentication Decorators

```python
from fastapi_fortify.utils.decorators import (
    require_auth,
    rate_limit,
    block_bots,
    security_headers,
    log_security_event,
    validate_input
)
```

#### `@require_auth(auth_func=None, error_message="Unauthorized")`
Require authentication for endpoint.

#### `@rate_limit(requests: int, window_seconds: int, key_func=None, limiter=None)`
Apply rate limiting to endpoint.

#### `@block_bots(mode="balanced", allow_search_engines=True)`
Block bots from accessing endpoint.

#### `@security_headers(**headers)`
Add security headers to response.

#### `@log_security_event(event_type: str, severity="medium")`
Log security events for endpoint.

#### `@validate_input(max_length=None, allowed_content_types=None)`
Validate request input.

**Example:**
```python
from fastapi_fortify.utils.decorators import require_auth, rate_limit

@require_auth()
@rate_limit(requests=10, window_seconds=60)
@app.post("/api/sensitive")
async def sensitive_endpoint(request: Request):
    return {"data": "sensitive"}
```

---

## Configuration Presets

### Available Presets

```python
from fastapi_fortify.config.presets import (
    DevelopmentConfig,
    ProductionConfig,
    HighSecurityConfig
)
```

#### `DevelopmentConfig()`
Optimized for development with permissive settings.

#### `ProductionConfig()`
Balanced security and performance for production.

#### `HighSecurityConfig()`
Maximum security for sensitive applications.

**Example:**
```python
from fastapi_fortify.config.presets import ProductionConfig

config = ProductionConfig()
config.excluded_paths = ["/health", "/metrics"]
app.add_middleware(SecurityMiddleware, config=config)
```

---

## Data Models

### Request/Response Models

```python
from fastapi_fortify.api.models import (
    SecurityStatus,
    HealthCheckResponse,
    ThreatSummary,
    IPBlockRequest,
    IPUnblockRequest,
    CustomPatternRequest
)
```

#### `IPBlockRequest`
```python
class IPBlockRequest(BaseModel):
    ip_address: str
    reason: str
    duration_hours: Optional[int] = None
    severity: str = "medium"
```

#### `ThreatSummary`
```python
class ThreatSummary(BaseModel):
    period_hours: int
    total_threats: int
    threat_types: Dict[str, int]
    top_sources: List[Dict[str, Any]]
    trend: str
```

---

## Error Handling

### Custom Exceptions

```python
from fastapi_fortify.exceptions import (
    SecurityError,
    WAFError,
    RateLimitError,
    BotDetectionError,
    ConfigurationError
)
```

#### `SecurityError`
Base security exception class.

#### `WAFError`
WAF-specific errors.

#### `RateLimitError`
Rate limiting errors.

**Example:**
```python
from fastapi_fortify.exceptions import SecurityError

try:
    waf.analyze_request(request)
except SecurityError as e:
    logger.error(f"Security error: {e}")
    return HTTPException(500, "Security check failed")
```

---

## Environment Variables

### Configuration via Environment

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `FASTAPI_GUARD_ENABLED` | bool | `true` | Enable/disable security |
| `FASTAPI_GUARD_DEBUG` | bool | `false` | Debug mode |
| `FASTAPI_GUARD_WAF_MODE` | str | `balanced` | WAF mode |
| `FASTAPI_GUARD_RATE_LIMIT_REQUESTS` | int | `1000` | Rate limit |
| `FASTAPI_GUARD_REDIS_URL` | str | `None` | Redis URL |
| `FASTAPI_GUARD_API_KEY` | str | `None` | Management API key |

**Example:**
```bash
export FASTAPI_GUARD_WAF_MODE=strict
export FASTAPI_GUARD_RATE_LIMIT_REQUESTS=500
export FASTAPI_GUARD_REDIS_URL=redis://localhost:6379/1
```

---

## Type Hints

### Common Types

```python
from typing import Dict, List, Optional, Union, Callable, Any
from fastapi import Request, Response
from starlette.types import ASGIApp

# Custom types
SecurityDecisionType = Union[SecurityDecision, bool]
ConfigValue = Union[str, int, bool, List[str], Dict[str, Any]]
NotificationHandler = Callable[[Dict[str, Any]], None]
```

This API reference provides comprehensive documentation for all public classes, methods, and functions in FastAPI Guard.