# Configuration Guide

FastAPI Guard provides flexible configuration options to suit different environments and security requirements.

## Configuration Methods

### 1. Default Configuration

Zero configuration setup:

```python
from fastapi import FastAPI
from fastapi_fortify import SecurityMiddleware

app = FastAPI()
app.add_middleware(SecurityMiddleware)  # Uses defaults
```

### 2. Custom Configuration

```python
from fastapi_fortify import SecurityMiddleware, SecurityConfig

config = SecurityConfig(
    waf_enabled=True,
    waf_mode="strict",
    rate_limiting_enabled=True,
    rate_limit_requests=100,
    rate_limit_window=3600
)

app.add_middleware(SecurityMiddleware, config=config)
```

### 3. Environment Presets

```python
from fastapi_fortify.config.presets import (
    DevelopmentConfig,
    ProductionConfig,
    HighSecurityConfig
)

# Choose based on environment
config = ProductionConfig()
app.add_middleware(SecurityMiddleware, config=config)
```

## Configuration Options

### Core Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | bool | `True` | Enable/disable all security features |
| `fail_open` | bool | `True` | Allow requests when components fail |
| `excluded_paths` | List[str] | `[]` | Paths to exclude from security checks |
| `debug_mode` | bool | `False` | Enable detailed logging |

### WAF Protection

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `waf_enabled` | bool | `True` | Enable Web Application Firewall |
| `waf_mode` | str | `"balanced"` | Mode: `strict`, `balanced`, `permissive` |
| `custom_waf_patterns` | List[str] | `[]` | Custom threat patterns |
| `waf_exclusions` | List[str] | `[]` | Paths excluded from WAF |
| `block_sql_injection` | bool | `True` | Block SQL injection attempts |
| `block_xss` | bool | `True` | Block XSS attempts |
| `block_path_traversal` | bool | `True` | Block path traversal |
| `block_command_injection` | bool | `True` | Block command injection |

### Bot Detection

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `bot_detection_enabled` | bool | `True` | Enable bot detection |
| `bot_detection_mode` | str | `"balanced"` | Detection sensitivity |
| `allow_search_engines` | bool | `True` | Allow legitimate search bots |
| `custom_bot_patterns` | List[str] | `[]` | Custom bot signatures |
| `bot_challenge_enabled` | bool | `False` | Enable bot challenges |
| `track_user_behavior` | bool | `True` | Analyze user behavior patterns |

### Rate Limiting

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `rate_limiting_enabled` | bool | `True` | Enable rate limiting |
| `rate_limit_requests` | int | `1000` | Requests per window |
| `rate_limit_window` | int | `3600` | Window size in seconds |
| `rate_limiter_backend` | str | `"memory"` | Backend: `memory`, `redis` |
| `rate_limit_per_endpoint` | Dict | `{}` | Per-endpoint limits |
| `rate_limit_burst` | int | `50` | Burst capacity |
| `redis_url` | str | `None` | Redis connection URL |

### IP Blocklist

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `ip_blocklist_enabled` | bool | `True` | Enable IP blocking |
| `ip_whitelist` | List[str] | `[]` | Always allowed IPs/CIDRs |
| `ip_blacklist` | List[str] | `[]` | Always blocked IPs/CIDRs |
| `block_private_networks` | bool | `False` | Block private IP ranges |
| `threat_intelligence_enabled` | bool | `True` | Use threat feeds |
| `threat_feeds` | List[str] | `[...]` | Threat intelligence sources |
| `max_block_duration` | int | `86400` | Max block time (seconds) |

### Authentication Monitoring

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `auth_monitoring_enabled` | bool | `True` | Monitor auth events |
| `failed_login_threshold` | int | `5` | Failed attempts threshold |
| `failed_login_window` | int | `900` | Window for failed attempts |
| `brute_force_protection` | bool | `True` | Enable brute force protection |
| `webhook_notifications` | List[str] | `[]` | Notification webhooks |
| `notification_severity` | str | `"medium"` | Minimum alert severity |

## Configuration Presets

### Development Configuration

```python
from fastapi_fortify.config.presets import DevelopmentConfig

config = DevelopmentConfig()
# Features:
# - Permissive settings
# - Detailed logging
# - No external dependencies
# - Fast startup
```

### Production Configuration

```python
from fastapi_fortify.config.presets import ProductionConfig

config = ProductionConfig()
# Features:
# - Balanced security
# - Performance optimized
# - Redis recommended
# - Comprehensive logging
```

### High Security Configuration

```python
from fastapi_fortify.config.presets import HighSecurityConfig

config = HighSecurityConfig()
# Features:
# - Maximum protection
# - Strict thresholds
# - All features enabled
# - Enhanced monitoring
```

## Environment Variables

Configure via environment variables:

```bash
# Core settings
FASTAPI_GUARD_ENABLED=true
FASTAPI_GUARD_DEBUG=false

# WAF settings
FASTAPI_GUARD_WAF_MODE=strict
FASTAPI_GUARD_WAF_ENABLED=true

# Rate limiting
FASTAPI_GUARD_RATE_LIMIT_REQUESTS=500
FASTAPI_GUARD_RATE_LIMIT_WINDOW=3600
FASTAPI_GUARD_REDIS_URL=redis://localhost:6379/1

# IP management
FASTAPI_GUARD_THREAT_INTEL=true
FASTAPI_GUARD_BLOCK_PRIVATE=false

# Auth monitoring
FASTAPI_GUARD_AUTH_THRESHOLD=3
FASTAPI_GUARD_WEBHOOK_URL=https://hooks.slack.com/...
```

Load from environment:

```python
from fastapi_fortify import SecurityConfig

config = SecurityConfig.from_env()
app.add_middleware(SecurityMiddleware, config=config)
```

## Per-Endpoint Configuration

### Rate Limiting Per Endpoint

```python
config = SecurityConfig(
    rate_limit_per_endpoint={
        "POST /api/login": {"requests": 10, "window": 300},
        "GET /api/data": {"requests": 1000, "window": 3600},
        "POST /api/upload": {"requests": 5, "window": 300}
    }
)
```

### WAF Exclusions

```python
config = SecurityConfig(
    waf_exclusions=[
        "/webhooks/*",        # Webhook endpoints
        "/api/raw-data",      # Raw data endpoints
        "/uploads/*"          # File upload paths
    ]
)
```

### Path-Specific Settings

```python
config = SecurityConfig(
    excluded_paths=[
        "/health",            # Health checks
        "/metrics",           # Monitoring
        "/docs",              # API documentation
        "/openapi.json"       # OpenAPI spec
    ]
)
```

## Advanced Configuration

### Custom Threat Patterns

```python
config = SecurityConfig(
    custom_waf_patterns=[
        r"(?i)(union|select).*from",           # SQL injection
        r"(?i)<script[^>]*>.*?</script>",      # XSS
        r"(?i)\.\.\/.*etc\/passwd",            # Path traversal
        r"(?i)company_specific_threat"         # Custom threat
    ]
)
```

### Custom Bot Detection

```python
config = SecurityConfig(
    custom_bot_patterns=[
        r"(?i)badbot/\d+\.\d+",              # Bad bot pattern
        r"(?i)scanner|crawler|spider",        # Generic crawlers
        r"(?i)company_internal_bot"           # Internal tools
    ],
    allow_search_engines=True,               # Still allow Google, Bing
    bot_challenge_enabled=True               # Enable challenges
)
```

### Notification Configuration

```python
config = SecurityConfig(
    webhook_notifications=[
        "https://hooks.slack.com/services/...",
        "https://api.company.com/security-alerts"
    ],
    notification_severity="high",            # Only high-severity alerts
    alert_rate_limit=10                      # Max 10 alerts/hour
)
```

## Configuration Validation

### Validate Configuration

```python
from fastapi_fortify import SecurityConfig
from fastapi_fortify.config.validation import validate_config

config = SecurityConfig(
    rate_limit_requests=1000,
    rate_limit_window=3600
)

# Validate before use
issues = validate_config(config)
if issues:
    for issue in issues:
        print(f"Warning: {issue}")
```

### Runtime Configuration Updates

```python
# Update configuration at runtime
middleware.update_config({
    "rate_limit_requests": 500,
    "waf_mode": "strict"
})

# Reload threat intelligence
await middleware.reload_threat_feeds()

# Update custom patterns
middleware.waf.add_custom_pattern(
    r"(?i)new_threat_pattern",
    "custom_threats"
)
```

## Best Practices

### Security Recommendations

1. **Start with ProductionConfig** for most applications
2. **Use HighSecurityConfig** for sensitive applications
3. **Enable Redis** for production rate limiting
4. **Whitelist known IPs** to reduce false positives
5. **Monitor alerts** and tune thresholds over time

### Performance Optimization

```python
config = SecurityConfig(
    # Disable expensive features for high-traffic endpoints
    bot_detection_enabled=False,    # For APIs
    threat_intelligence_enabled=False,  # Reduce latency
    
    # Optimize rate limiting
    rate_limiter_backend="redis",   # Better performance
    rate_limit_burst=100,           # Allow bursts
    
    # Optimize WAF
    waf_mode="balanced",           # Balance security/performance
    custom_waf_patterns=[]         # Avoid complex regex
)
```

### Development vs Production

| Feature | Development | Production |
|---------|-------------|------------|
| Debug Mode | `True` | `False` |
| WAF Mode | `permissive` | `balanced` |
| Rate Limits | High | Moderate |
| Threat Intel | `False` | `True` |
| Redis | Optional | Recommended |
| Logging | Verbose | Structured |

## Troubleshooting

### Common Issues

**Rate limiting too aggressive:**
```python
config.rate_limit_requests = 2000  # Increase limit
config.rate_limit_burst = 200      # Allow bursts
```

**False positive blocks:**
```python
config.ip_whitelist.append("192.168.1.0/24")  # Whitelist internal
config.waf_mode = "balanced"                   # Less strict WAF
```

**Performance issues:**
```python
config.bot_detection_enabled = False    # Disable for APIs
config.threat_intelligence_enabled = False  # Reduce lookups
```

**Redis connection errors:**
```python
config.rate_limiter_backend = "memory"  # Fallback to memory
```