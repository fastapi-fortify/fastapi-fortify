# Troubleshooting Guide

This guide helps diagnose and resolve common issues with FastAPI Guard.

## Common Issues

### Installation Problems

#### Issue: Package not found
```
ERROR: Could not find a version that satisfies the requirement fastapi-guard
```

**Solution:**
```bash
# Update pip first
pip install --upgrade pip

# Install from PyPI
pip install fastapi-guard

# Or install from source
pip install git+https://github.com/your-username/fastapi-guard.git
```

#### Issue: Dependency conflicts
```
ERROR: pip's dependency resolver does not currently consider all the dependencies
```

**Solution:**
```bash
# Create clean virtual environment
python -m venv fresh_env
source fresh_env/bin/activate  # Linux/Mac
# or
fresh_env\Scripts\activate     # Windows

# Install FastAPI Guard
pip install fastapi-guard
```

### Configuration Issues

#### Issue: Configuration not loading
```python
# Configuration seems to be ignored
config = SecurityConfig(waf_enabled=False)
app.add_middleware(SecurityMiddleware, config=config)
# WAF still running
```

**Diagnosis:**
```python
# Check if config is properly passed
@app.middleware("http")
async def debug_middleware(request, call_next):
    print(f"Config: {request.app.middleware_stack}")
    return await call_next(request)
```

**Solution:**
```python
# Ensure config is passed correctly
config = SecurityConfig(waf_enabled=False)
app.add_middleware(SecurityMiddleware, config=config)

# Or check configuration loading
config = SecurityConfig.from_env()
print(f"WAF enabled: {config.waf_enabled}")
```

#### Issue: Environment variables not recognized
```bash
export FASTAPI_GUARD_WAF_MODE=strict
# Configuration still shows 'balanced'
```

**Solution:**
```python
# Explicitly load from environment
config = SecurityConfig.from_env()

# Or check environment variable names
import os
print("Environment variables:")
for key, value in os.environ.items():
    if key.startswith("FASTAPI_GUARD"):
        print(f"{key}={value}")
```

### Performance Issues

#### Issue: High response times
```
Average response time increased from 50ms to 500ms
```

**Diagnosis:**
```python
import time
from fastapi_fortify.monitoring import PerformanceMonitor

@app.middleware("http")
async def timing_middleware(request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = time.time() - start
    print(f"Request took {duration:.3f}s")
    return response
```

**Solutions:**

1. **Optimize Configuration:**
```python
# Disable expensive features
config = SecurityConfig(
    bot_detection_enabled=False,    # Save 30ms+
    threat_intelligence_enabled=False,  # Save 20ms+
    waf_mode="permissive",         # Save 10ms+
    async_processing=True          # Use async
)
```

2. **Use Redis for Rate Limiting:**
```python
config = SecurityConfig(
    rate_limiter_backend="redis",
    redis_url="redis://localhost:6379/1"
)
```

3. **Optimize WAF Patterns:**
```python
# Avoid complex regex patterns
config = SecurityConfig(
    custom_waf_patterns=[
        # Good: simple, fast patterns
        r"(?i)\bunion\b.*\bselect\b",
        
        # Bad: complex, slow patterns
        # r"(a+)+b"  # Catastrophic backtracking
    ]
)
```

#### Issue: High memory usage
```
Memory usage growing from 100MB to 2GB over time
```

**Diagnosis:**
```python
import psutil
import gc

def check_memory():
    process = psutil.Process()
    print(f"Memory: {process.memory_info().rss / 1024 / 1024:.1f}MB")
    print(f"Objects: {len(gc.get_objects())}")
    
    # Force garbage collection
    collected = gc.collect()
    print(f"Collected: {collected} objects")
```

**Solutions:**

1. **Limit Cache Sizes:**
```python
config = SecurityConfig(
    waf_cache_size=1000,           # Limit WAF cache
    bot_cache_size=5000,           # Limit bot cache
    rate_limit_max_keys=10000,     # Limit rate limiter
    cache_cleanup_interval=300     # Clean every 5 minutes
)
```

2. **Enable Memory Management:**
```python
config = SecurityConfig(
    memory_monitoring=True,
    memory_alert_threshold=500,    # Alert at 500MB
    gc_enabled=True,
    gc_threshold=1000             # GC after 1000 requests
)
```

### Redis Issues

#### Issue: Redis connection failed
```
redis.exceptions.ConnectionError: Error 111 connecting to localhost:6379
```

**Diagnosis:**
```python
import redis

try:
    r = redis.Redis(host='localhost', port=6379, db=0)
    r.ping()
    print("Redis connected successfully")
except redis.ConnectionError as e:
    print(f"Redis connection failed: {e}")
```

**Solutions:**

1. **Check Redis Service:**
```bash
# Start Redis
redis-server

# Check Redis status
redis-cli ping
# Should return "PONG"
```

2. **Fallback to Memory:**
```python
config = SecurityConfig(
    rate_limiter_backend="memory",  # Fallback to memory
    # redis_url="redis://localhost:6379/1"  # Comment out
)
```

3. **Configure Redis URL:**
```python
# Different Redis configurations
configs = {
    "local": "redis://localhost:6379/1",
    "docker": "redis://redis:6379/1",
    "cloud": "redis://user:pass@host:port/db"
}

config = SecurityConfig(redis_url=configs["local"])
```

#### Issue: Redis performance problems
```
Redis operations taking 100ms+ per request
```

**Solutions:**

1. **Optimize Redis Configuration:**
```python
config = SecurityConfig(
    redis_pool_size=20,            # Connection pool
    redis_connection_timeout=1,     # Fast timeout
    redis_pipeline=True,           # Batch operations
    redis_compression=True         # Compress large data
)
```

2. **Use Redis Cluster:**
```python
# For high-scale deployments
config = SecurityConfig(
    redis_url="redis://redis-cluster-1:6379,redis-cluster-2:6379,redis-cluster-3:6379/1"
)
```

### WAF Issues

#### Issue: False positives blocking legitimate requests
```
Legitimate API calls being blocked by WAF
```

**Diagnosis:**
```python
# Enable WAF debugging
config = SecurityConfig(
    waf_enabled=True,
    debug_mode=True,              # Enable debug logging
    log_blocked_requests=True     # Log all blocked requests
)

# Check logs for blocked patterns
import logging
logging.getLogger("fastapi_fortify.waf").setLevel(logging.DEBUG)
```

**Solutions:**

1. **Adjust WAF Mode:**
```python
config = SecurityConfig(
    waf_mode="permissive",        # Less strict
    # waf_mode="balanced",        # Default
    # waf_mode="strict",          # Most strict
)
```

2. **Add Path Exclusions:**
```python
config = SecurityConfig(
    waf_exclusions=[
        "/api/webhooks/*",         # Webhook endpoints
        "/api/upload",             # File uploads
        "/api/raw-data"            # Raw data endpoints
    ]
)
```

3. **Whitelist Specific IPs:**
```python
config = SecurityConfig(
    ip_whitelist=[
        "192.168.1.0/24",          # Internal network
        "trusted.partner.com",      # Partner API
        "10.0.0.100"               # Specific trusted IP
    ]
)
```

#### Issue: WAF not blocking obvious attacks
```
SQL injection attempts passing through WAF
```

**Diagnosis:**
```python
# Test WAF patterns
from fastapi_fortify.protection.waf import WAFProtection

waf = WAFProtection(mode="strict")

test_payloads = [
    "' OR 1=1 --",
    "<script>alert('xss')</script>",
    "../../../etc/passwd"
]

for payload in test_payloads:
    result = waf.analyze_request_content(payload)
    print(f"Payload: {payload}")
    print(f"Blocked: {not result.allowed}")
    print(f"Reason: {result.reason}")
    print("---")
```

**Solutions:**

1. **Use Stricter Mode:**
```python
config = SecurityConfig(
    waf_mode="strict",             # Most strict mode
    block_sql_injection=True,
    block_xss=True,
    block_path_traversal=True
)
```

2. **Add Custom Patterns:**
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

### Rate Limiting Issues

#### Issue: Rate limiting too aggressive
```
Legitimate users being rate limited
```

**Solutions:**

1. **Increase Rate Limits:**
```python
config = SecurityConfig(
    rate_limit_requests=2000,      # Increase from 1000
    rate_limit_window=3600,        # Keep 1 hour window
    rate_limit_burst=200          # Allow burst traffic
)
```

2. **Per-Endpoint Configuration:**
```python
config = SecurityConfig(
    rate_limit_per_endpoint={
        "GET /api/public": {"requests": 10000, "window": 3600},
        "POST /api/auth": {"requests": 10, "window": 300},
        "GET /api/user": {"requests": 1000, "window": 3600}
    }
)
```

3. **User-Based Rate Limiting:**
```python
from fastapi_fortify.utils.decorators import rate_limit

@rate_limit(
    requests=1000,
    window_seconds=3600,
    key_func=lambda req: f"user:{get_user_id(req)}"
)
async def user_endpoint(request: Request):
    return {"data": "user-specific"}
```

#### Issue: Rate limiting not working
```
No rate limiting being applied despite configuration
```

**Diagnosis:**
```python
# Check rate limiter status
@app.get("/debug/rate-limiter")
async def debug_rate_limiter(request: Request):
    limiter = app.state.security_middleware.rate_limiter
    stats = await limiter.get_stats()
    return {"stats": stats, "enabled": limiter is not None}
```

**Solutions:**

1. **Verify Configuration:**
```python
config = SecurityConfig(
    rate_limiting_enabled=True,    # Must be True
    rate_limit_requests=100,
    rate_limit_window=3600
)

# Check if properly initialized
print(f"Rate limiting enabled: {config.rate_limiting_enabled}")
```

2. **Check Backend:**
```python
# Try different backends
config = SecurityConfig(
    rate_limiter_backend="memory",  # Try memory first
    # rate_limiter_backend="redis",  # Then try Redis
)
```

### Bot Detection Issues

#### Issue: Search engines being blocked
```
Google, Bing crawlers being blocked despite allow_search_engines=True
```

**Solutions:**

1. **Verify Search Engine Patterns:**
```python
config = SecurityConfig(
    allow_search_engines=True,
    custom_bot_allowlist=[
        r"(?i)googlebot",
        r"(?i)bingbot",
        r"(?i)slackbot",
        r"(?i)facebookexternalhit"
    ]
)
```

2. **Whitelist Search Engine IPs:**
```python
# Google bot IP ranges
config = SecurityConfig(
    ip_whitelist=[
        "66.249.64.0/19",          # Google
        "40.77.167.0/24",          # Bing
        "72.14.192.0/18"           # Google additional
    ]
)
```

#### Issue: Bots not being detected
```
Obvious bot traffic passing through detection
```

**Solutions:**

1. **Use Stricter Mode:**
```python
config = SecurityConfig(
    bot_detection_mode="strict",   # More aggressive
    track_user_behavior=True,      # Enable behavioral analysis
    bot_challenge_enabled=True     # Enable challenges
)
```

2. **Add Custom Patterns:**
```python
config = SecurityConfig(
    custom_bot_patterns=[
        r"(?i)(scrapy|beautifulsoup|mechanize)",
        r"(?i)(wget|curl)\/\d+",
        r"(?i)bot.*\d+\.\d+"
    ]
)
```

### Authentication Monitoring Issues

#### Issue: Failed login alerts not firing
```
Multiple failed logins but no alerts generated
```

**Diagnosis:**
```python
# Check auth monitor status
auth_monitor = app.state.security_middleware.auth_monitor
if auth_monitor:
    stats = auth_monitor.stats
    print(f"Events processed: {stats.get('events_processed', 0)}")
    print(f"Alerts generated: {stats.get('alerts_generated', 0)}")
```

**Solutions:**

1. **Verify Configuration:**
```python
config = SecurityConfig(
    auth_monitoring_enabled=True,
    failed_login_threshold=3,      # Lower threshold
    failed_login_window=300,       # 5 minute window
    brute_force_protection=True
)
```

2. **Check Notification Setup:**
```python
from fastapi_fortify.monitoring.auth_monitor import create_auth_monitor

auth_monitor = create_auth_monitor(
    security_level="high",
    notifications=["webhook", "email"],
    webhook_url="https://company.com/alerts",
    email_recipients=["security@company.com"]
)
```

3. **Process Login Events:**
```python
@app.post("/auth/login")
async def login(request: LoginRequest):
    success = authenticate_user(request.email, request.password)
    
    # Always process login attempt
    await auth_monitor.process_login_attempt(
        email=request.email,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        success=success
    )
    
    return {"success": success}
```

### Management API Issues

#### Issue: Management API endpoints returning 404
```
GET /security/status returns 404 Not Found
```

**Solutions:**

1. **Ensure API is Added:**
```python
from fastapi_fortify.api.management import create_security_api

# Create and add security API
security_api = create_security_api(
    middleware_instance=middleware,
    require_auth=False  # For testing
)
app.include_router(security_api.router)
```

2. **Check Prefix:**
```python
# API might be at different prefix
security_api = create_security_api(prefix="/admin/security")
# Endpoints will be at /admin/security/status
```

#### Issue: Management API authentication failing
```
401 Unauthorized despite correct API key
```

**Solutions:**

1. **Check API Key:**
```python
security_api = create_security_api(
    api_key="your-secret-key",
    require_auth=True
)

# Make request with correct header
headers = {"Authorization": "Bearer your-secret-key"}
response = requests.get("/security/status", headers=headers)
```

2. **Disable Auth for Testing:**
```python
security_api = create_security_api(
    require_auth=False  # Temporarily disable auth
)
```

### Logging and Debugging

#### Issue: No security logs appearing
```
Security events not being logged despite debug_mode=True
```

**Solutions:**

1. **Configure Logging:**
```python
import logging

# Configure FastAPI Guard logging
logging.getLogger("fastapi_fortify").setLevel(logging.DEBUG)
logging.getLogger("fastapi_fortify.waf").setLevel(logging.DEBUG)
logging.getLogger("fastapi_fortify.bot_detection").setLevel(logging.DEBUG)

# Add console handler
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
logging.getLogger("fastapi_fortify").addHandler(handler)
```

2. **Enable Debug Mode:**
```python
config = SecurityConfig(
    debug_mode=True,
    log_blocked_requests=True,
    log_all_requests=False,        # Only for debugging
    log_level="DEBUG"
)
```

#### Issue: Too many log messages
```
Log files growing rapidly with security messages
```

**Solutions:**

1. **Adjust Log Level:**
```python
config = SecurityConfig(
    debug_mode=False,              # Disable debug
    log_level="WARNING",           # Only warnings and errors
    log_blocked_requests=False     # Don't log every block
)
```

2. **Configure Log Rotation:**
```python
import logging.handlers

# Set up rotating log handler
handler = logging.handlers.RotatingFileHandler(
    "security.log",
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
logging.getLogger("fastapi_fortify").addHandler(handler)
```

## Getting Help

### Diagnostic Information

When reporting issues, include this diagnostic information:

```python
import fastapi_fortify
import sys
import os

def get_diagnostic_info():
    return {
        "fastapi_fortify_version": fastapi_fortify.__version__,
        "python_version": sys.version,
        "platform": sys.platform,
        "environment_variables": {
            k: v for k, v in os.environ.items() 
            if k.startswith("FASTAPI_GUARD")
        },
        "config": config.dict() if 'config' in locals() else "Not available"
    }

print(get_diagnostic_info())
```

### Health Check Endpoint

Add a health check to verify FastAPI Guard status:

```python
@app.get("/health/security")
async def security_health():
    middleware = app.state.security_middleware
    
    return {
        "status": "healthy" if middleware else "error",
        "components": {
            "waf": "healthy" if middleware.waf else "disabled",
            "rate_limiter": "healthy" if middleware.rate_limiter else "disabled",
            "bot_detector": "healthy" if middleware.bot_detector else "disabled",
            "ip_blocklist": "healthy" if middleware.ip_blocklist else "disabled",
            "auth_monitor": "healthy" if middleware.auth_monitor else "disabled"
        },
        "stats": middleware.get_stats() if middleware else {}
    }
```

### Support Channels

- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: Comprehensive guides and API reference
- **Community Forum**: Ask questions and share solutions
- **Security Issues**: Report security vulnerabilities privately

This troubleshooting guide covers the most common issues encountered when using FastAPI Guard. For issues not covered here, please check the GitHub issues or create a new issue with diagnostic information.