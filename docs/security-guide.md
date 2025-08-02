# Security Best Practices

This guide covers security best practices when using FastAPI Guard and general web application security principles.

## Security Architecture

### Defense in Depth

FastAPI Guard implements multiple security layers:

1. **Network Layer**: IP blocking, rate limiting
2. **Application Layer**: WAF protection, input validation  
3. **Authentication Layer**: Login monitoring, brute force protection
4. **Behavioral Layer**: Bot detection, anomaly detection

### Security Components

```python
from fastapi_fortify import SecurityMiddleware, SecurityConfig

config = SecurityConfig(
    # Layer 1: Network security
    ip_blocklist_enabled=True,
    rate_limiting_enabled=True,
    
    # Layer 2: Application security
    waf_enabled=True,
    input_validation=True,
    
    # Layer 3: Authentication security
    auth_monitoring_enabled=True,
    brute_force_protection=True,
    
    # Layer 4: Behavioral security
    bot_detection_enabled=True,
    anomaly_detection=True
)
```

## Web Application Firewall (WAF)

### OWASP Top 10 Protection

FastAPI Guard protects against OWASP Top 10 vulnerabilities:

#### 1. Injection Attacks

```python
# SQL Injection protection
config = SecurityConfig(
    waf_enabled=True,
    block_sql_injection=True,
    custom_waf_patterns=[
        r"(?i)(union|select).*from",
        r"(?i)(insert|update|delete).*where",
        r"(?i)(drop|create|alter).*table"
    ]
)
```

#### 2. Cross-Site Scripting (XSS)

```python
# XSS protection
config = SecurityConfig(
    block_xss=True,
    custom_waf_patterns=[
        r"(?i)<script[^>]*>.*?</script>",
        r"(?i)javascript:",
        r"(?i)on\w+\s*=",
        r"(?i)expression\s*\("
    ]
)
```

#### 3. Path Traversal

```python
# Directory traversal protection
config = SecurityConfig(
    block_path_traversal=True,
    custom_waf_patterns=[
        r"\.\.\/",
        r"\.\.\\",
        r"\/etc\/passwd",
        r"\\windows\\system32"
    ]
)
```

#### 4. Command Injection

```python
# Command injection protection
config = SecurityConfig(
    block_command_injection=True,
    custom_waf_patterns=[
        r"(?i)(;|\||&|\$\(|`)",
        r"(?i)(rm|cat|ls|ps|id|whoami)",
        r"(?i)(exec|eval|system)"
    ]
)
```

### Custom WAF Rules

Create application-specific rules:

```python
# E-commerce specific rules
ecommerce_patterns = [
    r"(?i)creditcard\d{13,19}",          # Credit card patterns
    r"(?i)\b\d{3}-\d{2}-\d{4}\b",        # SSN patterns
    r"(?i)(admin|administrator)\/",       # Admin path probing
    r"(?i)\.bak$|\.backup$|\.old$"       # Backup file access
]

config = SecurityConfig(
    custom_waf_patterns=ecommerce_patterns
)
```

## Rate Limiting Strategy

### Tiered Rate Limiting

```python
config = SecurityConfig(
    rate_limit_per_endpoint={
        # Authentication endpoints - strict
        "POST /auth/login": {"requests": 5, "window": 300},
        "POST /auth/register": {"requests": 3, "window": 3600},
        "POST /auth/password-reset": {"requests": 2, "window": 3600},
        
        # API endpoints - moderate
        "GET /api/user/profile": {"requests": 100, "window": 3600},
        "POST /api/data": {"requests": 50, "window": 3600},
        
        # Public endpoints - generous
        "GET /api/public": {"requests": 1000, "window": 3600},
        "GET /health": {"requests": 10000, "window": 3600}
    }
)
```

### Rate Limiting by User Type

```python
from fastapi import Request
from fastapi_fortify.utils.decorators import rate_limit

@rate_limit(
    requests=1000,
    window_seconds=3600,
    key_func=lambda req: f"premium:{get_user_id(req)}"  # Premium users
)
async def premium_endpoint(request: Request):
    return {"data": "premium content"}

@rate_limit(
    requests=100,
    window_seconds=3600,
    key_func=lambda req: f"free:{get_user_id(req)}"     # Free users
)
async def free_endpoint(request: Request):
    return {"data": "free content"}
```

## IP Management

### Whitelist Strategy

```python
config = SecurityConfig(
    ip_whitelist=[
        # Office networks
        "192.168.1.0/24",
        "10.0.0.0/8",
        
        # Partner APIs
        "203.0.113.0/24",
        
        # CDN networks (if needed)
        "cloudflare_range/24",
        
        # Monitoring services
        "monitoring.company.com"  # Will resolve to IP
    ]
)
```

### Dynamic Blocking

```python
# Block based on threat intelligence
config = SecurityConfig(
    threat_intelligence_enabled=True,
    threat_feeds=[
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "https://www.spamhaus.org/drop/drop.txt",
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    ],
    
    # Auto-block repeat offenders
    auto_block_enabled=True,
    auto_block_threshold=10,     # 10 blocked requests
    auto_block_window=3600,      # Within 1 hour
    auto_block_duration=86400    # Block for 24 hours
)
```

## Bot Detection

### Legitimate Bot Allowlist

```python
config = SecurityConfig(
    allow_search_engines=True,
    custom_bot_allowlist=[
        r"(?i)googlebot",
        r"(?i)bingbot",
        r"(?i)slackbot",
        r"(?i)twitterbot",
        r"(?i)facebookexternalhit",
        r"(?i)linkedinbot",
        
        # Custom bots
        r"(?i)company-monitoring-bot",
        r"(?i)internal-health-checker"
    ]
)
```

### Malicious Bot Detection

```python
config = SecurityConfig(
    custom_bot_patterns=[
        # Known malicious bots
        r"(?i)(sqlmap|nikto|nmap|masscan)",
        r"(?i)(acunetix|netsparker|burp)",
        r"(?i)(dirb|dirbuster|gobuster)",
        
        # Scraping bots
        r"(?i)(scrapy|beautifulsoup|mechanize)",
        r"(?i)(wget|curl)\/\d+",
        
        # Generic suspicious patterns
        r"(?i)bot.*\d+\.\d+",
        r"(?i)(scan|crawl|spider).*bot"
    ]
)
```

## Authentication Security

### Monitoring Failed Logins

```python
from fastapi_fortify.monitoring import create_auth_monitor

auth_monitor = create_auth_monitor(
    security_level="high",
    
    # Thresholds
    failed_login_threshold=3,     # 3 failed attempts
    failed_login_window=300,      # Within 5 minutes
    account_lockout_duration=1800, # Lock for 30 minutes
    
    # Notifications
    notifications=["webhook", "email"],
    webhook_url="https://company.com/security-alerts",
    email_recipients=["security@company.com"]
)

# Process login attempts
@app.post("/auth/login")
async def login(request: LoginRequest):
    success = authenticate_user(request.email, request.password)
    
    # Always monitor login attempts
    await auth_monitor.process_login_attempt(
        email=request.email,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        success=success,
        additional_data={
            "timestamp": datetime.utcnow(),
            "endpoint": "/auth/login",
            "method": "POST"
        }
    )
    
    return {"success": success}
```

### Password Security

```python
# Enhanced password validation
from fastapi_fortify.utils.decorators import validate_input

@validate_input(
    password_min_length=12,
    password_complexity=True,
    check_common_passwords=True,
    check_breach_databases=True
)
@app.post("/auth/change-password")
async def change_password(request: PasswordChangeRequest):
    # Password already validated by decorator
    return await update_user_password(request)
```

## API Security

### Input Validation

```python
from fastapi_fortify.utils.decorators import validate_input
from pydantic import BaseModel, validator

class APIRequest(BaseModel):
    data: str
    
    @validator('data')
    def validate_data(cls, v):
        # Custom validation logic
        if len(v) > 10000:
            raise ValueError("Data too large")
        if any(char in v for char in ['<', '>', '"', "'"]):
            raise ValueError("Invalid characters")
        return v

@validate_input(
    max_length=10000,
    allowed_content_types=["application/json"],
    check_encoding=True
)
@app.post("/api/data")
async def process_data(request: APIRequest):
    return {"processed": True}
```

### Output Security

```python
from fastapi_fortify.utils.decorators import security_headers

@security_headers(
    csp="default-src 'self'; script-src 'self' 'unsafe-inline'",
    hsts=True,
    frame_options="DENY",
    content_type_options=True,
    xss_protection=True,
    referrer_policy="strict-origin-when-cross-origin"
)
@app.get("/api/sensitive-data")
async def get_sensitive_data():
    return {"data": "sensitive information"}
```

## Monitoring and Alerting

### Security Event Logging

```python
from fastapi_fortify.utils.decorators import log_security_event

@log_security_event(
    event_type="api_access",
    severity="medium",
    include_request_data=True,
    include_response_data=False  # Don't log sensitive responses
)
@app.get("/api/admin/users")
async def admin_get_users(request: Request):
    return await get_all_users()

@log_security_event(
    event_type="data_modification",
    severity="high",
    alert_immediately=True
)
@app.post("/api/admin/delete-user")
async def admin_delete_user(user_id: str):
    return await delete_user(user_id)
```

### Real-time Monitoring

```python
# Set up real-time security monitoring
from fastapi_fortify.monitoring.real_time import SecurityMonitor

monitor = SecurityMonitor(
    thresholds={
        "requests_per_second": 1000,
        "error_rate_percent": 5,
        "blocked_requests_percent": 10,
        "new_ips_per_minute": 50
    },
    
    alert_channels=[
        "slack://security-alerts",
        "email://security@company.com",
        "webhook://https://company.com/security-webhook"
    ]
)

# Add to FastAPI app
app.add_middleware(SecurityMonitor, monitor=monitor)
```

## Compliance and Standards

### OWASP Compliance

```python
# OWASP-compliant configuration
config = SecurityConfig(
    # A01: Broken Access Control
    auth_monitoring_enabled=True,
    
    # A02: Cryptographic Failures
    enforce_https=True,
    
    # A03: Injection
    waf_enabled=True,
    block_sql_injection=True,
    block_xss=True,
    
    # A04: Insecure Design
    rate_limiting_enabled=True,
    bot_detection_enabled=True,
    
    # A05: Security Misconfiguration
    security_headers=True,
    debug_mode=False,
    
    # A06: Vulnerable Components
    component_scanning=True,
    
    # A07: Authentication Failures
    brute_force_protection=True,
    password_policy_enforcement=True,
    
    # A08: Software Integrity Failures
    integrity_checks=True,
    
    # A09: Logging Failures
    comprehensive_logging=True,
    log_retention_days=90,
    
    # A10: SSRF
    request_validation=True,
    url_filtering=True
)
```

### PCI DSS Considerations

```python
# For applications handling payment data
config = SecurityConfig(
    # Encrypt all data transmission
    enforce_https_only=True,
    ssl_redirect=True,
    
    # Strong access controls
    ip_whitelist=["trusted.payment.networks"],
    auth_monitoring_enabled=True,
    
    # Monitor all access
    log_all_requests=True,
    audit_trail_enabled=True,
    
    # Regular security testing
    penetration_testing_mode=True,
    
    # Protect cardholder data
    mask_sensitive_data=True,
    custom_waf_patterns=[
        r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",  # Credit cards
        r"\b\d{3}[\s-]?\d{2}[\s-]?\d{4}\b"              # SSN
    ]
)
```

## Incident Response

### Automated Response

```python
from fastapi_fortify.incident_response import IncidentHandler

handler = IncidentHandler(
    severity_thresholds={
        "low": {"rate_limit": 1000, "blocked_requests": 100},
        "medium": {"rate_limit": 500, "blocked_requests": 250},
        "high": {"rate_limit": 100, "blocked_requests": 500},
        "critical": {"rate_limit": 10, "blocked_requests": 1000}
    },
    
    response_actions={
        "medium": ["notify_team", "increase_monitoring"],
        "high": ["notify_team", "block_suspicious_ips", "escalate"],
        "critical": ["emergency_response", "block_all_suspicious", "page_on_call"]
    }
)

# Integrate with security middleware
app.add_middleware(SecurityMiddleware, 
                  config=config, 
                  incident_handler=handler)
```

### Manual Investigation Tools

```python
# Security management API for investigations
from fastapi_fortify.api.management import create_security_api

security_api = create_security_api(
    middleware_instance=middleware,
    api_key="incident-response-key",
    require_auth=True
)

# Investigation endpoints:
# GET /security/threats/summary?hours=24
# GET /security/ip-blocklist/{ip}
# POST /security/ip-blocklist/block
# GET /security/logs/search?query=...
# GET /security/alerts/recent
```

## Security Testing

### Penetration Testing Setup

```python
# Configure for penetration testing
config = SecurityConfig(
    # Allow pen testing from specific IPs
    ip_whitelist=["pentest.company.com"],
    
    # Log all attempts for analysis
    log_blocked_requests=True,
    log_level="DEBUG",
    
    # Don't actually block during tests
    test_mode=True,
    fail_open=True,
    
    # Monitor testing patterns
    alert_on_unusual_patterns=True
)
```

### Load Testing Considerations

```python
# Configure for load testing
config = SecurityConfig(
    # Higher rate limits for load tests
    rate_limit_requests=10000,
    rate_limit_window=60,
    
    # Disable some protections during load tests
    bot_detection_enabled=False,
    threat_intelligence_enabled=False,
    
    # But keep core security
    waf_enabled=True,
    basic_rate_limiting=True
)
```

## Emergency Procedures

### Security Incident Response

```python
# Emergency lockdown mode
config = SecurityConfig(
    emergency_mode=True,
    
    # Block all but essential traffic
    rate_limit_requests=10,
    rate_limit_window=60,
    
    # Strict IP filtering
    ip_whitelist_only=True,
    block_unknown_ips=True,
    
    # Maximum security
    waf_mode="strict",
    bot_detection_mode="strict",
    
    # Enhanced monitoring
    log_all_requests=True,
    alert_on_all_blocks=True
)
```

### Recovery Procedures

```python
# Gradual recovery from incident
async def gradual_recovery():
    # Step 1: Assess threat level
    threat_level = await assess_current_threats()
    
    # Step 2: Gradually relax restrictions
    if threat_level < 0.3:
        await update_config({"rate_limit_requests": 100})
    
    if threat_level < 0.2:
        await update_config({"waf_mode": "balanced"})
    
    if threat_level < 0.1:
        await update_config({"emergency_mode": False})
```

This comprehensive security guide provides the foundation for implementing robust security with FastAPI Guard while following industry best practices and compliance requirements.