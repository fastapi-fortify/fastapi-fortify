# Examples

Real-world examples of FastAPI Guard implementations for different use cases and scenarios.

## Basic Examples

### Minimal Setup

```python
from fastapi import FastAPI
from fastapi_fortify import SecurityMiddleware

app = FastAPI()

# Zero configuration - uses secure defaults
app.add_middleware(SecurityMiddleware)

@app.get("/")
async def root():
    return {"message": "Hello, secure world!"}

@app.get("/api/data")
async def get_data():
    return {"data": ["item1", "item2", "item3"]}
```

### Custom Configuration

```python
from fastapi import FastAPI
from fastapi_fortify import SecurityMiddleware, SecurityConfig

app = FastAPI()

# Custom security configuration
config = SecurityConfig(
    waf_enabled=True,
    waf_mode="balanced",
    rate_limiting_enabled=True,
    rate_limit_requests=1000,
    rate_limit_window=3600,
    bot_detection_enabled=True,
    ip_blocklist_enabled=True,
    excluded_paths=["/health", "/metrics"]
)

app.add_middleware(SecurityMiddleware, config=config)

@app.get("/health")
async def health():
    return {"status": "healthy"}  # Excluded from security checks

@app.get("/api/protected")
async def protected_data():
    return {"sensitive": "data"}  # Full security protection
```

## Production Examples

### E-commerce API

```python
from fastapi import FastAPI, HTTPException, Depends
from fastapi_fortify import SecurityMiddleware, SecurityConfig
from fastapi_fortify.config.presets import ProductionConfig
from fastapi_fortify.utils.decorators import rate_limit, require_auth
from fastapi_fortify.monitoring.auth_monitor import create_auth_monitor

app = FastAPI(title="E-commerce API")

# E-commerce specific security configuration
config = ProductionConfig()
config.update({
    # Custom rate limits for different endpoints
    "rate_limit_per_endpoint": {
        "POST /auth/login": {"requests": 5, "window": 300},
        "POST /auth/register": {"requests": 3, "window": 3600},
        "POST /orders": {"requests": 50, "window": 3600},
        "GET /products": {"requests": 1000, "window": 3600},
        "POST /payments": {"requests": 10, "window": 3600}
    },
    
    # E-commerce specific WAF patterns
    "custom_waf_patterns": [
        r"(?i)\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",  # Credit cards
        r"(?i)\b\d{3}[\s-]?\d{2}[\s-]?\d{4}\b",              # SSN
        r"(?i)(admin|administrator|root)\/",                  # Admin probing
        r"(?i)\.bak$|\.backup$|\.old$"                       # Backup files
    ],
    
    # Whitelist payment processors and partners
    "ip_whitelist": [
        "192.168.1.0/24",      # Internal network
        "paypal.com",          # PayPal IPs
        "stripe.com",          # Stripe IPs
        "partner-api.com"      # Partner APIs
    ],
    
    # Exclude health checks and webhooks
    "excluded_paths": [
        "/health",
        "/metrics",
        "/webhooks/stripe",
        "/webhooks/paypal"
    ]
})

app.add_middleware(SecurityMiddleware, config=config)

# Authentication monitoring for login security
auth_monitor = create_auth_monitor(
    security_level="high",
    notifications=["webhook", "email"],
    webhook_url="https://company.com/security-alerts",
    email_recipients=["security@company.com"]
)

# Product endpoints - high volume, relaxed security
@app.get("/products")
async def get_products(category: str = None):
    # High rate limit, basic security
    return {"products": []}

@app.get("/products/{product_id}")
async def get_product(product_id: str):
    return {"product": {"id": product_id, "name": "Sample Product"}}

# Authentication endpoints - strict security
@rate_limit(requests=5, window_seconds=300)
@app.post("/auth/login")
async def login(email: str, password: str, request: Request):
    # Authenticate user
    success = authenticate_user(email, password)
    
    # Monitor login attempt
    await auth_monitor.process_login_attempt(
        email=email,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        success=success
    )
    
    if not success:
        raise HTTPException(401, "Invalid credentials")
    
    return {"token": "jwt-token", "user": {"email": email}}

# Order endpoints - moderate security
@require_auth()
@rate_limit(requests=50, window_seconds=3600)
@app.post("/orders")
async def create_order(order_data: dict, request: Request):
    return {"order_id": "12345", "status": "created"}

# Payment endpoints - maximum security
@require_auth()
@rate_limit(requests=10, window_seconds=3600)
@app.post("/payments")
async def process_payment(payment_data: dict, request: Request):
    # Additional payment-specific validation
    return {"payment_id": "pay_12345", "status": "processed"}

# Admin endpoints - restricted access
@require_auth()
@rate_limit(requests=100, window_seconds=3600, key_func=lambda req: f"admin:{get_user_id(req)}")
@app.get("/admin/users")
async def admin_get_users(request: Request):
    return {"users": []}
```

### Banking API

```python
from fastapi import FastAPI, HTTPException, Request
from fastapi_fortify import SecurityMiddleware, SecurityConfig
from fastapi_fortify.config.presets import HighSecurityConfig
from fastapi_fortify.utils.decorators import (
    require_auth, 
    rate_limit, 
    security_headers,
    log_security_event
)

app = FastAPI(title="Banking API")

# Maximum security for financial services
config = HighSecurityConfig()
config.update({
    # Very strict rate limits
    "rate_limit_requests": 100,
    "rate_limit_window": 3600,
    
    # Banking-specific patterns
    "custom_waf_patterns": [
        r"(?i)\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",  # Credit cards
        r"(?i)\b\d{3}[\s-]?\d{2}[\s-]?\d{4}\b",              # SSN
        r"(?i)\b\d{9}\b",                                     # Routing numbers
        r"(?i)(account|routing|swift).*\d+",                  # Account patterns
        r"(?i)(transfer|wire|ach).*\$?\d+",                   # Transaction patterns
    ],
    
    # Whitelist only known IP ranges
    "ip_whitelist": [
        "10.0.0.0/8",          # Internal network
        "172.16.0.0/12",       # Internal network
        "fed.gov",             # Federal systems
        "clearinghouse.net"    # ACH network
    ],
    
    # Block all private networks from public access
    "block_private_networks": True,
    
    # Enable all security features
    "waf_mode": "strict",
    "bot_detection_mode": "strict",
    "auth_monitoring_enabled": True,
    "brute_force_protection": True,
    
    # Enhanced logging
    "log_all_requests": True,
    "audit_trail_enabled": True,
    "log_retention_days": 2555  # 7 years
})

app.add_middleware(SecurityMiddleware, config=config)

# Security headers for all responses
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

# Account balance - high security
@require_auth()
@rate_limit(requests=10, window_seconds=300)
@security_headers(csp="default-src 'self'", hsts=True)
@log_security_event(event_type="account_access", severity="high")
@app.get("/accounts/{account_id}/balance")
async def get_balance(account_id: str, request: Request):
    return {"account_id": account_id, "balance": "encrypted_balance"}

# Money transfer - maximum security
@require_auth()
@rate_limit(requests=5, window_seconds=3600)
@log_security_event(event_type="money_transfer", severity="critical", alert_immediately=True)
@app.post("/transfers")
async def transfer_money(transfer_data: dict, request: Request):
    # Additional fraud detection
    # Multi-factor authentication
    # Transaction limits
    return {"transfer_id": "txn_12345", "status": "pending_approval"}

# Transaction history - monitored access
@require_auth()
@rate_limit(requests=50, window_seconds=3600)
@log_security_event(event_type="transaction_history", severity="medium")
@app.get("/accounts/{account_id}/transactions")
async def get_transactions(account_id: str, request: Request):
    return {"transactions": []}
```

### Microservices Architecture

```python
# Service A: User Service
from fastapi import FastAPI
from fastapi_fortify import SecurityMiddleware, SecurityConfig

user_service = FastAPI(title="User Service")

# Microservice-specific configuration
config = SecurityConfig(
    # Service-to-service communication
    ip_whitelist=[
        "10.0.0.0/8",          # Internal network
        "172.16.0.0/12",       # Container network
        "service-b.internal",   # Other services
        "service-c.internal"
    ],
    
    # Moderate rate limits for internal APIs
    rate_limit_requests=5000,
    rate_limit_window=3600,
    
    # Exclude health checks and service discovery
    excluded_paths=[
        "/health",
        "/ready",
        "/metrics",
        "/service-info"
    ],
    
    # Service-specific patterns
    custom_waf_patterns=[
        r"(?i)email.*injection",    # Email injection
        r"(?i)ldap.*injection"      # LDAP injection for user lookups
    ]
)

user_service.add_middleware(SecurityMiddleware, config=config)

@user_service.get("/users/{user_id}")
async def get_user(user_id: str):
    return {"user_id": user_id, "email": "user@example.com"}

# Service B: Order Service
order_service = FastAPI(title="Order Service")

order_config = SecurityConfig(
    # Higher rate limits for order processing
    rate_limit_requests=10000,
    rate_limit_window=3600,
    
    # Order-specific security
    custom_waf_patterns=[
        r"(?i)price.*manipulation",
        r"(?i)quantity.*overflow"
    ],
    
    # Different IP whitelist
    ip_whitelist=[
        "10.0.0.0/8",
        "payment-gateway.com",
        "inventory-service.internal"
    ]
)

order_service.add_middleware(SecurityMiddleware, config=order_config)

@order_service.post("/orders")
async def create_order(order: dict):
    return {"order_id": "12345", "status": "created"}
```

## API Gateway Example

```python
from fastapi import FastAPI, Request, HTTPException
from fastapi_fortify import SecurityMiddleware, SecurityConfig
from fastapi_fortify.config.presets import ProductionConfig
import httpx

app = FastAPI(title="API Gateway")

# Gateway-specific configuration
config = ProductionConfig()
config.update({
    # High throughput configuration
    "rate_limit_requests": 10000,
    "rate_limit_window": 3600,
    
    # Per-service rate limits
    "rate_limit_per_endpoint": {
        "GET /api/v1/users/*": {"requests": 1000, "window": 3600},
        "POST /api/v1/orders/*": {"requests": 500, "window": 3600},
        "GET /api/v1/products/*": {"requests": 5000, "window": 3600},
        "POST /api/v1/auth/*": {"requests": 100, "window": 3600}
    },
    
    # Gateway-specific exclusions
    "excluded_paths": [
        "/health",
        "/metrics",
        "/docs",
        "/openapi.json"
    ],
    
    # Enhanced bot detection for API gateway
    "bot_detection_mode": "balanced",
    "allow_search_engines": False,  # API gateway doesn't need SEO
    
    # Comprehensive threat protection
    "custom_waf_patterns": [
        r"(?i)api.*key.*[a-zA-Z0-9]{20,}",    # API key leakage
        r"(?i)token.*[a-zA-Z0-9]{30,}",       # Token exposure
        r"(?i)bearer.*[a-zA-Z0-9]{20,}"       # Bearer token exposure
    ]
})

app.add_middleware(SecurityMiddleware, config=config)

# Service registry
SERVICES = {
    "users": "http://user-service:8001",
    "orders": "http://order-service:8002",
    "products": "http://product-service:8003",
    "auth": "http://auth-service:8004"
}

@app.api_route("/api/v1/{service_name}/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy_request(service_name: str, path: str, request: Request):
    if service_name not in SERVICES:
        raise HTTPException(404, f"Service {service_name} not found")
    
    service_url = SERVICES[service_name]
    target_url = f"{service_url}/{path}"
    
    # Forward request to service
    async with httpx.AsyncClient() as client:
        response = await client.request(
            method=request.method,
            url=target_url,
            headers=dict(request.headers),
            params=dict(request.query_params),
            content=await request.body()
        )
    
    return response.json()
```

## Content Management System

```python
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi_fortify import SecurityMiddleware, SecurityConfig
from fastapi_fortify.utils.decorators import (
    rate_limit, 
    require_auth, 
    block_bots,
    validate_input
)

app = FastAPI(title="CMS API")

# CMS-specific security configuration
config = SecurityConfig(
    # Allow search engines for public content
    allow_search_engines=True,
    
    # CMS-specific rate limits
    rate_limit_per_endpoint={
        "GET /content/*": {"requests": 2000, "window": 3600},     # Public content
        "POST /content": {"requests": 50, "window": 3600},        # Creating content
        "PUT /content/*": {"requests": 100, "window": 3600},      # Editing content
        "DELETE /content/*": {"requests": 10, "window": 3600},    # Deleting content
        "POST /media/upload": {"requests": 20, "window": 3600}    # File uploads
    },
    
    # CMS-specific threats
    "custom_waf_patterns": [
        r"(?i)<\?php.*\?>",                    # PHP injection
        r"(?i)<%.*%>",                         # ASP injection
        r"(?i){{.*}}",                         # Template injection
        r"(?i)file_get_contents",              # File inclusion
        r"(?i)eval\s*\(",                      # Code evaluation
        r"(?i)base64_decode",                  # Encoded payloads
        r"(?i)\.\./.*\.\./",                   # Directory traversal
    ],
    
    # Media upload protection
    "file_upload_protection": True,
    "max_file_size": 10 * 1024 * 1024,       # 10MB
    "allowed_file_types": ["jpg", "png", "gif", "pdf", "doc", "docx"],
    
    # Admin area protection  
    "ip_whitelist": ["192.168.1.0/24"],      # Admin network
}

app.add_middleware(SecurityMiddleware, config=config)

# Public content - allow search engines
@app.get("/content/{content_id}")
async def get_content(content_id: str):
    return {"id": content_id, "title": "Sample Article", "body": "Content..."}

# Search endpoint - high volume
@app.get("/search")
async def search_content(q: str):
    return {"results": [], "query": q}

# Admin content creation - protected
@require_auth()
@rate_limit(requests=50, window_seconds=3600)
@validate_input(max_length=100000, check_encoding=True)
@app.post("/content")
async def create_content(content: dict, request: Request):
    return {"id": "new_content_123", "status": "created"}

# Media upload - strict validation
@require_auth()
@rate_limit(requests=20, window_seconds=3600)
@app.post("/media/upload")
async def upload_media(file: UploadFile, request: Request):
    # Additional file validation would go here
    return {"file_id": "file_123", "url": "/media/file_123.jpg"}

# Admin endpoints - IP restricted
@require_auth()
@block_bots(mode="strict")
@app.get("/admin/users")
async def admin_users(request: Request):
    client_ip = get_client_ip(request)
    if not ip_in_whitelist(client_ip):
        raise HTTPException(403, "Admin access restricted")
    
    return {"users": []}
```

## IoT Device Management

```python
from fastapi import FastAPI, HTTPException, Request
from fastapi_fortify import SecurityMiddleware, SecurityConfig
from fastapi_fortify.utils.decorators import rate_limit, require_auth

app = FastAPI(title="IoT Device Management")

# IoT-specific security configuration
config = SecurityConfig(
    # Device-specific rate limits
    rate_limit_per_endpoint={
        "POST /devices/telemetry": {"requests": 10000, "window": 3600},  # High frequency data
        "GET /devices/status": {"requests": 1000, "window": 3600},       # Status checks
        "POST /devices/commands": {"requests": 100, "window": 3600},     # Control commands
        "POST /devices/register": {"requests": 10, "window": 86400}      # Device registration
    },
    
    # IoT-specific threats
    "custom_waf_patterns": [
        r"(?i)mqtt.*injection",               # MQTT injection
        r"(?i)coap.*exploit",                 # CoAP exploits
        r"(?i)device.*overflow",              # Buffer overflow
        r"(?i)firmware.*\.(bin|hex|img)",     # Firmware patterns
    ],
    
    # Device network whitelisting
    "ip_whitelist": [
        "10.0.0.0/8",          # Internal IoT network
        "172.16.0.0/12",       # Container network
        "192.168.0.0/16"       # Local networks
    ],
    
    # Disable features not needed for IoT
    "bot_detection_enabled": False,          # Devices aren't bots
    "allow_search_engines": False,           # No SEO needed
    
    # Enhanced monitoring for devices
    "auth_monitoring_enabled": True,
    "failed_login_threshold": 3,            # Strict for device auth
    "device_fingerprinting": True
)

app.add_middleware(SecurityMiddleware, config=config)

# Device authentication
@app.post("/devices/auth")
async def device_auth(device_id: str, device_key: str, request: Request):
    # Authenticate device
    if not validate_device_credentials(device_id, device_key):
        raise HTTPException(401, "Invalid device credentials")
    
    return {"token": "device_jwt_token", "expires_in": 3600}

# High-frequency telemetry data
@require_auth()
@rate_limit(requests=10000, window_seconds=3600, key_func=lambda req: f"device:{get_device_id(req)}")
@app.post("/devices/telemetry")
async def receive_telemetry(data: dict, request: Request):
    return {"status": "received", "timestamp": "2023-01-01T00:00:00Z"}

# Device control commands - restricted
@require_auth()
@rate_limit(requests=100, window_seconds=3600)
@app.post("/devices/{device_id}/commands")
async def send_command(device_id: str, command: dict, request: Request):
    return {"command_id": "cmd_123", "status": "sent"}

# Device status monitoring
@require_auth()
@app.get("/devices/{device_id}/status")
async def get_device_status(device_id: str):
    return {"device_id": device_id, "status": "online", "last_seen": "2023-01-01T00:00:00Z"}
```

## WebSocket Example

```python
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi_fortify import SecurityMiddleware, SecurityConfig
from fastapi_fortify.utils.websocket import WebSocketSecurityManager

app = FastAPI(title="Real-time Chat")

# WebSocket-compatible security
config = SecurityConfig(
    # Rate limiting for WebSocket connections
    websocket_rate_limiting=True,
    websocket_max_connections=1000,
    websocket_rate_limit_messages=100,     # Messages per minute
    
    # Connection authentication
    websocket_auth_required=True,
    websocket_auth_timeout=30,            # 30 seconds to authenticate
    
    # Message filtering
    websocket_message_filtering=True,
    custom_waf_patterns=[
        r"(?i)<script.*>.*</script>",      # XSS in messages
        r"(?i)javascript:",                # JavaScript URLs
        r"(?i)on\w+\s*=",                 # Event handlers
    ]
)

app.add_middleware(SecurityMiddleware, config=config)

# WebSocket security manager
ws_security = WebSocketSecurityManager(config)

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket, client_id: str):
        # Security check before accepting connection
        if not await ws_security.validate_connection(websocket, client_id):
            await websocket.close(code=4003, reason="Security validation failed")
            return False
        
        await websocket.accept()
        self.active_connections.append(websocket)
        return True
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    
    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    if not await manager.connect(websocket, client_id):
        return
    
    try:
        while True:
            # Receive message
            data = await websocket.receive_text()
            
            # Security check on message
            if not await ws_security.validate_message(data, client_id):
                await websocket.send_text(json.dumps({
                    "error": "Message blocked by security filter"
                }))
                continue
            
            # Rate limit check
            if not await ws_security.check_rate_limit(client_id):
                await websocket.send_text(json.dumps({
                    "error": "Rate limit exceeded"
                }))
                continue
            
            # Broadcast message
            await manager.broadcast(f"Client {client_id}: {data}")
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
```

## Integration Examples

### With Existing Authentication

```python
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi_fortify import SecurityMiddleware, SecurityConfig
import jwt

app = FastAPI()
security = HTTPBearer()

# Integrate with existing JWT authentication
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, "secret", algorithms=["HS256"])
        return payload["user_id"]
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")

# Configure FastAPI Guard to work with existing auth
config = SecurityConfig(
    # Don't duplicate authentication
    auth_monitoring_integration=True,
    
    # Rate limit by authenticated user
    rate_limit_key_func=lambda req: f"user:{get_user_from_request(req)}",
    
    # Exclude auth endpoints from some checks
    excluded_paths=["/auth/login", "/auth/refresh"]
)

app.add_middleware(SecurityMiddleware, config=config)

@app.get("/protected")
async def protected_endpoint(user_id: str = Depends(get_current_user)):
    return {"user_id": user_id, "data": "protected"}
```

### With Database Integration

```python
from fastapi import FastAPI
from sqlalchemy import create_engine
from fastapi_fortify import SecurityMiddleware, SecurityConfig
from fastapi_fortify.integrations.sqlalchemy import SQLAlchemySecurityStore

app = FastAPI()

# Database integration for persistent security data
engine = create_engine("postgresql://user:pass@localhost/security_db")
security_store = SQLAlchemySecurityStore(engine)

config = SecurityConfig(
    # Use database for persistent storage
    security_data_store=security_store,
    
    # Enable persistent IP blocklist
    ip_blocklist_persistent=True,
    
    # Store rate limiting data in database
    rate_limiter_backend="database",
    
    # Persistent threat intelligence
    threat_intelligence_cache="database"
)

app.add_middleware(SecurityMiddleware, config=config)
```

These examples demonstrate FastAPI Guard's flexibility and ability to adapt to different application types and security requirements. Each example showcases specific configuration patterns and best practices for different use cases.