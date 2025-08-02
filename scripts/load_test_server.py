#!/usr/bin/env python3
"""
Load Test Server for FastAPI Guard

This script sets up a test server with FastAPI Guard for realistic load testing
using external tools like Artillery, Locust, wrk, or Apache Bench.

Usage:
    python scripts/load_test_server.py [options]

Options:
    --host HOST         Host to bind to (default: 0.0.0.0)
    --port PORT         Port to bind to (default: 8000)
    --security LEVEL    Security level: none, minimal, balanced, production, high
    --workers NUM       Number of worker processes (default: 1)
    --log-level LEVEL   Log level: debug, info, warning, error (default: info)
    --redis-url URL     Redis URL for distributed rate limiting
    --no-reload         Disable auto-reload
"""
import argparse
import asyncio
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import sys
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi_fortify import SecurityMiddleware, SecurityConfig
from fastapi_fortify.config.presets import (
    ProductionConfig, 
    HighSecurityConfig
)


def create_test_app(security_level: str = "balanced", redis_url: str = None) -> FastAPI:
    """Create FastAPI test application with specified security level"""
    
    app = FastAPI(
        title="FastAPI Guard Load Test Server",
        description="Test server for load testing FastAPI Guard performance",
        version="1.0.0"
    )
    
    # Configure security based on level
    if security_level == "none":
        config = SecurityConfig(
            waf_enabled=False,
            bot_detection_enabled=False,
            ip_blocklist_enabled=False,
            rate_limiting_enabled=False,
            auth_monitoring_enabled=False
        )
    elif security_level == "minimal":
        config = SecurityConfig(
            waf_enabled=True,
            waf_mode="permissive",
            bot_detection_enabled=False,
            ip_blocklist_enabled=False,
            rate_limiting_enabled=True,
            rate_limit_requests=10000,
            rate_limit_window=60,
            auth_monitoring_enabled=False
        )
    elif security_level == "balanced":
        config = SecurityConfig(
            waf_enabled=True,
            waf_mode="balanced",
            bot_detection_enabled=True,
            bot_detection_mode="balanced",
            ip_blocklist_enabled=True,
            rate_limiting_enabled=True,
            rate_limit_requests=1000,
            rate_limit_window=3600,
            auth_monitoring_enabled=False
        )
    elif security_level == "production":
        config = ProductionConfig()
    elif security_level == "high":
        config = HighSecurityConfig()
    else:
        raise ValueError(f"Unknown security level: {security_level}")
    
    # Configure Redis if provided
    if redis_url:
        config.rate_limiter_backend = "redis"
        config.redis_url = redis_url
    
    # Add security middleware
    app.add_middleware(SecurityMiddleware, config=config)
    
    # Health check endpoint (excluded from security)
    @app.get("/health")
    async def health_check():
        return {"status": "healthy", "timestamp": "2023-01-01T00:00:00Z"}
    
    # Simple endpoints for load testing
    @app.get("/")
    async def root():
        return {"message": "Hello World", "security_level": security_level}
    
    @app.get("/api/simple")
    async def simple_endpoint():
        return {"data": "simple response"}
    
    @app.get("/api/data")
    async def get_data():
        return {
            "users": [
                {"id": 1, "name": "Alice"},
                {"id": 2, "name": "Bob"},
                {"id": 3, "name": "Charlie"}
            ],
            "total": 3
        }
    
    @app.post("/api/data")
    async def post_data(data: dict):
        return {
            "message": "Data received",
            "received": data,
            "processed": True
        }
    
    # CPU-intensive endpoint
    @app.get("/api/cpu")
    async def cpu_intensive():
        """Simulate CPU-intensive work"""
        result = 0
        for i in range(10000):
            result += i * i
        return {"result": result}
    
    # Memory-intensive endpoint
    @app.get("/api/memory")
    async def memory_intensive():
        """Simulate memory-intensive work"""
        data = list(range(10000))
        processed = [x * 2 for x in data]
        return {"processed_count": len(processed)}
    
    # Endpoint that might trigger WAF
    @app.get("/api/search")
    async def search(q: str = ""):
        """Search endpoint that accepts query parameters"""
        if not q:
            return {"results": [], "query": ""}
        
        # Simulate search results
        results = [
            {"id": 1, "title": f"Result for '{q}' #1"},
            {"id": 2, "title": f"Result for '{q}' #2"},
            {"id": 3, "title": f"Result for '{q}' #3"}
        ]
        return {"results": results, "query": q}
    
    # Authentication simulation
    @app.post("/api/auth/login")
    async def login(credentials: dict):
        """Simulate login endpoint"""
        username = credentials.get("username", "")
        password = credentials.get("password", "")
        
        # Simulate authentication logic
        if username == "admin" and password == "secret":
            return {"token": "jwt_token_here", "user": {"username": "admin"}}
        else:
            raise HTTPException(401, "Invalid credentials")
    
    # Rate limiting test endpoint
    @app.get("/api/limited")
    async def rate_limited_endpoint():
        """Endpoint with stricter rate limiting"""
        return {"message": "This endpoint has strict rate limits"}
    
    # Error simulation endpoint
    @app.get("/api/error")
    async def error_endpoint(error_type: str = "500"):
        """Simulate different types of errors"""
        if error_type == "400":
            raise HTTPException(400, "Bad Request")
        elif error_type == "401":
            raise HTTPException(401, "Unauthorized")
        elif error_type == "403":
            raise HTTPException(403, "Forbidden") 
        elif error_type == "404":
            raise HTTPException(404, "Not Found")
        elif error_type == "429":
            raise HTTPException(429, "Too Many Requests")
        else:
            raise HTTPException(500, "Internal Server Error")
    
    # Security info endpoint
    @app.get("/api/security/info")
    async def security_info():
        """Get security configuration info"""
        return {
            "security_level": security_level,
            "components": {
                "waf": config.waf_enabled,
                "bot_detection": config.bot_detection_enabled,
                "ip_blocklist": config.ip_blocklist_enabled,
                "rate_limiting": config.rate_limiting_enabled,
                "auth_monitoring": config.auth_monitoring_enabled
            },
            "rate_limits": {
                "requests": config.rate_limit_requests,
                "window": config.rate_limit_window
            }
        }
    
    return app


def print_load_test_examples():
    """Print examples of how to run load tests against the server"""
    print("\n📊 Load Testing Examples:")
    print("=" * 50)
    
    print("\n🔧 Apache Bench (ab):")
    print("  ab -n 1000 -c 10 http://localhost:8000/")
    print("  ab -n 5000 -c 50 http://localhost:8000/api/data")
    
    print("\n🚀 wrk:")
    print("  wrk -t12 -c400 -d30s http://localhost:8000/")
    print("  wrk -t4 -c100 -d60s --script post.lua http://localhost:8000/api/data")
    
    print("\n🐍 Locust:")
    print("  Create locustfile.py and run: locust -f locustfile.py --host=http://localhost:8000")
    
    print("\n🎯 Artillery:")
    print("  Create artillery-config.yml and run: artillery run artillery-config.yml")
    
    print("\n🌐 curl (simple test):")
    print("  curl http://localhost:8000/")
    print("  curl -X POST -H 'Content-Type: application/json' -d '{\"test\":\"data\"}' http://localhost:8000/api/data")
    
    print("\n🔍 Test malicious patterns (should be blocked):")
    print("  curl 'http://localhost:8000/api/search?q='; DROP TABLE users; --'")
    print("  curl 'http://localhost:8000/api/search?q=<script>alert(\"xss\")</script>'")
    
    print("\n📈 Monitor security metrics:")
    print("  curl http://localhost:8000/api/security/info")


def main():
    """Main server runner"""
    parser = argparse.ArgumentParser(description="FastAPI Guard Load Test Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--security", choices=["none", "minimal", "balanced", "production", "high"],
                       default="balanced", help="Security level")
    parser.add_argument("--workers", type=int, default=1, help="Number of worker processes")
    parser.add_argument("--log-level", choices=["debug", "info", "warning", "error"],
                       default="info", help="Log level")
    parser.add_argument("--redis-url", help="Redis URL for distributed rate limiting")
    parser.add_argument("--no-reload", action="store_true", help="Disable auto-reload")
    parser.add_argument("--examples", action="store_true", 
                       help="Show load testing examples and exit")
    
    args = parser.parse_args()
    
    if args.examples:
        print_load_test_examples()
        return
    
    print("FastAPI Guard Load Test Server")
    print("=" * 40)
    print(f"Security Level: {args.security}")
    print(f"Host: {args.host}")
    print(f"Port: {args.port}")
    print(f"Workers: {args.workers}")
    print(f"Redis: {args.redis_url or 'Not configured'}")
    print()
    
    # Create application
    try:
        app = create_test_app(args.security, args.redis_url)
        print(f"✅ Server configured with '{args.security}' security level")
    except Exception as e:
        print(f"❌ Failed to configure server: {e}")
        sys.exit(1)
    
    # Print available endpoints
    print("\n🌐 Available Endpoints:")
    endpoints = [
        "GET /health - Health check",
        "GET / - Simple hello world",
        "GET /api/simple - Simple API response",
        "GET /api/data - Get sample data",
        "POST /api/data - Post data",
        "GET /api/cpu - CPU-intensive endpoint",
        "GET /api/memory - Memory-intensive endpoint", 
        "GET /api/search?q= - Search endpoint (test WAF)",
        "POST /api/auth/login - Authentication endpoint",
        "GET /api/limited - Rate limited endpoint",
        "GET /api/error?error_type= - Error simulation",
        "GET /api/security/info - Security configuration"
    ]
    
    for endpoint in endpoints:
        print(f"  {endpoint}")
    
    print_load_test_examples()
    
    print(f"\n🚀 Starting server at http://{args.host}:{args.port}")
    print("   Press Ctrl+C to stop")
    
    # Start server
    try:
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            workers=args.workers,
            log_level=args.log_level,
            reload=not args.no_reload and args.workers == 1,
            loop="uvloop" if sys.platform != "win32" else "asyncio"
        )
    except KeyboardInterrupt:
        print("\n👋 Server stopped")
    except Exception as e:
        print(f"\n❌ Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()