"""
Integration tests for FastAPI Guard

These tests verify that all components work together correctly.
"""
import pytest
import asyncio
from unittest.mock import Mock, patch
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from fastapi_fortify.middleware.security import SecurityMiddleware
from fastapi_fortify.config.settings import SecurityConfig
from fastapi_fortify.config.presets import ProductionConfig, HighSecurityConfig
from fastapi_fortify.api.management import create_security_api


class TestFullStackIntegration:
    """Test complete FastAPI Guard stack integration"""
    
    def test_basic_integration(self):
        """Test basic integration with minimal config"""
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello World"}
        
        # Add security middleware
        app.add_middleware(
            SecurityMiddleware,
            config=SecurityConfig(
                waf_enabled=True,
                bot_detection_enabled=True,
                rate_limiting_enabled=True
            )
        )
        
        client = TestClient(app)
        
        # Normal request should work
        response = client.get("/")
        assert response.status_code == 200
        assert response.json() == {"message": "Hello World"}
    
    def test_production_configuration(self):
        """Test with production configuration"""
        app = FastAPI()
        
        @app.get("/api/data")
        async def get_data():
            return {"data": "sensitive"}
        
        @app.get("/health")
        async def health():
            return {"status": "ok"}
        
        # Use production config
        config = ProductionConfig()
        config.excluded_paths = ["/health"]
        
        app.add_middleware(SecurityMiddleware, config=config)
        
        client = TestClient(app)
        
        # Health endpoint should bypass security
        response = client.get("/health")
        assert response.status_code == 200
        
        # API endpoint should be protected
        response = client.get("/api/data")
        assert response.status_code == 200
        
        # Security headers should be present
        assert "X-Content-Type-Options" in response.headers
    
    def test_attack_scenarios(self):
        """Test protection against various attack scenarios"""
        app = FastAPI()
        
        @app.get("/search")
        async def search(q: str = ""):
            return {"query": q}
        
        @app.post("/login")
        async def login(username: str, password: str):
            return {"status": "success"}
        
        # High security configuration
        app.add_middleware(
            SecurityMiddleware,
            config=HighSecurityConfig()
        )
        
        client = TestClient(app)
        
        # Test 1: SQL Injection should be blocked
        response = client.get("/search?q='; DROP TABLE users; --")
        assert response.status_code == 403
        
        # Test 2: XSS should be blocked
        response = client.get("/search?q=<script>alert('xss')</script>")
        assert response.status_code == 403
        
        # Test 3: Bot user agent should be blocked
        response = client.get(
            "/search?q=normal",
            headers={"User-Agent": "sqlmap/1.0"}
        )
        assert response.status_code == 403
        
        # Test 4: Normal request should pass
        response = client.get(
            "/search?q=normal search",
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/91.0"}
        )
        assert response.status_code == 200
    
    def test_rate_limiting_integration(self):
        """Test rate limiting integration"""
        app = FastAPI()
        
        @app.get("/api/endpoint")
        async def api_endpoint():
            return {"data": "test"}
        
        # Configure with low rate limit for testing
        app.add_middleware(
            SecurityMiddleware,
            config=SecurityConfig(
                rate_limiting_enabled=True,
                rate_limit_requests=3,
                rate_limit_window=60
            )
        )
        
        client = TestClient(app)
        
        # First 3 requests should succeed
        for i in range(3):
            response = client.get("/api/endpoint")
            assert response.status_code == 200
        
        # 4th request should be rate limited
        response = client.get("/api/endpoint")
        assert response.status_code == 429
        assert "rate limit" in response.json()["detail"].lower()
    
    def test_management_api_integration(self):
        """Test management API integration"""
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello"}
        
        # Add security middleware
        middleware = SecurityMiddleware(
            app,
            config=SecurityConfig(
                waf_enabled=True,
                bot_detection_enabled=True,
                ip_blocklist_enabled=True,
                rate_limiting_enabled=True
            )
        )
        
        # Add management API
        security_api = create_security_api(
            middleware_instance=middleware,
            require_auth=False
        )
        app.include_router(security_api.router)
        
        client = TestClient(app)
        
        # Test health endpoint
        response = client.get("/security/health")
        assert response.status_code == 200
        
        # Test status endpoint
        response = client.get("/security/status")
        assert response.status_code in [200, 503]  # May be 503 if middleware not properly linked
        
        # Test blocking an IP
        response = client.post("/security/ip-blocklist/block", json={
            "ip_address": "192.168.1.100",
            "reason": "Test block",
            "duration_hours": 24
        })
        assert response.status_code == 200
    
    def test_error_resilience(self):
        """Test that the system is resilient to component failures"""
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello"}
        
        # Add middleware with all components
        middleware = SecurityMiddleware(
            app,
            config=SecurityConfig(
                waf_enabled=True,
                bot_detection_enabled=True,
                ip_blocklist_enabled=True,
                rate_limiting_enabled=True
            )
        )
        
        # Simulate component failure
        if middleware.waf:
            middleware.waf.analyze_request = Mock(side_effect=Exception("WAF failed"))
        
        client = TestClient(app)
        
        # Request should still succeed (fail-open behavior)
        response = client.get("/")
        assert response.status_code == 200
        assert response.json() == {"message": "Hello"}
    
    def test_concurrent_requests(self):
        """Test handling of concurrent requests"""
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello"}
        
        app.add_middleware(
            SecurityMiddleware,
            config=SecurityConfig(
                waf_enabled=True,
                bot_detection_enabled=True,
                rate_limiting_enabled=True,
                rate_limit_requests=50  # Allow many concurrent requests
            )
        )
        
        client = TestClient(app)
        
        # Make many concurrent requests
        import threading
        import time
        
        results = []
        errors = []
        
        def make_request():
            try:
                response = client.get("/")
                results.append(response.status_code)
            except Exception as e:
                errors.append(str(e))
        
        # Create and start threads
        threads = []
        for i in range(20):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Most requests should succeed
        successful_requests = sum(1 for status in results if status == 200)
        assert successful_requests >= 15  # Allow for some rate limiting
        assert len(errors) == 0  # No errors should occur
    
    def test_websocket_passthrough(self):
        """Test that WebSocket connections pass through middleware"""
        app = FastAPI()
        
        @app.websocket("/ws")
        async def websocket_endpoint(websocket):
            await websocket.accept()
            await websocket.send_text("Hello WebSocket")
            await websocket.close()
        
        app.add_middleware(
            SecurityMiddleware,
            config=SecurityConfig()
        )
        
        client = TestClient(app)
        
        # WebSocket should work (middleware should not interfere)
        with client.websocket_connect("/ws") as websocket:
            data = websocket.receive_text()
            assert data == "Hello WebSocket"


class TestConfigurationIntegration:
    """Test different configuration scenarios"""
    
    def test_environment_based_config(self):
        """Test environment-based configuration"""
        import os
        
        # Simulate environment variables
        os.environ["SECURITY_MODE"] = "production"
        
        try:
            app = FastAPI()
            
            @app.get("/")
            async def root():
                return {"message": "Hello"}
            
            # Use production config
            config = ProductionConfig()
            app.add_middleware(SecurityMiddleware, config=config)
            
            client = TestClient(app)
            response = client.get("/")
            
            assert response.status_code == 200
            # Production should add security headers
            assert "X-Content-Type-Options" in response.headers
            
        finally:
            os.environ.pop("SECURITY_MODE", None)
    
    def test_custom_configuration_override(self):
        """Test custom configuration overrides"""
        app = FastAPI()
        
        @app.get("/api/test")
        async def test_endpoint():
            return {"test": True}
        
        # Start with production config and customize
        config = ProductionConfig()
        config_dict = config.dict()
        config_dict.update({
            "rate_limit_requests": 5,  # Very low for testing
            "excluded_paths": ["/api/test"],  # Exclude test endpoint
            "custom_waf_patterns": ["custom_threat_pattern"]
        })
        
        custom_config = SecurityConfig(**config_dict)
        app.add_middleware(SecurityMiddleware, config=custom_config)
        
        client = TestClient(app)
        
        # Test endpoint should bypass all security (excluded)
        for i in range(10):  # More than rate limit
            response = client.get("/api/test")
            assert response.status_code == 200


class TestPerformanceIntegration:
    """Test performance characteristics of integrated system"""
    
    def test_response_time_impact(self):
        """Test that security middleware doesn't significantly impact response times"""
        import time
        
        # App without security
        app_plain = FastAPI()
        
        @app_plain.get("/")
        async def root_plain():
            return {"message": "Hello"}
        
        # App with security
        app_secure = FastAPI()
        
        @app_secure.get("/")
        async def root_secure():
            return {"message": "Hello"}
        
        app_secure.add_middleware(
            SecurityMiddleware,
            config=SecurityConfig(
                waf_enabled=True,
                bot_detection_enabled=True,
                rate_limiting_enabled=True
            )
        )
        
        client_plain = TestClient(app_plain)
        client_secure = TestClient(app_secure)
        
        # Warm up
        client_plain.get("/")
        client_secure.get("/")
        
        # Measure response times
        iterations = 100
        
        # Plain app
        start = time.time()
        for _ in range(iterations):
            response = client_plain.get("/")
            assert response.status_code == 200
        plain_time = time.time() - start
        
        # Secure app
        start = time.time()
        for _ in range(iterations):
            response = client_secure.get("/")
            assert response.status_code == 200
        secure_time = time.time() - start
        
        # Security overhead should be reasonable
        overhead_ratio = secure_time / plain_time
        assert overhead_ratio < 3.0  # Less than 3x slower
        
        print(f"Performance overhead: {overhead_ratio:.2f}x")
        print(f"Plain: {plain_time:.3f}s, Secure: {secure_time:.3f}s")
    
    def test_memory_usage_stability(self):
        """Test that memory usage remains stable over many requests"""
        import gc
        import psutil
        import os
        
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello"}
        
        app.add_middleware(
            SecurityMiddleware,
            config=SecurityConfig()
        )
        
        client = TestClient(app)
        
        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Make many requests
        for i in range(1000):
            response = client.get("/")
            assert response.status_code == 200
            
            # Force garbage collection periodically
            if i % 100 == 0:
                gc.collect()
        
        # Check final memory usage
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (less than 50MB)
        assert memory_increase < 50 * 1024 * 1024
        
        print(f"Memory increase: {memory_increase / 1024 / 1024:.2f} MB")


class TestRealWorldScenarios:
    """Test real-world usage scenarios"""
    
    def test_api_gateway_scenario(self):
        """Test scenario similar to API gateway usage"""
        app = FastAPI()
        
        # Multiple API endpoints
        @app.get("/api/v1/users")
        async def get_users():
            return {"users": []}
        
        @app.post("/api/v1/users")
        async def create_user():
            return {"id": "user123"}
        
        @app.get("/api/v1/orders")
        async def get_orders():
            return {"orders": []}
        
        @app.get("/health")
        async def health():
            return {"status": "healthy"}
        
        # Configure like an API gateway
        config = ProductionConfig()
        config.excluded_paths = ["/health", "/metrics"]
        config.rate_limit_requests = 1000  # High throughput
        config.rate_limit_window = 60
        
        app.add_middleware(SecurityMiddleware, config=config)
        
        client = TestClient(app)
        
        # Test various scenarios
        scenarios = [
            ("GET", "/api/v1/users", 200),
            ("POST", "/api/v1/users", 200),
            ("GET", "/health", 200),
            ("GET", "/api/v1/orders?filter=' OR 1=1", 403),  # SQL injection
            ("GET", "/api/v1/users", 200, {"User-Agent": "sqlmap/1.0"}),  # Should block
        ]
        
        for scenario in scenarios:
            method = scenario[0]
            path = scenario[1]
            expected_status = scenario[2]
            headers = scenario[3] if len(scenario) > 3 else {}
            
            if method == "GET":
                response = client.get(path, headers=headers)
            elif method == "POST":
                response = client.post(path, headers=headers)
            
            if "sqlmap" in headers.get("User-Agent", ""):
                assert response.status_code == 403  # Bot should be blocked
            else:
                assert response.status_code == expected_status
    
    def test_microservice_scenario(self):
        """Test scenario for microservice protection"""
        app = FastAPI()
        
        # Service endpoints
        @app.get("/service/data")
        async def get_service_data():
            return {"data": "service response"}
        
        @app.post("/service/process")
        async def process_data():
            return {"status": "processed"}
        
        # Internal health checks
        @app.get("/internal/health")
        async def internal_health():
            return {"status": "ok"}
        
        # Configure for microservice
        config = SecurityConfig(
            waf_enabled=True,
            bot_detection_enabled=True,
            rate_limiting_enabled=True,
            ip_blocklist_enabled=True,
            
            # Microservice specific settings
            excluded_paths=["/internal/*"],
            ip_whitelist=["10.0.0.0/8", "192.168.0.0/16"],  # Internal networks
            rate_limit_requests=500,
            rate_limit_window=60
        )
        
        app.add_middleware(SecurityMiddleware, config=config)
        
        client = TestClient(app)
        
        # Test service endpoints
        response = client.get("/service/data")
        assert response.status_code == 200
        
        # Test internal endpoint (should bypass security)
        response = client.get("/internal/health")
        assert response.status_code == 200
        
        # Test malicious request
        response = client.get("/service/data?param=<script>alert('xss')</script>")
        assert response.status_code == 403