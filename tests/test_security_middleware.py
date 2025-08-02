"""
Tests for Security Middleware integration
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient

from fastapi_fortify.middleware.security import (
    SecurityMiddleware,
    create_security_middleware,
    SecurityEnvironment
)
from fastapi_fortify.config.settings import SecurityConfig
from fastapi_fortify.config.presets import DevelopmentConfig, ProductionConfig, HighSecurityConfig
from fastapi_fortify.utils.security_utils import SecurityDecision


class TestSecurityMiddleware:
    """Test main security middleware functionality"""
    
    def test_middleware_initialization_default(self):
        """Test middleware initialization with default config"""
        middleware = SecurityMiddleware(app=Mock(), config=SecurityConfig())
        
        assert middleware.config is not None
        assert middleware.stats["requests_processed"] == 0
        assert middleware.stats["threats_blocked"] == 0
    
    def test_middleware_initialization_with_components(self):
        """Test middleware initialization with all components enabled"""
        config = SecurityConfig(
            waf_enabled=True,
            bot_detection_enabled=True,
            ip_blocklist_enabled=True,
            rate_limiting_enabled=True,
            auth_monitoring_enabled=True
        )
        
        middleware = SecurityMiddleware(app=Mock(), config=config)
        
        # All components should be initialized
        assert middleware.waf is not None
        assert middleware.bot_detector is not None
        assert middleware.ip_blocklist is not None
        assert middleware.rate_limiter is not None
        assert middleware.auth_monitor is not None
    
    def test_middleware_initialization_partial(self):
        """Test middleware initialization with partial components"""
        config = SecurityConfig(
            waf_enabled=True,
            bot_detection_enabled=False,
            ip_blocklist_enabled=True,
            rate_limiting_enabled=False,
            auth_monitoring_enabled=False
        )
        
        middleware = SecurityMiddleware(app=Mock(), config=config)
        
        # Only enabled components should be initialized
        assert middleware.waf is not None
        assert middleware.bot_detector is None
        assert middleware.ip_blocklist is not None
        assert middleware.rate_limiter is None
        assert middleware.auth_monitor is None
    
    @pytest.mark.asyncio
    async def test_middleware_request_processing(self):
        """Test basic request processing through middleware"""
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello World"}
        
        # Add middleware with minimal config
        app.add_middleware(
            SecurityMiddleware,
            config=SecurityConfig(
                waf_enabled=False,
                bot_detection_enabled=False,
                ip_blocklist_enabled=False,
                rate_limiting_enabled=False
            )
        )
        
        client = TestClient(app)
        response = client.get("/")
        
        assert response.status_code == 200
        assert response.json() == {"message": "Hello World"}
    
    @pytest.mark.asyncio
    async def test_waf_blocking(self):
        """Test WAF blocking malicious requests"""
        app = FastAPI()
        
        @app.get("/search")
        async def search(q: str):
            return {"query": q}
        
        # Add middleware with WAF enabled
        app.add_middleware(
            SecurityMiddleware,
            config=SecurityConfig(
                waf_enabled=True,
                bot_detection_enabled=False,
                ip_blocklist_enabled=False,
                rate_limiting_enabled=False
            )
        )
        
        client = TestClient(app)
        
        # Normal request should pass
        response = client.get("/search?q=normal+search")
        assert response.status_code == 200
        
        # SQL injection should be blocked
        response = client.get("/search?q='; DROP TABLE users; --")
        assert response.status_code == 403
        assert "blocked" in response.json()["detail"].lower()
    
    @pytest.mark.asyncio
    async def test_bot_detection_blocking(self):
        """Test bot detection blocking suspicious user agents"""
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello"}
        
        # Add middleware with bot detection enabled
        app.add_middleware(
            SecurityMiddleware,
            config=SecurityConfig(
                waf_enabled=False,
                bot_detection_enabled=True,
                bot_detection_mode="strict",
                ip_blocklist_enabled=False,
                rate_limiting_enabled=False
            )
        )
        
        client = TestClient(app)
        
        # Normal browser user agent should pass
        response = client.get(
            "/",
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0"}
        )
        assert response.status_code == 200
        
        # Bot user agent should be blocked
        response = client.get(
            "/",
            headers={"User-Agent": "sqlmap/1.0"}
        )
        assert response.status_code == 403
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self):
        """Test rate limiting functionality"""
        app = FastAPI()
        
        @app.get("/api/data")
        async def get_data():
            return {"data": "test"}
        
        # Add middleware with rate limiting
        app.add_middleware(
            SecurityMiddleware,
            config=SecurityConfig(
                waf_enabled=False,
                bot_detection_enabled=False,
                ip_blocklist_enabled=False,
                rate_limiting_enabled=True,
                rate_limit_requests=3,
                rate_limit_window=60
            )
        )
        
        client = TestClient(app)
        
        # First 3 requests should pass
        for i in range(3):
            response = client.get("/api/data")
            assert response.status_code == 200
        
        # 4th request should be rate limited
        response = client.get("/api/data")
        assert response.status_code == 429
        assert "rate limit" in response.json()["detail"].lower()
    
    @pytest.mark.asyncio
    async def test_ip_blocking(self):
        """Test IP blocklist functionality"""
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello"}
        
        # Create middleware with IP blocklist
        middleware = SecurityMiddleware(
            app=app,
            config=SecurityConfig(
                waf_enabled=False,
                bot_detection_enabled=False,
                ip_blocklist_enabled=True,
                rate_limiting_enabled=False
            )
        )
        
        # Manually block an IP
        if middleware.ip_blocklist:
            middleware.ip_blocklist.add_temporary_block(
                "192.168.1.100",
                "Test block",
                24
            )
        
        # Mock request from blocked IP
        async def call_next(request):
            return Response(content='{"message": "Hello"}', media_type="application/json")
        
        request = Mock(spec=Request)
        request.client.host = "192.168.1.100"
        request.url.path = "/"
        request.headers = {"user-agent": "test"}
        
        response = await middleware.dispatch(request, call_next)
        
        assert response.status_code == 403
    
    @pytest.mark.asyncio
    async def test_excluded_paths(self):
        """Test that excluded paths bypass security checks"""
        app = FastAPI()
        
        @app.get("/health")
        async def health():
            return {"status": "ok"}
        
        @app.get("/api/data")
        async def data():
            return {"data": "test"}
        
        # Add middleware with exclusions
        app.add_middleware(
            SecurityMiddleware,
            config=SecurityConfig(
                waf_enabled=True,
                excluded_paths=["/health", "/metrics/*"],
                rate_limiting_enabled=True,
                rate_limit_requests=1
            )
        )
        
        client = TestClient(app)
        
        # Health endpoint should bypass all checks
        for i in range(5):
            response = client.get(
                "/health",
                headers={"User-Agent": "sqlmap/1.0"},  # Malicious UA
                params={"q": "'; DROP TABLE users; --"}  # SQL injection
            )
            assert response.status_code == 200
        
        # API endpoint should be protected
        response = client.get("/api/data")
        assert response.status_code == 200  # First request OK
        
        response = client.get("/api/data")
        assert response.status_code == 429  # Rate limited
    
    @pytest.mark.asyncio
    async def test_security_headers_addition(self):
        """Test that security headers are added to responses"""
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello"}
        
        # Add middleware with security headers enabled
        app.add_middleware(
            SecurityMiddleware,
            config=SecurityConfig(
                waf_enabled=False,
                security_headers_enabled=True
            )
        )
        
        client = TestClient(app)
        response = client.get("/")
        
        assert response.status_code == 200
        assert "X-Content-Type-Options" in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert "X-Frame-Options" in response.headers
        assert "X-XSS-Protection" in response.headers
    
    @pytest.mark.asyncio
    async def test_error_handling_in_middleware(self):
        """Test error handling when components fail"""
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello"}
        
        middleware = SecurityMiddleware(
            app=app,
            config=SecurityConfig(waf_enabled=True)
        )
        
        # Mock WAF to raise an error
        if middleware.waf:
            middleware.waf.analyze_request = AsyncMock(side_effect=Exception("WAF error"))
        
        # Request should still go through (fail open)
        async def call_next(request):
            return Response(content='{"message": "Hello"}', media_type="application/json")
        
        request = Mock(spec=Request)
        request.client.host = "192.168.1.1"
        request.url.path = "/"
        request.headers = {"user-agent": "test"}
        
        response = await middleware.dispatch(request, call_next)
        
        # Should fail open and allow request
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_statistics_tracking(self):
        """Test that middleware tracks statistics correctly"""
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello"}
        
        middleware = SecurityMiddleware(
            app=app,
            config=SecurityConfig(
                waf_enabled=True,
                rate_limiting_enabled=True,
                rate_limit_requests=2
            )
        )
        
        client = TestClient(app)
        
        # Make some requests
        initial_stats = middleware.get_stats()
        
        # Normal request
        response = client.get("/")
        assert response.status_code == 200
        
        # Malicious request (should be blocked by WAF)
        response = client.get("/?q=<script>alert('xss')</script>")
        assert response.status_code == 403
        
        # Rate limited requests
        response = client.get("/")
        assert response.status_code == 200
        response = client.get("/")
        assert response.status_code == 429
        
        # Check updated stats
        stats = middleware.get_stats()
        assert stats["requests_processed"] > initial_stats["requests_processed"]
        assert stats["threats_blocked"] > initial_stats["threats_blocked"]
    
    @pytest.mark.asyncio
    async def test_auth_monitoring_integration(self):
        """Test authentication monitoring integration"""
        app = FastAPI()
        
        @app.post("/login")
        async def login():
            return {"status": "success"}
        
        middleware = SecurityMiddleware(
            app=app,
            config=SecurityConfig(
                auth_monitoring_enabled=True,
                auth_monitor_endpoints=["/login", "/signup"]
            )
        )
        
        # Mock auth monitor
        if middleware.auth_monitor:
            middleware.auth_monitor.process_login_attempt = AsyncMock(return_value=[])
        
        client = TestClient(app)
        
        # Login request should trigger auth monitoring
        response = client.post("/login")
        assert response.status_code == 200
        
        # Verify auth monitor was called
        if middleware.auth_monitor:
            middleware.auth_monitor.process_login_attempt.assert_called()


class TestSecurityMiddlewareFactory:
    """Test middleware factory functions"""
    
    def test_create_development_middleware(self):
        """Test creating development middleware"""
        app = Mock()
        middleware = create_security_middleware(
            app=app,
            environment=SecurityEnvironment.DEVELOPMENT
        )
        
        assert isinstance(middleware, SecurityMiddleware)
        assert middleware.config.log_level == "DEBUG"
        # Development should have more permissive settings
        assert middleware.config.rate_limit_requests >= 100
    
    def test_create_production_middleware(self):
        """Test creating production middleware"""
        app = Mock()
        middleware = create_security_middleware(
            app=app,
            environment=SecurityEnvironment.PRODUCTION
        )
        
        assert isinstance(middleware, SecurityMiddleware)
        assert middleware.config.log_level == "WARNING"
        # Production should have stricter settings
        assert middleware.config.rate_limit_requests <= 100
    
    def test_create_high_security_middleware(self):
        """Test creating high security middleware"""
        app = Mock()
        middleware = create_security_middleware(
            app=app,
            environment=SecurityEnvironment.HIGH_SECURITY
        )
        
        assert isinstance(middleware, SecurityMiddleware)
        # High security should have all components enabled
        assert middleware.config.waf_enabled is True
        assert middleware.config.bot_detection_enabled is True
        assert middleware.config.ip_blocklist_enabled is True
        assert middleware.config.rate_limiting_enabled is True
    
    def test_create_middleware_with_custom_config(self):
        """Test creating middleware with custom configuration"""
        app = Mock()
        custom_config = SecurityConfig(
            waf_enabled=True,
            bot_detection_enabled=False,
            rate_limit_requests=50
        )
        
        middleware = create_security_middleware(
            app=app,
            config=custom_config
        )
        
        assert middleware.config == custom_config
        assert middleware.config.rate_limit_requests == 50


class TestConfigurationPresets:
    """Test configuration preset classes"""
    
    def test_development_config(self):
        """Test development configuration preset"""
        config = DevelopmentConfig()
        
        assert config.log_level == "DEBUG"
        assert config.rate_limit_requests >= 100  # More permissive
        assert config.bot_detection_mode == "permissive"
        # Should allow localhost by default
        assert "127.0.0.1" in config.ip_whitelist
        assert "localhost" in config.ip_whitelist
    
    def test_production_config(self):
        """Test production configuration preset"""
        config = ProductionConfig()
        
        assert config.log_level == "WARNING"
        assert config.rate_limit_requests <= 100  # More restrictive
        assert config.bot_detection_mode == "balanced"
        assert config.waf_enabled is True
        assert config.security_headers_enabled is True
    
    def test_high_security_config(self):
        """Test high security configuration preset"""
        config = HighSecurityConfig()
        
        assert config.log_level == "ERROR"
        assert config.rate_limit_requests <= 50  # Very restrictive
        assert config.bot_detection_mode == "strict"
        assert config.waf_enabled is True
        assert config.bot_detection_enabled is True
        assert config.ip_blocklist_enabled is True
        assert config.block_private_networks is True


class TestMiddlewareIntegration:
    """Integration tests for complete middleware stack"""
    
    @pytest.mark.asyncio
    async def test_full_security_stack(self):
        """Test full security stack with all components"""
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello"}
        
        @app.get("/api/data")
        async def get_data():
            return {"data": "sensitive"}
        
        # Add middleware with all components
        app.add_middleware(
            SecurityMiddleware,
            config=SecurityConfig(
                waf_enabled=True,
                bot_detection_enabled=True,
                ip_blocklist_enabled=True,
                rate_limiting_enabled=True,
                security_headers_enabled=True,
                rate_limit_requests=5
            )
        )
        
        client = TestClient(app)
        
        # Test 1: Normal request passes all checks
        response = client.get(
            "/",
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/91.0"}
        )
        assert response.status_code == 200
        assert "X-Content-Type-Options" in response.headers
        
        # Test 2: Malicious bot blocked
        response = client.get(
            "/api/data",
            headers={"User-Agent": "sqlmap/1.0"}
        )
        assert response.status_code == 403
        
        # Test 3: SQL injection blocked by WAF
        response = client.get(
            "/api/data?filter=' OR 1=1--",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        assert response.status_code == 403
        
        # Test 4: Rate limiting works
        for i in range(5):
            response = client.get("/", headers={"User-Agent": "Mozilla/5.0"})
            if i < 5:
                assert response.status_code == 200
            else:
                assert response.status_code == 429
    
    @pytest.mark.asyncio
    async def test_performance_impact(self):
        """Test performance impact of security middleware"""
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello"}
        
        # Create two test clients - one with and one without middleware
        app_with_security = FastAPI()
        
        @app_with_security.get("/")
        async def root_secure():
            return {"message": "Hello"}
        
        app_with_security.add_middleware(
            SecurityMiddleware,
            config=SecurityConfig(
                waf_enabled=True,
                bot_detection_enabled=True,
                rate_limiting_enabled=True
            )
        )
        
        client_plain = TestClient(app)
        client_secure = TestClient(app_with_security)
        
        import time
        
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
        
        # Security overhead should be reasonable (less than 100% slower)
        overhead_ratio = secure_time / plain_time
        assert overhead_ratio < 2.0  # Less than 2x slower
    
    @pytest.mark.asyncio
    async def test_graceful_degradation(self):
        """Test that middleware degrades gracefully when components fail"""
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello"}
        
        middleware = SecurityMiddleware(
            app=app,
            config=SecurityConfig(
                waf_enabled=True,
                bot_detection_enabled=True,
                ip_blocklist_enabled=True
            )
        )
        
        # Simulate component failures
        if middleware.waf:
            middleware.waf.analyze_request = AsyncMock(side_effect=Exception("WAF down"))
        
        if middleware.bot_detector:
            middleware.bot_detector.analyze_user_agent = Mock(side_effect=Exception("Bot detector down"))
        
        if middleware.ip_blocklist:
            middleware.ip_blocklist.is_blocked = Mock(side_effect=Exception("Blocklist down"))
        
        # Middleware should still allow requests (fail open)
        client = TestClient(app)
        response = client.get("/")
        
        assert response.status_code == 200
        assert response.json() == {"message": "Hello"}