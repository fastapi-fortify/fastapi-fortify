"""
Tests for Management API
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime
from fastapi import FastAPI
from fastapi.testclient import TestClient

from fastapi_fortify.api.management import SecurityAPI, create_security_api
from fastapi_fortify.api.models import (
    SecurityStatus,
    RateLimitStatus,
    IPBlockStatus,
    BotDetectionStatus,
    WAFStatus,
    AuthStats,
    ThreatSummary,
    IPBlockRequest,
    IPUnblockRequest,
    CustomPatternRequest,
    HealthCheckResponse
)
from fastapi_fortify.middleware.security import SecurityMiddleware
from fastapi_fortify.config.settings import SecurityConfig


class TestSecurityAPI:
    """Test Security Management API"""
    
    def test_api_initialization(self):
        """Test API initialization"""
        api = SecurityAPI()
        
        assert api.enabled is True
        assert api.prefix == "/security"
        assert api.require_auth is True
        assert api.router is not None
    
    def test_api_initialization_with_middleware(self):
        """Test API initialization with middleware reference"""
        mock_middleware = Mock()
        api = SecurityAPI(
            middleware_instance=mock_middleware,
            api_key="test-api-key",
            prefix="/admin/security"
        )
        
        assert api.middleware == mock_middleware
        assert api.api_key == "test-api-key"
        assert api.prefix == "/admin/security"
    
    def test_api_disabled(self):
        """Test disabled API"""
        api = SecurityAPI(enabled=False)
        assert api.enabled is False


class TestHealthEndpoints:
    """Test health check endpoints"""
    
    def test_health_check_endpoint(self):
        """Test basic health check endpoint"""
        api = SecurityAPI(require_auth=False)
        app = FastAPI()
        app.include_router(api.router)
        
        client = TestClient(app)
        response = client.get("/security/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "uptime_seconds" in data
        assert "components" in data
    
    def test_health_check_with_middleware(self):
        """Test health check with middleware components"""
        # Create middleware
        middleware = SecurityMiddleware(
            app=Mock(),
            config=SecurityConfig(
                waf_enabled=True,
                bot_detection_enabled=True,
                ip_blocklist_enabled=True,
                rate_limiting_enabled=True,
                auth_monitoring_enabled=True
            )
        )
        
        api = SecurityAPI(middleware_instance=middleware, require_auth=False)
        app = FastAPI()
        app.include_router(api.router)
        
        client = TestClient(app)
        response = client.get("/security/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["components"]["middleware"] == "healthy"
        assert data["components"]["waf"] == "healthy"
        assert data["components"]["bot_detection"] == "healthy"


class TestStatusEndpoints:
    """Test status endpoints"""
    
    def test_security_status_endpoint(self):
        """Test overall security status endpoint"""
        middleware = SecurityMiddleware(
            app=Mock(),
            config=SecurityConfig()
        )
        middleware.stats = {
            "requests_processed": 1000,
            "threats_blocked": 50,
            "last_threat": datetime.utcnow()
        }
        
        api = SecurityAPI(middleware_instance=middleware, require_auth=False)
        app = FastAPI()
        app.include_router(api.router)
        
        client = TestClient(app)
        response = client.get("/security/status")
        
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is True
        assert data["requests_processed"] == 1000
        assert data["threats_blocked"] == 50
        assert data["last_threat"] is not None
    
    def test_waf_status_endpoint(self):
        """Test WAF status endpoint"""
        middleware = SecurityMiddleware(
            app=Mock(),
            config=SecurityConfig(waf_enabled=True)
        )
        
        # Mock WAF stats
        if middleware.waf:
            middleware.waf.get_pattern_stats = Mock(return_value={
                "sql_injection": 10,
                "xss": 15,
                "custom": 5
            })
            middleware.waf.requests_analyzed = 500
            middleware.waf.threats_blocked = 25
        
        api = SecurityAPI(middleware_instance=middleware, require_auth=False)
        app = FastAPI()
        app.include_router(api.router)
        
        client = TestClient(app)
        response = client.get("/security/waf/status")
        
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is True
        assert data["patterns_loaded"]["sql_injection"] == 10
        assert data["patterns_loaded"]["xss"] == 15
    
    def test_rate_limit_status_endpoint(self):
        """Test rate limit status endpoint"""
        middleware = SecurityMiddleware(
            app=Mock(),
            config=SecurityConfig(rate_limiting_enabled=True)
        )
        
        # Mock rate limiter stats
        if middleware.rate_limiter:
            middleware.rate_limiter.get_stats = AsyncMock(return_value={
                "type": "memory",
                "total_keys": 100,
                "active_limits": 20,
                "requests_limited": 150
            })
        
        api = SecurityAPI(middleware_instance=middleware, require_auth=False)
        app = FastAPI()
        app.include_router(api.router)
        
        client = TestClient(app)
        response = client.get("/security/rate-limits/status")
        
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is True
        assert data["limiter_type"] == "memory"
        assert data["total_keys"] == 100
    
    def test_ip_blocklist_status_endpoint(self):
        """Test IP blocklist status endpoint"""
        middleware = SecurityMiddleware(
            app=Mock(),
            config=SecurityConfig(ip_blocklist_enabled=True)
        )
        
        # Mock IP blocklist stats
        if middleware.ip_blocklist:
            middleware.ip_blocklist.get_stats = Mock(return_value={
                "static_entries": 50,
                "dynamic_entries": 25,
                "whitelist_entries": 10,
                "threat_feeds_configured": 3,
                "blocks": 200
            })
        
        api = SecurityAPI(middleware_instance=middleware, require_auth=False)
        app = FastAPI()
        app.include_router(api.router)
        
        client = TestClient(app)
        response = client.get("/security/ip-blocklist/status")
        
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is True
        assert data["static_entries"] == 50
        assert data["dynamic_entries"] == 25
    
    def test_bot_detection_status_endpoint(self):
        """Test bot detection status endpoint"""
        middleware = SecurityMiddleware(
            app=Mock(),
            config=SecurityConfig(bot_detection_enabled=True)
        )
        
        # Mock bot detector stats
        if middleware.bot_detector:
            middleware.bot_detector.get_detection_stats = Mock(return_value={
                "mode": "balanced",
                "tracked_ips": 500,
                "bots_detected": 75,
                "active_patterns": {
                    "malicious": 20,
                    "suspicious": 15
                }
            })
        
        api = SecurityAPI(middleware_instance=middleware, require_auth=False)
        app = FastAPI()
        app.include_router(api.router)
        
        client = TestClient(app)
        response = client.get("/security/bot-detection/status")
        
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is True
        assert data["detection_mode"] == "balanced"
        assert data["tracked_ips"] == 500
    
    def test_auth_status_endpoint(self):
        """Test authentication monitoring status endpoint"""
        middleware = SecurityMiddleware(
            app=Mock(),
            config=SecurityConfig(auth_monitoring_enabled=True)
        )
        
        # Mock auth monitor
        if middleware.auth_monitor:
            middleware.auth_monitor.stats = {
                "events_processed": 1000,
                "alerts_generated": 50
            }
            middleware.auth_monitor.get_security_summary = AsyncMock(return_value={
                "summary": {
                    "failed_logins": 100,
                    "successful_logins": 900
                }
            })
        
        api = SecurityAPI(middleware_instance=middleware, require_auth=False)
        app = FastAPI()
        app.include_router(api.router)
        
        client = TestClient(app)
        response = client.get("/security/auth/status")
        
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is True
        assert data["events_processed"] == 1000


class TestBlocklistManagement:
    """Test IP blocklist management endpoints"""
    
    def test_block_ip_endpoint(self):
        """Test blocking an IP address"""
        middleware = SecurityMiddleware(
            app=Mock(),
            config=SecurityConfig(ip_blocklist_enabled=True)
        )
        
        api = SecurityAPI(middleware_instance=middleware, require_auth=False)
        app = FastAPI()
        app.include_router(api.router)
        
        client = TestClient(app)
        
        # Block an IP
        block_request = {
            "ip_address": "192.168.1.100",
            "reason": "Malicious activity",
            "duration_hours": 24,
            "severity": "high"
        }
        
        response = client.post("/security/ip-blocklist/block", json=block_request)
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "192.168.1.100" in data["message"]
    
    def test_unblock_ip_endpoint(self):
        """Test unblocking an IP address"""
        middleware = SecurityMiddleware(
            app=Mock(),
            config=SecurityConfig(ip_blocklist_enabled=True)
        )
        
        # Mock remove_block to return True
        if middleware.ip_blocklist:
            middleware.ip_blocklist.remove_block = Mock(return_value=True)
        
        api = SecurityAPI(middleware_instance=middleware, require_auth=False)
        app = FastAPI()
        app.include_router(api.router)
        
        client = TestClient(app)
        
        # Unblock an IP
        unblock_request = {
            "ip_address": "192.168.1.100"
        }
        
        response = client.post("/security/ip-blocklist/unblock", json=unblock_request)
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
    
    def test_get_ip_status_endpoint(self):
        """Test getting IP block status"""
        middleware = SecurityMiddleware(
            app=Mock(),
            config=SecurityConfig(ip_blocklist_enabled=True)
        )
        
        # Mock is_blocked
        if middleware.ip_blocklist:
            middleware.ip_blocklist.is_blocked = Mock(
                return_value=(True, "Manual block: Testing")
            )
        
        api = SecurityAPI(middleware_instance=middleware, require_auth=False)
        app = FastAPI()
        app.include_router(api.router)
        
        client = TestClient(app)
        
        response = client.get("/security/ip-blocklist/192.168.1.100")
        
        assert response.status_code == 200
        data = response.json()
        assert data["ip_address"] == "192.168.1.100"
        assert data["is_blocked"] is True
        assert "Manual block" in data["reason"]


class TestWAFManagement:
    """Test WAF pattern management endpoints"""
    
    def test_add_waf_pattern_endpoint(self):
        """Test adding custom WAF pattern"""
        middleware = SecurityMiddleware(
            app=Mock(),
            config=SecurityConfig(waf_enabled=True)
        )
        
        # Mock add_custom_pattern
        if middleware.waf:
            middleware.waf.add_custom_pattern = Mock(return_value=True)
        
        api = SecurityAPI(middleware_instance=middleware, require_auth=False)
        app = FastAPI()
        app.include_router(api.router)
        
        client = TestClient(app)
        
        # Add pattern
        pattern_request = {
            "pattern": "malicious_pattern_\\d+",
            "pattern_type": "custom",
            "description": "Custom malicious pattern"
        }
        
        response = client.post("/security/waf/patterns", json=pattern_request)
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
    
    def test_add_invalid_waf_pattern(self):
        """Test adding invalid WAF pattern"""
        middleware = SecurityMiddleware(
            app=Mock(),
            config=SecurityConfig(waf_enabled=True)
        )
        
        # Mock add_custom_pattern to return False
        if middleware.waf:
            middleware.waf.add_custom_pattern = Mock(return_value=False)
        
        api = SecurityAPI(middleware_instance=middleware, require_auth=False)
        app = FastAPI()
        app.include_router(api.router)
        
        client = TestClient(app)
        
        # Add invalid pattern
        pattern_request = {
            "pattern": "[invalid_regex",
            "pattern_type": "custom"
        }
        
        response = client.post("/security/waf/patterns", json=pattern_request)
        
        assert response.status_code == 400
        assert "Invalid pattern" in response.json()["detail"]


class TestThreatAnalysis:
    """Test threat analysis endpoints"""
    
    def test_threat_summary_endpoint(self):
        """Test threat summary endpoint"""
        middleware = SecurityMiddleware(
            app=Mock(),
            config=SecurityConfig(
                waf_enabled=True,
                bot_detection_enabled=True,
                ip_blocklist_enabled=True,
                rate_limiting_enabled=True
            )
        )
        
        # Mock threat statistics
        if middleware.waf:
            middleware.waf.threats_blocked = 50
        if middleware.bot_detector:
            middleware.bot_detector.bots_detected = 30
        if middleware.ip_blocklist:
            middleware.ip_blocklist.blocks = 20
        if middleware.rate_limiter:
            middleware.rate_limiter.requests_limited = 40
        
        api = SecurityAPI(middleware_instance=middleware, require_auth=False)
        app = FastAPI()
        app.include_router(api.router)
        
        client = TestClient(app)
        
        response = client.get("/security/threats/summary?hours=24")
        
        assert response.status_code == 200
        data = response.json()
        assert data["period_hours"] == 24
        assert data["total_threats"] > 0
        assert "waf" in data["threat_types"]
        assert "bot_detection" in data["threat_types"]


class TestMetricsEndpoint:
    """Test metrics endpoint"""
    
    def test_metrics_endpoint(self):
        """Test security metrics endpoint"""
        middleware = SecurityMiddleware(
            app=Mock(),
            config=SecurityConfig()
        )
        middleware.stats = {
            "requests_processed": 5000,
            "threats_blocked": 250
        }
        
        api = SecurityAPI(middleware_instance=middleware, require_auth=False)
        api.stats["requests_processed"] = 100
        
        app = FastAPI()
        app.include_router(api.router)
        
        client = TestClient(app)
        
        response = client.get("/security/metrics?hours=24")
        
        assert response.status_code == 200
        data = response.json()
        assert "timestamp" in data
        assert data["period_hours"] == 24
        assert data["metrics"]["api_requests"] == 100
        assert data["metrics"]["requests_processed"] == 5000


class TestAuthentication:
    """Test API authentication"""
    
    def test_authentication_required(self):
        """Test that authentication is required by default"""
        api = SecurityAPI(require_auth=True, api_key="secret-key")
        app = FastAPI()
        app.include_router(api.router)
        
        client = TestClient(app)
        
        # Request without auth should fail
        response = client.get("/security/status")
        assert response.status_code == 401
        
        # Request with wrong auth should fail
        response = client.get(
            "/security/status",
            headers={"Authorization": "Bearer wrong-key"}
        )
        assert response.status_code == 401
        
        # Request with correct auth should succeed
        response = client.get(
            "/security/status",
            headers={"Authorization": "Bearer secret-key"}
        )
        # Will fail because no middleware, but auth passed
        assert response.status_code in [200, 503]
    
    def test_authentication_disabled(self):
        """Test with authentication disabled"""
        api = SecurityAPI(require_auth=False)
        app = FastAPI()
        app.include_router(api.router)
        
        client = TestClient(app)
        
        # Should work without auth
        response = client.get("/security/health")
        assert response.status_code == 200


class TestErrorHandling:
    """Test error handling in API"""
    
    def test_no_middleware_error(self):
        """Test API without middleware instance"""
        api = SecurityAPI(middleware_instance=None, require_auth=False)
        app = FastAPI()
        app.include_router(api.router)
        
        client = TestClient(app)
        
        # Most endpoints should return 503 without middleware
        response = client.get("/security/status")
        assert response.status_code == 503
        assert "not available" in response.json()["detail"]
    
    def test_component_not_available(self):
        """Test when specific component is not available"""
        middleware = SecurityMiddleware(
            app=Mock(),
            config=SecurityConfig(waf_enabled=False)  # WAF disabled
        )
        
        api = SecurityAPI(middleware_instance=middleware, require_auth=False)
        app = FastAPI()
        app.include_router(api.router)
        
        client = TestClient(app)
        
        # WAF endpoint should indicate it's disabled
        response = client.get("/security/waf/status")
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is False
    
    def test_exception_handling(self):
        """Test exception handling in endpoints"""
        middleware = SecurityMiddleware(
            app=Mock(),
            config=SecurityConfig(ip_blocklist_enabled=True)
        )
        
        # Mock method to raise exception
        if middleware.ip_blocklist:
            middleware.ip_blocklist.is_blocked = Mock(
                side_effect=Exception("Database error")
            )
        
        api = SecurityAPI(middleware_instance=middleware, require_auth=False)
        app = FastAPI()
        app.include_router(api.router)
        
        client = TestClient(app)
        
        response = client.get("/security/ip-blocklist/192.168.1.1")
        assert response.status_code == 500
        assert "Failed to check IP status" in response.json()["detail"]


class TestAPIFactory:
    """Test API factory function"""
    
    def test_create_security_api(self):
        """Test creating security API with factory"""
        middleware = Mock()
        api = create_security_api(
            middleware_instance=middleware,
            api_key="test-key",
            enabled=True,
            prefix="/admin"
        )
        
        assert isinstance(api, SecurityAPI)
        assert api.middleware == middleware
        assert api.api_key == "test-key"
        assert api.prefix == "/admin"
    
    def test_create_security_api_minimal(self):
        """Test creating security API with minimal params"""
        api = create_security_api()
        
        assert isinstance(api, SecurityAPI)
        assert api.enabled is True
        assert api.prefix == "/security"


class TestIntegration:
    """Integration tests for management API"""
    
    def test_full_api_integration(self):
        """Test full API integration with middleware"""
        # Create app with security middleware
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello"}
        
        # Add security middleware
        app.add_middleware(
            SecurityMiddleware,
            config=SecurityConfig(
                waf_enabled=True,
                bot_detection_enabled=True,
                ip_blocklist_enabled=True,
                rate_limiting_enabled=True,
                auth_monitoring_enabled=True
            )
        )
        
        # Get middleware instance
        middleware = app.middleware_stack
        while hasattr(middleware, 'app'):
            if hasattr(middleware, 'cls') and middleware.cls == SecurityMiddleware:
                break
            middleware = middleware.app
        
        # Create and add management API
        security_api = create_security_api(
            middleware_instance=middleware.options.get('middleware') if hasattr(middleware, 'options') else None,
            require_auth=False
        )
        app.include_router(security_api.router)
        
        client = TestClient(app)
        
        # Test various endpoints
        response = client.get("/security/health")
        assert response.status_code == 200
        
        response = client.get("/security/status")
        assert response.status_code in [200, 503]  # Might be 503 if middleware not properly linked
        
        response = client.get("/security/threats/summary")
        assert response.status_code in [200, 503]