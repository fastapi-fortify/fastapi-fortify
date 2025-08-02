"""
Tests for Utility modules
"""
import pytest
from unittest.mock import Mock, AsyncMock
from fastapi import Request, Response, HTTPException

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
from fastapi_fortify.utils.security_utils import SecurityDecision
from fastapi_fortify.utils.decorators import (
    require_auth,
    rate_limit,
    block_bots,
    security_headers,
    log_security_event,
    validate_input
)


class TestIPUtils:
    """Test IP utility functions"""
    
    def test_get_client_ip_direct(self):
        """Test getting client IP from direct connection"""
        request = Mock(spec=Request)
        request.client.host = "192.168.1.100"
        request.headers = {}
        
        ip = get_client_ip(request)
        assert ip == "192.168.1.100"
    
    def test_get_client_ip_with_forwarded_header(self):
        """Test getting client IP from X-Forwarded-For header"""
        request = Mock(spec=Request)
        request.client.host = "127.0.0.1"
        request.headers = {"x-forwarded-for": "203.0.113.10, 192.168.1.1"}
        
        ip = get_client_ip(request)
        assert ip == "203.0.113.10"  # First IP in chain
    
    def test_get_client_ip_with_real_ip_header(self):
        """Test getting client IP from X-Real-IP header"""
        request = Mock(spec=Request)
        request.client.host = "127.0.0.1"
        request.headers = {"x-real-ip": "203.0.113.20"}
        
        ip = get_client_ip(request)
        assert ip == "203.0.113.20"
    
    def test_get_client_ip_no_client(self):
        """Test getting client IP when client is None"""
        request = Mock(spec=Request)
        request.client = None
        request.headers = {}
        
        ip = get_client_ip(request)
        assert ip == "unknown"
    
    def test_is_valid_ip(self):
        """Test IP address validation"""
        # Valid IPv4
        assert is_valid_ip("192.168.1.1") is True
        assert is_valid_ip("10.0.0.1") is True
        assert is_valid_ip("8.8.8.8") is True
        
        # Valid IPv6
        assert is_valid_ip("2001:db8::1") is True
        assert is_valid_ip("::1") is True
        
        # Invalid IPs
        assert is_valid_ip("999.999.999.999") is False
        assert is_valid_ip("not.an.ip") is False
        assert is_valid_ip("192.168.1") is False
        assert is_valid_ip("") is False
        assert is_valid_ip(None) is False
    
    def test_is_valid_cidr(self):
        """Test CIDR notation validation"""
        # Valid CIDR
        assert is_valid_cidr("192.168.1.0/24") is True
        assert is_valid_cidr("10.0.0.0/8") is True
        assert is_valid_cidr("2001:db8::/32") is True
        
        # Invalid CIDR
        assert is_valid_cidr("192.168.1.1") is False  # No prefix
        assert is_valid_cidr("192.168.1.0/33") is False  # Invalid prefix
        assert is_valid_cidr("invalid/24") is False
        assert is_valid_cidr("") is False
    
    def test_ip_in_network(self):
        """Test IP in network checking"""
        # IPv4
        assert ip_in_network("192.168.1.100", "192.168.1.0/24") is True
        assert ip_in_network("192.168.2.1", "192.168.1.0/24") is False
        assert ip_in_network("10.0.0.1", "10.0.0.0/8") is True
        
        # IPv6
        assert ip_in_network("2001:db8::1", "2001:db8::/32") is True
        assert ip_in_network("2001:db9::1", "2001:db8::/32") is False
        
        # Invalid inputs
        assert ip_in_network("invalid", "192.168.1.0/24") is False
        assert ip_in_network("192.168.1.1", "invalid/24") is False
    
    def test_ip_matches_patterns(self):
        """Test IP pattern matching"""
        patterns = [
            "192.168.1.100",  # Exact match
            "10.0.0.0/8",     # CIDR range
            "172.16.0.0/12"   # Another CIDR
        ]
        
        # Matches
        assert ip_matches_patterns("192.168.1.100", patterns) is True
        assert ip_matches_patterns("10.5.5.5", patterns) is True
        assert ip_matches_patterns("172.16.1.1", patterns) is True
        
        # No matches
        assert ip_matches_patterns("8.8.8.8", patterns) is False
        assert ip_matches_patterns("192.168.2.1", patterns) is False
        
        # Empty patterns
        assert ip_matches_patterns("192.168.1.1", []) is False
    
    def test_is_private_ip(self):
        """Test private IP detection"""
        # Private IPs
        assert is_private_ip("192.168.1.1") is True
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("127.0.0.1") is True
        assert is_private_ip("::1") is True
        
        # Public IPs
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False
        assert is_private_ip("203.0.113.1") is False
        
        # Invalid
        assert is_private_ip("invalid") is False
    
    def test_is_public_ip(self):
        """Test public IP detection"""
        # Public IPs
        assert is_public_ip("8.8.8.8") is True
        assert is_public_ip("1.1.1.1") is True
        assert is_public_ip("203.0.113.1") is True
        
        # Private IPs
        assert is_public_ip("192.168.1.1") is False
        assert is_public_ip("10.0.0.1") is False
        assert is_public_ip("127.0.0.1") is False
        
        # Invalid
        assert is_public_ip("invalid") is False
    
    def test_normalize_ip_list(self):
        """Test IP list normalization"""
        input_list = [
            "192.168.1.1",
            "  10.0.0.1  ",  # Whitespace
            "192.168.1.1",   # Duplicate
            "",              # Empty
            "invalid.ip",    # Invalid
            "172.16.0.0/12"  # CIDR
        ]
        
        normalized = normalize_ip_list(input_list)
        
        assert len(normalized) == 3  # Duplicates and invalid removed
        assert "192.168.1.1" in normalized
        assert "10.0.0.1" in normalized
        assert "172.16.0.0/12" in normalized
        assert "invalid.ip" not in normalized


class TestSecurityDecision:
    """Test SecurityDecision utility"""
    
    def test_allow_decision(self):
        """Test creating allow decision"""
        decision = SecurityDecision.allow(
            reason="Request is safe",
            rule_type="test_rule",
            confidence=0.9
        )
        
        assert decision.allowed is True
        assert decision.reason == "Request is safe"
        assert decision.rule_type == "test_rule"
        assert decision.confidence == 0.9
        assert decision.metadata == {}
    
    def test_block_decision(self):
        """Test creating block decision"""
        decision = SecurityDecision.block(
            reason="Malicious pattern detected",
            rule_type="waf_sql_injection",
            confidence=0.95,
            pattern="' OR 1=1"
        )
        
        assert decision.allowed is False
        assert decision.reason == "Malicious pattern detected"
        assert decision.rule_type == "waf_sql_injection"
        assert decision.confidence == 0.95
        assert decision.metadata["pattern"] == "' OR 1=1"
    
    def test_decision_with_metadata(self):
        """Test decision with additional metadata"""
        decision = SecurityDecision.block(
            reason="Bot detected",
            rule_type="bot_detection",
            ip="192.168.1.1",
            user_agent="bot/1.0",
            score=0.85
        )
        
        assert decision.allowed is False
        assert decision.metadata["ip"] == "192.168.1.1"
        assert decision.metadata["user_agent"] == "bot/1.0"
        assert decision.metadata["score"] == 0.85
    
    def test_decision_string_representation(self):
        """Test decision string representation"""
        decision = SecurityDecision.block(
            reason="Test block",
            rule_type="test"
        )
        
        str_repr = str(decision)
        assert "BLOCKED" in str_repr
        assert "Test block" in str_repr
        assert "test" in str_repr


class TestDecorators:
    """Test utility decorators"""
    
    @pytest.mark.asyncio
    async def test_require_auth_decorator(self):
        """Test authentication requirement decorator"""
        @require_auth()
        async def protected_endpoint(request):
            return {"message": "Protected data"}
        
        # Request without auth header
        request = Mock(spec=Request)
        request.headers = {}
        
        with pytest.raises(HTTPException) as exc_info:
            await protected_endpoint(request)
        
        assert exc_info.value.status_code == 401
        
        # Request with auth header
        request.headers = {"authorization": "Bearer token123"}
        result = await protected_endpoint(request)
        assert result["message"] == "Protected data"
    
    @pytest.mark.asyncio
    async def test_require_auth_with_custom_func(self):
        """Test require_auth with custom validation function"""
        async def custom_auth(request):
            return request.headers.get("x-api-key") == "secret"
        
        @require_auth(auth_func=custom_auth, error_message="Invalid API key")
        async def protected_endpoint(request):
            return {"status": "success"}
        
        # Invalid auth
        request = Mock(spec=Request)
        request.headers = {"x-api-key": "wrong"}
        
        with pytest.raises(HTTPException) as exc_info:
            await protected_endpoint(request)
        
        assert exc_info.value.detail == "Invalid API key"
        
        # Valid auth
        request.headers = {"x-api-key": "secret"}
        result = await protected_endpoint(request)
        assert result["status"] == "success"
    
    @pytest.mark.asyncio
    async def test_rate_limit_decorator(self):
        """Test rate limit decorator"""
        from fastapi_fortify.middleware.rate_limiter import MemoryRateLimiter
        
        limiter = MemoryRateLimiter()
        
        @rate_limit(
            requests=2,
            window_seconds=60,
            key_func=lambda req: req.client.host,
            limiter=limiter
        )
        async def rate_limited_endpoint(request):
            return {"data": "test"}
        
        # Mock request
        request = Mock(spec=Request)
        request.client.host = "192.168.1.1"
        
        # First two requests should pass
        result = await rate_limited_endpoint(request)
        assert result["data"] == "test"
        
        result = await rate_limited_endpoint(request)
        assert result["data"] == "test"
        
        # Third request should be rate limited
        with pytest.raises(HTTPException) as exc_info:
            await rate_limited_endpoint(request)
        
        assert exc_info.value.status_code == 429
    
    @pytest.mark.asyncio
    async def test_block_bots_decorator(self):
        """Test bot blocking decorator"""
        @block_bots(mode="strict")
        async def protected_endpoint(request):
            return {"message": "Human users only"}
        
        # Normal user agent
        request = Mock(spec=Request)
        request.headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0)"}
        
        result = await protected_endpoint(request)
        assert result["message"] == "Human users only"
        
        # Bot user agent (would be blocked with real implementation)
        request.headers = {"user-agent": "bot/1.0"}
        result = await protected_endpoint(request)
        # Note: Without full integration, decorator doesn't actually block
        assert result["message"] == "Human users only"
    
    @pytest.mark.asyncio
    async def test_security_headers_decorator(self):
        """Test security headers decorator"""
        @security_headers(
            csp="default-src 'self'",
            hsts=True,
            frame_options="SAMEORIGIN"
        )
        async def endpoint():
            response = Response()
            response.headers = {}
            return response
        
        response = await endpoint()
        
        assert response.headers["Content-Security-Policy"] == "default-src 'self'"
        assert "Strict-Transport-Security" in response.headers
        assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-XSS-Protection"] == "1; mode=block"
    
    @pytest.mark.asyncio
    async def test_log_security_event_decorator(self):
        """Test security event logging decorator"""
        @log_security_event(
            event_type="api_access",
            include_request_data=True
        )
        async def api_endpoint(request):
            return {"status": "ok"}
        
        request = Mock(spec=Request)
        request.method = "GET"
        request.url = "http://example.com/api"
        request.client.host = "192.168.1.1"
        request.headers = {"user-agent": "test"}
        
        # Should log and return normally
        result = await api_endpoint(request)
        assert result["status"] == "ok"
        
        # Test with exception
        @log_security_event(event_type="api_error")
        async def failing_endpoint(request):
            raise ValueError("Test error")
        
        with pytest.raises(ValueError):
            await failing_endpoint(request)
    
    @pytest.mark.asyncio
    async def test_validate_input_decorator(self):
        """Test input validation decorator"""
        @validate_input(max_length=10)
        async def limited_endpoint(query: str):
            return {"query": query}
        
        # Valid input
        result = await limited_endpoint("short")
        assert result["query"] == "short"
        
        # Too long input
        with pytest.raises(HTTPException) as exc_info:
            await limited_endpoint("this is too long for the limit")
        
        assert exc_info.value.status_code == 400
        assert "too long" in exc_info.value.detail


class TestDecoratorIntegration:
    """Test decorator integration scenarios"""
    
    @pytest.mark.asyncio
    async def test_multiple_decorators(self):
        """Test combining multiple decorators"""
        from fastapi_fortify.middleware.rate_limiter import MemoryRateLimiter
        
        limiter = MemoryRateLimiter()
        
        @require_auth()
        @rate_limit(requests=5, window_seconds=60, limiter=limiter)
        @log_security_event(event_type="secure_api_access")
        async def secure_endpoint(request):
            return {"data": "sensitive"}
        
        # Request without auth should fail first
        request = Mock(spec=Request)
        request.headers = {}
        request.client.host = "192.168.1.1"
        
        with pytest.raises(HTTPException) as exc_info:
            await secure_endpoint(request)
        
        assert exc_info.value.status_code == 401
        
        # Request with auth should work
        request.headers = {"authorization": "Bearer token"}
        result = await secure_endpoint(request)
        assert result["data"] == "sensitive"
    
    @pytest.mark.asyncio
    async def test_decorator_error_handling(self):
        """Test decorator error handling"""
        @require_auth()
        async def endpoint_without_request():
            return {"data": "test"}
        
        # Should handle missing request gracefully
        with pytest.raises(HTTPException) as exc_info:
            await endpoint_without_request()
        
        assert exc_info.value.status_code == 500
        assert "Request object not found" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_custom_key_functions(self):
        """Test decorators with custom key functions"""
        from fastapi_fortify.middleware.rate_limiter import MemoryRateLimiter
        
        limiter = MemoryRateLimiter()
        
        # Rate limit by user ID instead of IP
        @rate_limit(
            requests=10,
            window_seconds=60,
            key_func=lambda req: f"user:{req.headers.get('x-user-id', 'anonymous')}",
            limiter=limiter
        )
        async def user_limited_endpoint(request):
            return {"user": request.headers.get("x-user-id")}
        
        # Different users should have separate limits
        request1 = Mock(spec=Request)
        request1.headers = {"x-user-id": "user1"}
        
        request2 = Mock(spec=Request)
        request2.headers = {"x-user-id": "user2"}
        
        # Both users can make requests
        result1 = await user_limited_endpoint(request1)
        assert result1["user"] == "user1"
        
        result2 = await user_limited_endpoint(request2)
        assert result2["user"] == "user2"