"""
Tests for WAF Protection module
"""
import pytest
from unittest.mock import Mock, AsyncMock
from fastapi import Request

from fastapi_fortify.protection.waf import WAFProtection, create_waf_protection
from fastapi_fortify.utils.security_utils import SecurityDecision


class TestWAFProtection:
    """Test WAF protection functionality"""
    
    def test_waf_initialization(self):
        """Test WAF initialization with various configurations"""
        # Basic initialization
        waf = WAFProtection()
        assert waf.block_mode is True
        assert waf.case_sensitive is False
        assert len(waf._compiled_patterns) > 0
        
        # Custom initialization
        custom_patterns = ["test_pattern_\\d+"]
        exclusions = ["/api/webhook/*"]
        waf = WAFProtection(
            custom_patterns=custom_patterns,
            exclusions=exclusions,
            block_mode=False,
            case_sensitive=True
        )
        assert waf.block_mode is False
        assert waf.case_sensitive is True
        assert waf.custom_patterns == custom_patterns
        assert waf.exclusions == exclusions
    
    def test_pattern_compilation(self):
        """Test regex pattern compilation"""
        waf = WAFProtection(custom_patterns=["valid_pattern"])
        
        # Should have compiled patterns for all categories
        expected_categories = [
            "sql_injection", "xss", "path_traversal", 
            "command_injection", "rce", "lfi", "exploit_paths", "custom"
        ]
        
        for category in expected_categories:
            assert category in waf._compiled_patterns
            assert len(waf._compiled_patterns[category]) > 0
    
    def test_invalid_pattern_handling(self):
        """Test handling of invalid regex patterns"""
        # Invalid pattern should be skipped
        waf = WAFProtection(custom_patterns=["[invalid_regex"])
        
        # Should still initialize successfully
        assert waf is not None
        # Custom patterns should be empty due to invalid regex
        assert len(waf._compiled_patterns["custom"]) == 0
    
    @pytest.mark.asyncio
    async def test_path_exclusion(self):
        """Test path exclusion from WAF checks"""
        waf = WAFProtection(exclusions=["/api/webhook/*", "/health"])
        
        # Mock request with excluded path
        request = Mock(spec=Request)
        request.url.path = "/api/webhook/clerk"
        
        result = await waf.analyze_request(request)
        assert result.allowed is True
        assert result.rule_type == "waf_exclusion"
    
    @pytest.mark.asyncio
    async def test_sql_injection_detection(self, malicious_payloads):
        """Test SQL injection detection in various parts of request"""
        waf = WAFProtection()
        
        for payload in malicious_payloads["sql_injection"]:
            # Test in URL path
            request = Mock(spec=Request)
            request.url.path = f"/search/{payload}"
            request.url.query = ""
            request.headers = {"user-agent": "test"}
            request.method = "GET"
            request.body = AsyncMock(return_value=b"")
            
            result = await waf.analyze_request(request)
            assert result.allowed is False
            assert "sql" in result.rule_type.lower() or "exploit" in result.rule_type.lower()
            
            # Test in query parameters
            request.url.path = "/search"
            request.url.query = f"q={payload}"
            
            result = await waf.analyze_request(request)
            assert result.allowed is False
            assert result.rule_type in ["waf_sqli", "waf_exploit_path"]
    
    @pytest.mark.asyncio
    async def test_xss_detection(self, malicious_payloads):
        """Test XSS detection"""
        waf = WAFProtection()
        
        for payload in malicious_payloads["xss"]:
            request = Mock(spec=Request)
            request.url.path = "/"
            request.url.query = f"input={payload}"
            request.headers = {"user-agent": "test"}
            request.method = "GET"
            request.body = AsyncMock(return_value=b"")
            
            result = await waf.analyze_request(request)
            assert result.allowed is False
            assert result.rule_type == "waf_xss"
    
    @pytest.mark.asyncio
    async def test_path_traversal_detection(self, malicious_payloads):
        """Test path traversal detection"""
        waf = WAFProtection()
        
        for payload in malicious_payloads["path_traversal"]:
            request = Mock(spec=Request)
            request.url.path = f"/file/{payload}"
            request.url.query = ""
            request.headers = {"user-agent": "test"}
            request.method = "GET"
            request.body = AsyncMock(return_value=b"")
            
            result = await waf.analyze_request(request)
            assert result.allowed is False
            assert result.rule_type in ["waf_path_traversal", "waf_lfi", "waf_exploit_path"]
    
    @pytest.mark.asyncio
    async def test_command_injection_detection(self, malicious_payloads):
        """Test command injection detection"""
        waf = WAFProtection()
        
        for payload in malicious_payloads["command_injection"]:
            request = Mock(spec=Request)
            request.url.path = "/"
            request.url.query = f"cmd={payload}"
            request.headers = {"user-agent": "test"}
            request.method = "GET"
            request.body = AsyncMock(return_value=b"")
            
            result = await waf.analyze_request(request)
            assert result.allowed is False
            assert result.rule_type in ["waf_command_injection", "waf_rce"]
    
    @pytest.mark.asyncio
    async def test_header_analysis(self):
        """Test malicious content detection in headers"""
        waf = WAFProtection()
        
        # XSS in User-Agent header
        request = Mock(spec=Request)
        request.url.path = "/"
        request.url.query = ""
        request.headers = {"user-agent": "<script>alert('xss')</script>"}
        request.method = "GET"
        request.body = AsyncMock(return_value=b"")
        
        result = await waf.analyze_request(request)
        assert result.allowed is False
        assert result.rule_type == "waf_header_xss"
    
    @pytest.mark.asyncio
    async def test_request_body_analysis(self):
        """Test request body analysis"""
        waf = WAFProtection()
        
        # Malicious JSON payload
        malicious_json = '{"query": "SELECT * FROM users WHERE id=1 OR 1=1"}'
        
        request = Mock(spec=Request)
        request.url.path = "/api/data"
        request.url.query = ""
        request.headers = {"content-type": "application/json", "user-agent": "test"}
        request.method = "POST"
        request.body = AsyncMock(return_value=malicious_json.encode())
        
        result = await waf.analyze_request(request)
        assert result.allowed is False
        assert "body" in result.rule_type
    
    @pytest.mark.asyncio
    async def test_legitimate_requests(self):
        """Test that legitimate requests pass through"""
        waf = WAFProtection()
        
        request = Mock(spec=Request)
        request.url.path = "/api/users"
        request.url.query = "page=1&limit=10"
        request.headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "content-type": "application/json"
        }
        request.method = "GET"
        request.body = AsyncMock(return_value=b"")
        
        result = await waf.analyze_request(request)
        assert result.allowed is True
        assert result.rule_type == "waf"
    
    @pytest.mark.asyncio
    async def test_large_body_handling(self):
        """Test handling of large request bodies"""
        waf = WAFProtection()
        
        # Create a body larger than the limit (1MB)
        large_body = b"x" * (1024 * 1024 + 1)
        
        request = Mock(spec=Request)
        request.url.path = "/upload"
        request.url.query = ""
        request.headers = {"content-type": "application/octet-stream", "user-agent": "test"}
        request.method = "POST"
        request.body = AsyncMock(return_value=large_body)
        
        result = await waf.analyze_request(request)
        # Should allow (skip analysis) for large bodies
        assert result.allowed is True
        assert "too large" in result.reason.lower()
    
    @pytest.mark.asyncio
    async def test_binary_content_handling(self):
        """Test handling of binary content"""
        waf = WAFProtection()
        
        # Binary content that can't be decoded as UTF-8
        binary_data = bytes([0xFF, 0xFE, 0xFD, 0xFC] * 100)
        
        request = Mock(spec=Request)
        request.url.path = "/upload"
        request.url.query = ""
        request.headers = {"content-type": "application/octet-stream", "user-agent": "test"}
        request.method = "POST"
        request.body = AsyncMock(return_value=binary_data)
        
        result = await waf.analyze_request(request)
        # Should allow (skip analysis) for binary content
        assert result.allowed is True
        assert "binary" in result.reason.lower()
    
    def test_custom_pattern_addition(self):
        """Test adding custom patterns at runtime"""
        waf = WAFProtection()
        
        # Add valid pattern
        success = waf.add_custom_pattern(r"malicious_keyword", "custom_threats")
        assert success is True
        
        # Add invalid pattern
        success = waf.add_custom_pattern("[invalid_regex", "custom_threats")
        assert success is False
    
    def test_pattern_statistics(self):
        """Test pattern statistics retrieval"""
        waf = WAFProtection()
        
        stats = waf.get_pattern_stats()
        assert isinstance(stats, dict)
        assert "sql_injection" in stats
        assert "xss" in stats
        assert all(isinstance(count, int) for count in stats.values())
    
    def test_pattern_testing(self):
        """Test pattern testing functionality"""
        waf = WAFProtection()
        
        # Test string with multiple matches
        test_string = "SELECT * FROM users; <script>alert('xss')</script>"
        matches = waf.test_pattern_against_string(test_string)
        
        assert len(matches) >= 2  # Should match both SQL and XSS patterns
        assert any("sql" in match["pattern_type"] for match in matches)
        assert any("xss" in match["pattern_type"] for match in matches)
    
    def test_case_sensitivity(self):
        """Test case sensitivity configuration"""
        # Case insensitive (default)
        waf_insensitive = WAFProtection(case_sensitive=False)
        
        # Case sensitive
        waf_sensitive = WAFProtection(case_sensitive=True)
        
        test_payload = "SELECT * FROM USERS"
        
        # Both should detect SQL injection (patterns are designed to work both ways)
        matches_insensitive = waf_insensitive.test_pattern_against_string(test_payload)
        matches_sensitive = waf_sensitive.test_pattern_against_string(test_payload)
        
        assert len(matches_insensitive) > 0
        assert len(matches_sensitive) > 0


class TestWAFFactory:
    """Test WAF factory functions"""
    
    def test_create_waf_protection_permissive(self):
        """Test creating permissive WAF"""
        waf = create_waf_protection("permissive")
        assert waf.block_mode is True
        assert isinstance(waf, WAFProtection)
    
    def test_create_waf_protection_balanced(self):
        """Test creating balanced WAF"""
        waf = create_waf_protection("balanced")
        assert waf.block_mode is True
        assert isinstance(waf, WAFProtection)
    
    def test_create_waf_protection_strict(self):
        """Test creating strict WAF"""
        waf = create_waf_protection("strict")
        assert waf.block_mode is True
        assert isinstance(waf, WAFProtection)
        
        # Strict mode should have additional patterns
        stats = waf.get_pattern_stats()
        assert stats["custom"] > 0  # Should have additional strict patterns
    
    def test_create_waf_protection_with_custom_patterns(self):
        """Test creating WAF with custom patterns"""
        custom_patterns = ["custom_threat_\\d+", "another_pattern"]
        waf = create_waf_protection(
            "balanced",
            custom_patterns=custom_patterns
        )
        
        # Should include custom patterns
        test_string = "custom_threat_123"
        matches = waf.test_pattern_against_string(test_string)
        assert len(matches) > 0
        assert any("custom" in match["pattern_type"] for match in matches)


class TestWAFIntegration:
    """Integration tests for WAF with FastAPI"""
    
    @pytest.mark.asyncio
    async def test_waf_with_real_request_structure(self):
        """Test WAF with more realistic request structure"""
        waf = WAFProtection()
        
        # Simulate a more complete request object
        request = Mock(spec=Request)
        request.method = "POST"
        request.url.path = "/api/search"
        request.url.query = "q=normal+search+term"
        request.headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "content-type": "application/json",
            "accept": "application/json",
            "host": "example.com"
        }
        request.body = AsyncMock(return_value=b'{"search": "legitimate query"}')
        
        result = await waf.analyze_request(request)
        assert result.allowed is True
    
    def test_waf_performance_characteristics(self):
        """Test WAF performance with many patterns"""
        waf = WAFProtection()
        
        # Pattern compilation should be done once at startup
        stats = waf.get_pattern_stats()
        total_patterns = sum(stats.values())
        
        # Should have a reasonable number of patterns
        assert total_patterns > 20  # Minimum coverage
        assert total_patterns < 200  # Not too many for performance
    
    @pytest.mark.asyncio
    async def test_error_handling_in_body_analysis(self):
        """Test error handling during body analysis"""
        waf = WAFProtection()
        
        # Mock a request that will cause an error during body reading
        request = Mock(spec=Request)
        request.url.path = "/test"
        request.url.query = ""
        request.headers = {"content-type": "application/json", "user-agent": "test"}
        request.method = "POST"
        request.body = AsyncMock(side_effect=Exception("Network error"))
        
        # Should handle the error gracefully (fail open)
        result = await waf.analyze_request(request)
        assert result.allowed is True
        assert "error" in result.reason.lower()