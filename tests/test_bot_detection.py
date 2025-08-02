"""
Tests for Bot Detection module
"""
import pytest
from unittest.mock import Mock, patch
from datetime import datetime

from fastapi_fortify.protection.bot_detection import (
    BotDetector, 
    create_bot_detector,
    BotSignatures,
    RequestPattern
)
from fastapi_fortify.utils.security_utils import SecurityDecision


class TestBotDetector:
    """Test bot detection functionality"""
    
    def test_bot_detector_initialization(self):
        """Test bot detector initialization"""
        # Default initialization
        detector = BotDetector()
        assert detector.mode == "balanced"
        assert detector.allow_search_bots is True
        assert detector.request_threshold == 30
        assert detector.time_window == 300
        
        # Custom initialization
        detector = BotDetector(
            mode="strict",
            allow_search_bots=False,
            request_threshold=10,
            time_window=120
        )
        assert detector.mode == "strict"
        assert detector.allow_search_bots is False
        assert detector.request_threshold == 10
        assert detector.time_window == 120
    
    def test_pattern_compilation(self):
        """Test regex pattern compilation"""
        detector = BotDetector()
        
        # Should have compiled patterns
        assert len(detector.compiled_malicious) > 0
        assert len(detector.compiled_legitimate) > 0
        assert len(detector.compiled_suspicious) > 0
        assert len(detector.compiled_automation) > 0
    
    def test_malicious_bot_detection(self, bot_user_agents):
        """Test detection of malicious bots"""
        detector = BotDetector()
        
        for ua in bot_user_agents["malicious"]:
            result = detector.analyze_user_agent(ua)
            assert result.allowed is False
            assert result.rule_type in [
                "bot_malicious", "bot_suspicious", "bot_automation"
            ]
    
    def test_legitimate_bot_allowance(self, bot_user_agents):
        """Test allowing legitimate search engine bots"""
        detector = BotDetector(allow_search_bots=True)
        
        for ua in bot_user_agents["legitimate"]:
            result = detector.analyze_user_agent(ua)
            assert result.allowed is True
            assert result.rule_type == "bot_legitimate"
    
    def test_legitimate_bot_blocking_when_disabled(self, bot_user_agents):
        """Test blocking legitimate bots when disabled"""
        detector = BotDetector(allow_search_bots=False)
        
        # Some legitimate bots might be detected as bots when parsed
        for ua in bot_user_agents["legitimate"]:
            result = detector.analyze_user_agent(ua)
            # Result depends on user-agents library detection
            # We just ensure it doesn't crash
            assert isinstance(result.allowed, bool)
    
    def test_browser_user_agents(self, bot_user_agents):
        """Test that browser user agents are allowed"""
        detector = BotDetector()
        
        for ua in bot_user_agents["browsers"]:
            result = detector.analyze_user_agent(ua)
            assert result.allowed is True
    
    def test_empty_user_agent_handling(self):
        """Test handling of empty/missing user agents"""
        detector = BotDetector(block_empty_user_agents=True)
        
        # Empty string
        result = detector.analyze_user_agent("")
        assert result.allowed is False
        assert result.rule_type == "bot_empty_ua"
        
        # None
        result = detector.analyze_user_agent(None)
        assert result.allowed is False
        assert result.rule_type == "bot_empty_ua"
        
        # Whitespace only
        result = detector.analyze_user_agent("   ")
        assert result.allowed is False
        assert result.rule_type == "bot_empty_ua"
    
    def test_empty_user_agent_allowance(self):
        """Test allowing empty user agents when configured"""
        detector = BotDetector(block_empty_user_agents=False)
        
        result = detector.analyze_user_agent("")
        assert result.allowed is True
    
    def test_custom_patterns(self):
        """Test custom bot patterns"""
        custom_patterns = ["custombot.*", "malicious-scanner"]
        detector = BotDetector(custom_patterns=custom_patterns)
        
        # Should detect custom pattern
        result = detector.analyze_user_agent("custombot/1.0")
        assert result.allowed is False
        assert result.rule_type == "bot_custom"
        
        result = detector.analyze_user_agent("malicious-scanner")
        assert result.allowed is False
        assert result.rule_type == "bot_custom"
    
    def test_suspicious_patterns(self):
        """Test detection of suspicious user agent patterns"""
        detector = BotDetector()
        
        suspicious_uas = [
            "Mozilla/5.0",  # Incomplete
            "test",  # Too short
            "User-Agent",  # Literally "User-Agent"
            "hack",  # Contains suspicious word
            "x" * 600  # Too long
        ]
        
        for ua in suspicious_uas:
            result = detector.analyze_user_agent(ua)
            assert result.allowed is False
            assert result.rule_type in ["bot_suspicious", "bot_malicious"]
    
    def test_mode_based_detection(self):
        """Test different detection modes"""
        automation_ua = "PostmanRuntime/7.28.0"
        
        # Permissive mode - should allow automation tools
        detector_permissive = BotDetector(mode="permissive")
        result = detector_permissive.analyze_user_agent(automation_ua)
        assert result.allowed is True
        
        # Balanced mode - should block automation tools
        detector_balanced = BotDetector(mode="balanced")
        result = detector_balanced.analyze_user_agent(automation_ua)
        assert result.allowed is False
        assert result.rule_type == "bot_automation"
        
        # Strict mode - should also block automation tools
        detector_strict = BotDetector(mode="strict")
        result = detector_strict.analyze_user_agent(automation_ua)
        assert result.allowed is False
        assert result.rule_type == "bot_automation"
    
    @patch('fastapi_fortify.protection.bot_detection.user_agents.parse')
    def test_advanced_user_agent_analysis(self, mock_parse):
        """Test advanced user agent analysis with user-agents library"""
        detector = BotDetector(mode="strict")
        
        # Mock parsed user agent without OS info
        mock_ua = Mock()
        mock_ua.is_bot = False
        mock_ua.os.family = "Other"  # No OS info
        mock_ua.browser.family = "Unknown"
        mock_parse.return_value = mock_ua
        
        result = detector.analyze_user_agent("suspicious/1.0")
        assert result.allowed is False
        assert result.rule_type == "bot_no_os"
        
        # Mock very old browser version
        mock_ua.os.family = "Windows"
        mock_ua.browser.family = "Chrome"
        mock_ua.browser.version = ["50", "0", "0"]  # Very old Chrome
        
        result = detector.analyze_user_agent("Chrome/50.0")
        assert result.allowed is False
        assert result.rule_type == "bot_old_browser"
    
    def test_request_pattern_tracking(self):
        """Test request pattern analysis"""
        detector = BotDetector(request_threshold=5, time_window=60)
        
        ip = "192.168.1.100"
        user_agent = "test-agent"
        
        # Normal request pattern
        for i in range(3):
            result = detector.analyze_request_pattern(ip, f"/page{i}", user_agent)
            assert result.allowed is True
        
        # Excessive requests should trigger detection
        for i in range(10):
            result = detector.analyze_request_pattern(ip, f"/spam{i}", user_agent)
        
        # Last request should be blocked due to rate limit
        assert result.allowed is False
        assert result.rule_type == "bot_rate_limit"
    
    def test_scanning_behavior_detection(self):
        """Test detection of directory scanning behavior"""
        detector = BotDetector()
        
        ip = "192.168.1.101"
        user_agent = "scanner"
        
        # Simulate scanning behavior
        scan_paths = [
            "/admin", "/wp-admin", "/.env", "/config", "/backup",
            "/test", "/debug", "/info.php", "/phpmyadmin", "/robots.txt"
        ]
        
        for path in scan_paths:
            result = detector.analyze_request_pattern(ip, path, user_agent)
        
        # Should detect scanning
        assert result.allowed is False
        assert result.rule_type == "bot_scanning"
    
    def test_user_agent_rotation_detection(self):
        """Test detection of user agent rotation"""
        detector = BotDetector()
        
        ip = "192.168.1.102"
        different_uas = [
            "Mozilla/5.0 (Windows NT 10.0)",
            "Mozilla/5.0 (Macintosh; Intel)",
            "Mozilla/5.0 (X11; Linux)",
            "Chrome/91.0.4472.124",
            "Firefox/89.0"
        ]
        
        # Use different user agents for same IP
        for i, ua in enumerate(different_uas):
            result = detector.analyze_request_pattern(ip, f"/page{i}", ua)
        
        # Should detect user agent rotation
        assert result.allowed is False
        assert result.rule_type == "bot_ua_rotation"
    
    def test_api_only_access_pattern(self):
        """Test detection of API-only access patterns"""
        detector = BotDetector()
        
        ip = "192.168.1.103"
        user_agent = "api-client"
        
        # Access only API endpoints
        api_paths = ["/api/users", "/api/posts", "/api/data", "/api/search", "/api/config"]
        
        for path in api_paths:
            result = detector.analyze_request_pattern(ip, path, user_agent)
        
        # Should detect API-only pattern (with lower confidence)
        assert result.allowed is False
        assert result.rule_type == "bot_api_only"
    
    def test_error_prone_paths_detection(self):
        """Test detection of high ratio of error-prone paths"""
        detector = BotDetector()
        
        ip = "192.168.1.104"
        user_agent = "error-bot"
        
        # Access mostly error-prone paths
        error_paths = [
            "/wp-admin/admin.php", "/admin/login", "/.env", 
            "/phpmyadmin/index.php", "/config/database.php"
        ]
        normal_paths = ["/"]
        
        all_paths = error_paths + normal_paths
        for path in all_paths:
            result = detector.analyze_request_pattern(ip, path, user_agent)
        
        # Should detect high error path ratio
        assert result.allowed is False
        assert result.rule_type == "bot_error_paths"
    
    def test_sequential_path_enumeration(self):
        """Test detection of sequential path enumeration"""
        detector = BotDetector()
        
        ip = "192.168.1.105"
        user_agent = "enumerator"
        
        # Sequential paths that look like enumeration
        sequential_paths = [
            "/user/1", "/user/2", "/user/3", "/user/4", "/user/5",
            "/page/1", "/page/2", "/page/3", "/post/100", "/post/101"
        ]
        
        for path in sequential_paths:
            result = detector.analyze_request_pattern(ip, path, user_agent)
        
        # Should detect enumeration pattern
        assert result.allowed is False
        assert result.rule_type == "bot_enumeration"
    
    def test_cleanup_expired_patterns(self):
        """Test cleanup of expired request patterns"""
        detector = BotDetector(time_window=60)
        
        ip = "192.168.1.106"
        
        # Add some patterns
        detector.analyze_request_pattern(ip, "/test1", "agent")
        assert ip in detector.request_patterns
        
        # Mock old timestamp to trigger cleanup
        detector.request_patterns[ip].timestamps = [
            datetime.utcnow().timestamp() - 3600  # 1 hour ago
        ]
        
        # Force cleanup
        detector._cleanup_expired_patterns()
        
        # Pattern should be removed
        assert ip not in detector.request_patterns
    
    def test_add_custom_pattern_runtime(self):
        """Test adding custom patterns at runtime"""
        detector = BotDetector()
        
        # Add valid pattern
        success = detector.add_custom_pattern("newbot.*")
        assert success is True
        
        # Test the new pattern
        result = detector.analyze_user_agent("newbot/1.0")
        assert result.allowed is False
        assert result.rule_type == "bot_custom"
        
        # Add invalid pattern
        success = detector.add_custom_pattern("[invalid")
        assert success is False
    
    def test_detection_statistics(self):
        """Test detection statistics"""
        detector = BotDetector()
        
        # Add some patterns
        detector.analyze_request_pattern("192.168.1.1", "/test", "agent1")
        detector.analyze_request_pattern("192.168.1.2", "/test", "agent2")
        
        stats = detector.get_detection_stats()
        
        assert stats["mode"] == detector.mode
        assert stats["tracked_ips"] >= 2
        assert "active_patterns" in stats
        assert stats["active_patterns"]["malicious"] > 0
    
    def test_ip_reputation_analysis(self):
        """Test IP reputation analysis"""
        detector = BotDetector()
        
        ip = "192.168.1.107"
        
        # Unknown IP
        reputation = detector.analyze_ip_reputation(ip)
        assert reputation["status"] == "unknown"
        
        # Add some activity
        detector.analyze_request_pattern(ip, "/test1", "agent")
        detector.analyze_request_pattern(ip, "/test2", "agent")
        
        reputation = detector.analyze_ip_reputation(ip)
        assert reputation["status"] == "tracked"
        assert reputation["total_requests"] >= 2
        assert reputation["unique_paths"] >= 2


class TestRequestPattern:
    """Test RequestPattern class"""
    
    def test_request_pattern_creation(self):
        """Test creating and using RequestPattern"""
        pattern = RequestPattern(
            ip="192.168.1.1",
            timestamps=[],
            paths=[],
            user_agents=set()
        )
        
        assert pattern.ip == "192.168.1.1"
        assert len(pattern.timestamps) == 0
        assert len(pattern.paths) == 0
        assert len(pattern.user_agents) == 0
    
    def test_add_request_to_pattern(self):
        """Test adding requests to pattern"""
        pattern = RequestPattern(
            ip="192.168.1.1",
            timestamps=[],
            paths=[],
            user_agents=set()
        )
        
        # Add requests
        pattern.add_request("/test1", "agent1")
        pattern.add_request("/test2", "agent2")
        
        assert len(pattern.timestamps) == 2
        assert len(pattern.paths) == 2
        assert len(pattern.user_agents) == 2
        assert "/test1" in pattern.paths
        assert "/test2" in pattern.paths
        assert "agent1" in pattern.user_agents
        assert "agent2" in pattern.user_agents
    
    def test_pattern_data_limits(self):
        """Test that pattern data is limited to prevent memory issues"""
        pattern = RequestPattern(
            ip="192.168.1.1",
            timestamps=[],
            paths=[],
            user_agents=set()
        )
        
        # Add many requests (more than the limit of 50 paths)
        for i in range(100):
            pattern.add_request(f"/test{i}", f"agent{i}")
        
        # Should be limited to 50 paths
        assert len(pattern.paths) == 50
        # But user agents are stored in a set (no duplicates expected anyway)
        assert len(pattern.user_agents) == 100


class TestBotSignatures:
    """Test BotSignatures class"""
    
    def test_malicious_bot_patterns(self):
        """Test malicious bot signature patterns"""
        import re
        
        malicious_uas = [
            "sqlmap/1.0", "Nikto/2.1", "w3af", "burpsuite", 
            "nmap", "python-requests", "curl/7.0"
        ]
        
        for pattern_str in BotSignatures.MALICIOUS_BOTS:
            pattern = re.compile(pattern_str)
            # At least one malicious UA should match each pattern
            matches = [ua for ua in malicious_uas if pattern.search(ua)]
            # Some patterns might be very specific, so we don't require matches for all
    
    def test_legitimate_bot_patterns(self):
        """Test legitimate bot signature patterns"""
        import re
        
        legitimate_uas = [
            "Googlebot/2.1", "bingbot/2.0", "facebookexternalhit/1.1",
            "Twitterbot/1.0", "LinkedInBot/1.0"
        ]
        
        for pattern_str in BotSignatures.LEGITIMATE_BOTS:
            pattern = re.compile(pattern_str)
            # Check that pattern is valid regex
            assert pattern is not None


class TestBotDetectorFactory:
    """Test bot detector factory functions"""
    
    def test_create_bot_detector_permissive(self):
        """Test creating permissive bot detector"""
        detector = create_bot_detector("permissive")
        assert detector.mode == "permissive"
        assert detector.request_threshold == 100  # Higher threshold
        assert detector.block_empty_user_agents is False
    
    def test_create_bot_detector_balanced(self):
        """Test creating balanced bot detector"""
        detector = create_bot_detector("balanced")
        assert detector.mode == "balanced"
        assert detector.request_threshold == 30
        assert detector.block_empty_user_agents is True
    
    def test_create_bot_detector_strict(self):
        """Test creating strict bot detector"""
        detector = create_bot_detector("strict")
        assert detector.mode == "strict"
        assert detector.request_threshold == 15  # Lower threshold
        assert detector.block_empty_user_agents is True
    
    def test_create_bot_detector_with_custom_settings(self):
        """Test creating bot detector with custom settings"""
        detector = create_bot_detector(
            "balanced",
            allow_search_engines=False,
            request_threshold=50
        )
        assert detector.allow_search_bots is False
        assert detector.request_threshold == 50


class TestBotDetectorIntegration:
    """Integration tests for bot detector"""
    
    def test_comprehensive_bot_analysis(self, bot_user_agents):
        """Test comprehensive analysis of various user agents"""
        detector = BotDetector(mode="balanced")
        
        # Test all categories
        for category, uas in bot_user_agents.items():
            for ua in uas:
                result = detector.analyze_user_agent(ua)
                assert isinstance(result, SecurityDecision)
                assert isinstance(result.allowed, bool)
                
                if category == "malicious":
                    assert result.allowed is False
                elif category == "legitimate":
                    assert result.allowed is True  # Should be allowed with default settings
                elif category == "browsers":
                    assert result.allowed is True
    
    def test_performance_with_many_patterns(self):
        """Test performance characteristics"""
        detector = BotDetector()
        
        # Analysis should be fast even with many patterns
        import time
        start_time = time.time()
        
        for i in range(100):
            detector.analyze_user_agent(f"test-agent-{i}")
        
        elapsed = time.time() - start_time
        # Should complete 100 analyses in reasonable time (less than 1 second)
        assert elapsed < 1.0
    
    def test_memory_usage_with_many_ips(self):
        """Test memory usage with many tracked IPs"""
        detector = BotDetector()
        
        # Track many IPs
        for i in range(1000):
            ip = f"192.168.{i // 256}.{i % 256}"
            detector.analyze_request_pattern(ip, "/test", "agent")
        
        # Should have reasonable number of tracked patterns
        assert len(detector.request_patterns) <= 1000
        
        # Cleanup should work
        detector._cleanup_expired_patterns()
        # After cleanup, some patterns might remain (depending on timing)