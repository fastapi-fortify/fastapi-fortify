"""
Tests for Rate Limiting module
"""
import pytest
import asyncio
import time
from unittest.mock import Mock, AsyncMock, patch

from fastapi_fortify.middleware.rate_limiter import (
    MemoryRateLimiter,
    RedisRateLimiter,
    SlidingWindowRateLimiter,
    RateLimitInfo,
    create_rate_limiter,
    rate_limit
)


class TestRateLimitInfo:
    """Test RateLimitInfo dataclass"""
    
    def test_rate_limit_info_creation(self):
        """Test creating RateLimitInfo"""
        current_time = time.time()
        info = RateLimitInfo(
            requests=5,
            window_start=current_time,
            window_size=60,
            limit=10
        )
        
        assert info.requests == 5
        assert info.limit == 10
        assert info.remaining == 5
        assert info.window_size == 60
    
    def test_remaining_calculation(self):
        """Test remaining requests calculation"""
        info = RateLimitInfo(
            requests=8,
            window_start=time.time(),
            window_size=60,
            limit=10
        )
        
        assert info.remaining == 2
        
        # Test when limit is exceeded
        info = RateLimitInfo(
            requests=15,
            window_start=time.time(),
            window_size=60,
            limit=10
        )
        
        assert info.remaining == 0  # Should not go negative
    
    def test_reset_time_calculation(self):
        """Test reset time calculation"""
        current_time = time.time()
        info = RateLimitInfo(
            requests=5,
            window_start=current_time,
            window_size=60,
            limit=10
        )
        
        expected_reset = current_time + 60
        assert abs(info.reset_time - expected_reset) < 1  # Allow small float differences
        
        # Test seconds until reset
        seconds_until = info.seconds_until_reset
        assert 58 <= seconds_until <= 60  # Should be close to 60 seconds


class TestMemoryRateLimiter:
    """Test memory-based rate limiter"""
    
    @pytest.mark.asyncio
    async def test_initialization(self):
        """Test rate limiter initialization"""
        limiter = MemoryRateLimiter(cache_size=5000, cleanup_interval=300)
        
        assert limiter.cache_size == 5000
        assert limiter.cleanup_interval == 300
        assert len(limiter.store) == 0
    
    @pytest.mark.asyncio
    async def test_basic_rate_limiting(self):
        """Test basic rate limiting functionality"""
        limiter = MemoryRateLimiter()
        
        key = "test_key"
        limit = 10
        window = 60
        
        # First request should be allowed
        allowed, info = await limiter.check_rate_limit(key, limit, window)
        assert allowed is True
        assert info.requests == 1
        assert info.remaining == 9
        
        # Multiple requests within limit
        for i in range(8):
            allowed, info = await limiter.check_rate_limit(key, limit, window)
            assert allowed is True
            assert info.requests == i + 2
        
        # Should still be allowed (10th request)
        allowed, info = await limiter.check_rate_limit(key, limit, window)
        assert allowed is True
        assert info.requests == 10
        assert info.remaining == 0
        
        # 11th request should be blocked
        allowed, info = await limiter.check_rate_limit(key, limit, window)
        assert allowed is False
        assert info.requests == 10  # Should not increment
    
    @pytest.mark.asyncio
    async def test_window_reset(self):
        """Test rate limit window reset"""
        limiter = MemoryRateLimiter()
        
        key = "reset_test"
        limit = 5
        window = 1  # 1 second window
        
        # Fill up the limit
        for i in range(5):
            allowed, info = await limiter.check_rate_limit(key, limit, window)
            assert allowed is True
        
        # Next request should be blocked
        allowed, info = await limiter.check_rate_limit(key, limit, window)
        assert allowed is False
        
        # Wait for window to expire
        await asyncio.sleep(1.1)
        
        # Should be allowed again (new window)
        allowed, info = await limiter.check_rate_limit(key, limit, window)
        assert allowed is True
        assert info.requests == 1
    
    @pytest.mark.asyncio
    async def test_multiple_keys(self):
        """Test rate limiting with multiple keys"""
        limiter = MemoryRateLimiter()
        
        limit = 3
        window = 60
        
        # Fill limit for key1
        for i in range(3):
            allowed, info = await limiter.check_rate_limit("key1", limit, window)
            assert allowed is True
        
        # key1 should be blocked
        allowed, info = await limiter.check_rate_limit("key1", limit, window)
        assert allowed is False
        
        # key2 should still be allowed
        allowed, info = await limiter.check_rate_limit("key2", limit, window)
        assert allowed is True
        assert info.requests == 1
    
    @pytest.mark.asyncio
    async def test_reset_rate_limit(self):
        """Test resetting rate limit for a key"""
        limiter = MemoryRateLimiter()
        
        key = "reset_key"
        limit = 2
        window = 60
        
        # Fill the limit
        for i in range(2):
            allowed, info = await limiter.check_rate_limit(key, limit, window)
            assert allowed is True
        
        # Should be blocked
        allowed, info = await limiter.check_rate_limit(key, limit, window)
        assert allowed is False
        
        # Reset the limit
        reset_success = await limiter.reset_rate_limit(key)
        assert reset_success is True
        
        # Should be allowed again
        allowed, info = await limiter.check_rate_limit(key, limit, window)
        assert allowed is True
        assert info.requests == 1
    
    @pytest.mark.asyncio
    async def test_cleanup_expired_entries(self):
        """Test cleanup of expired entries"""
        limiter = MemoryRateLimiter(cleanup_interval=0)  # Cleanup every time
        
        key = "cleanup_test"
        limit = 5
        window = 1  # 1 second window
        
        # Add entry
        allowed, info = await limiter.check_rate_limit(key, limit, window)
        assert allowed is True
        assert key in limiter.store
        
        # Wait for expiration
        await asyncio.sleep(1.1)
        
        # Force cleanup by checking rate limit (triggers cleanup)
        allowed, info = await limiter.check_rate_limit("another_key", limit, window)
        
        # Original key should start fresh (cleanup removed expired entry)
        allowed, info = await limiter.check_rate_limit(key, limit, window)
        assert info.requests == 1  # Fresh start
    
    @pytest.mark.asyncio
    async def test_cache_size_limit(self):
        """Test cache size limitation"""
        limiter = MemoryRateLimiter(cache_size=5)
        
        limit = 10
        window = 60
        
        # Add more keys than cache size
        for i in range(10):
            key = f"key_{i}"
            allowed, info = await limiter.check_rate_limit(key, limit, window)
            assert allowed is True
        
        # Cache should be limited
        assert len(limiter.store) <= 5
    
    def test_get_stats(self):
        """Test statistics retrieval"""
        limiter = MemoryRateLimiter(cache_size=1000, cleanup_interval=300)
        
        stats = limiter.get_stats()
        
        assert stats["type"] == "memory"
        assert stats["total_keys"] == 0
        assert stats["cache_size_limit"] == 1000
        assert stats["cleanup_interval"] == 300
        assert "last_cleanup" in stats
    
    @pytest.mark.asyncio
    async def test_get_all_limits(self):
        """Test getting all current limits"""
        limiter = MemoryRateLimiter()
        
        # Add some limits
        await limiter.check_rate_limit("key1", 10, 60)
        await limiter.check_rate_limit("key2", 5, 30)
        
        all_limits = limiter.get_all_limits()
        
        assert "key1" in all_limits
        assert "key2" in all_limits
        assert all_limits["key1"]["limit"] == 10
        assert all_limits["key2"]["limit"] == 5


class TestRedisRateLimiter:
    """Test Redis-based rate limiter"""
    
    def test_initialization(self):
        """Test Redis rate limiter initialization"""
        limiter = RedisRateLimiter(
            redis_url="redis://localhost:6379",
            key_prefix="test:",
            connection_pool_size=20
        )
        
        assert limiter.redis_url == "redis://localhost:6379"
        assert limiter.key_prefix == "test:"
        assert limiter.connection_pool_size == 20
        assert limiter._redis is None  # Lazy initialization
    
    @pytest.mark.asyncio
    async def test_redis_connection_error_handling(self):
        """Test handling of Redis connection errors"""
        # Use invalid Redis URL
        limiter = RedisRateLimiter(redis_url="redis://nonexistent:6379")
        
        # Should fail open when Redis is unavailable
        allowed, info = await limiter.check_rate_limit("test_key", 10, 60)
        assert allowed is True  # Fail open policy
        assert info.requests == 1
    
    @pytest.mark.asyncio
    @patch('fastapi_fortify.middleware.rate_limiter.redis')
    async def test_redis_rate_limiting_success(self, mock_redis_module):
        """Test successful Redis rate limiting"""
        # Mock Redis client
        mock_redis = AsyncMock()
        mock_pipeline = AsyncMock()
        mock_redis.pipeline.return_value = mock_pipeline
        mock_pipeline.execute.return_value = [None, 5, None, None]  # 5 current requests
        mock_redis.ping.return_value = True
        mock_redis_module.from_url.return_value = mock_redis
        
        limiter = RedisRateLimiter()
        
        # Should work with mocked Redis
        allowed, info = await limiter.check_rate_limit("test_key", 10, 60)
        assert allowed is True
        assert info.requests == 6  # 5 + 1 (current request)
    
    @pytest.mark.asyncio
    @patch('fastapi_fortify.middleware.rate_limiter.redis')
    async def test_redis_rate_limit_exceeded(self, mock_redis_module):
        """Test Redis rate limit exceeded"""
        # Mock Redis client with limit exceeded
        mock_redis = AsyncMock()
        mock_pipeline = AsyncMock()
        mock_redis.pipeline.return_value = mock_pipeline
        mock_pipeline.execute.return_value = [None, 15, None, None]  # 15 current requests (over limit)
        mock_redis.ping.return_value = True
        mock_redis.zrem.return_value = 1
        mock_redis_module.from_url.return_value = mock_redis
        
        limiter = RedisRateLimiter()
        
        allowed, info = await limiter.check_rate_limit("test_key", 10, 60)
        assert allowed is False  # Should be blocked
        # Request should be removed from Redis since it exceeded limit
        mock_redis.zrem.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('fastapi_fortify.middleware.rate_limiter.redis')
    async def test_redis_reset_rate_limit(self, mock_redis_module):
        """Test resetting rate limit in Redis"""
        mock_redis = AsyncMock()
        mock_redis.delete.return_value = 1
        mock_redis.ping.return_value = True
        mock_redis_module.from_url.return_value = mock_redis
        
        limiter = RedisRateLimiter(key_prefix="test:")
        
        success = await limiter.reset_rate_limit("test_key")
        assert success is True
        mock_redis.delete.assert_called_once_with("test:test_key")
    
    @pytest.mark.asyncio
    async def test_redis_import_error(self):
        """Test handling of missing Redis package"""
        with patch('fastapi_fortify.middleware.rate_limiter.redis', None):
            limiter = RedisRateLimiter()
            
            # Should raise ImportError when trying to connect
            with pytest.raises(ImportError, match="Redis support requires"):
                await limiter._get_redis()


class TestSlidingWindowRateLimiter:
    """Test sliding window rate limiter"""
    
    @pytest.mark.asyncio
    async def test_sliding_window_precision(self):
        """Test precise sliding window behavior"""
        limiter = SlidingWindowRateLimiter()
        
        key = "sliding_test"
        limit = 5
        window = 2  # 2 second window
        
        # Make requests at specific times
        start_time = time.time()
        
        # Fill the limit
        for i in range(5):
            allowed, info = await limiter.check_rate_limit(key, limit, window)
            assert allowed is True
            await asyncio.sleep(0.1)  # Small delay between requests
        
        # Should be blocked now
        allowed, info = await limiter.check_rate_limit(key, limit, window)
        assert allowed is False
        
        # Wait for first request to fall out of window
        await asyncio.sleep(1.5)
        
        # Should be allowed again (sliding window)
        allowed, info = await limiter.check_rate_limit(key, limit, window)
        assert allowed is True
    
    @pytest.mark.asyncio
    async def test_sliding_window_cleanup(self):
        """Test sliding window data cleanup"""
        limiter = SlidingWindowRateLimiter(cleanup_interval=0)
        
        key = "cleanup_sliding_test"
        limit = 10
        window = 1
        
        # Add requests
        for i in range(5):
            allowed, info = await limiter.check_rate_limit(key, limit, window)
            assert allowed is True
        
        # Check that request logs exist
        assert key in limiter.request_logs
        assert len(limiter.request_logs[key]) == 5
        
        # Wait for data to expire
        await asyncio.sleep(1.5)
        
        # Force cleanup
        await limiter._cleanup_expired()
        
        # Old data should be cleaned up
        if key in limiter.request_logs:
            assert len(limiter.request_logs[key]) == 0
    
    @pytest.mark.asyncio
    async def test_sliding_window_reset(self):
        """Test resetting sliding window rate limit"""
        limiter = SlidingWindowRateLimiter()
        
        key = "reset_sliding_test"
        limit = 3
        window = 60
        
        # Fill the limit
        for i in range(3):
            allowed, info = await limiter.check_rate_limit(key, limit, window)
            assert allowed is True
        
        # Should be blocked
        allowed, info = await limiter.check_rate_limit(key, limit, window)
        assert allowed is False
        
        # Reset
        success = await limiter.reset_rate_limit(key)
        assert success is True
        
        # Should be allowed again
        allowed, info = await limiter.check_rate_limit(key, limit, window)
        assert allowed is True
    
    def test_sliding_window_stats(self):
        """Test sliding window statistics"""
        limiter = SlidingWindowRateLimiter()
        
        stats = limiter.get_stats()
        
        assert stats["type"] == "sliding_window"
        assert "request_logs_count" in stats
        assert "total_logged_requests" in stats


class TestRateLimiterFactory:
    """Test rate limiter factory functions"""
    
    def test_create_memory_rate_limiter(self):
        """Test creating memory rate limiter"""
        limiter = create_rate_limiter("memory", cache_size=5000)
        
        assert isinstance(limiter, MemoryRateLimiter)
        assert limiter.cache_size == 5000
    
    def test_create_sliding_window_rate_limiter(self):
        """Test creating sliding window rate limiter"""
        limiter = create_rate_limiter("sliding_window", cache_size=10000)
        
        assert isinstance(limiter, SlidingWindowRateLimiter)
        assert limiter.cache_size == 10000
    
    def test_create_redis_rate_limiter(self):
        """Test creating Redis rate limiter"""
        redis_url = "redis://localhost:6379"
        limiter = create_rate_limiter("redis", redis_url=redis_url)
        
        assert isinstance(limiter, RedisRateLimiter)
        assert limiter.redis_url == redis_url
    
    def test_create_redis_rate_limiter_without_url(self):
        """Test creating Redis rate limiter without URL"""
        with pytest.raises(ValueError, match="Redis URL required"):
            create_rate_limiter("redis")
    
    def test_create_default_rate_limiter(self):
        """Test creating default rate limiter"""
        limiter = create_rate_limiter("unknown_type")
        
        # Should default to memory rate limiter
        assert isinstance(limiter, MemoryRateLimiter)


class TestRateLimitDecorator:
    """Test rate limit decorator"""
    
    @pytest.mark.asyncio
    async def test_rate_limit_decorator_basic(self):
        """Test basic rate limit decorator functionality"""
        limiter = MemoryRateLimiter()
        
        @rate_limit(
            key_func=lambda req: req.client.host,
            limit=3,
            window=60,
            limiter=limiter
        )
        async def test_endpoint(request):
            return {"success": True}
        
        # Mock request
        mock_request = Mock()
        mock_request.client.host = "192.168.1.1"
        
        # First few requests should succeed
        for i in range(3):
            result = await test_endpoint(mock_request)
            assert result["success"] is True
        
        # Fourth request should be rate limited
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await test_endpoint(mock_request)
        
        assert exc_info.value.status_code == 429
        assert "rate limit exceeded" in exc_info.value.detail.lower()
    
    @pytest.mark.asyncio
    async def test_rate_limit_decorator_no_request(self):
        """Test rate limit decorator with no request object"""
        @rate_limit(
            key_func=lambda req: req.client.host,
            limit=5,
            window=60
        )
        async def test_endpoint():
            return {"success": True}
        
        # Should not rate limit when no request object
        result = await test_endpoint()
        assert result["success"] is True
    
    @pytest.mark.asyncio
    async def test_rate_limit_decorator_custom_key(self):
        """Test rate limit decorator with custom key function"""
        limiter = MemoryRateLimiter()
        
        @rate_limit(
            key_func=lambda req: f"user:{req.user_id}",
            limit=2,
            window=60,
            limiter=limiter
        )
        async def test_endpoint(request):
            return {"user": request.user_id}
        
        # Mock requests with different user IDs
        request1 = Mock()
        request1.user_id = "user1"
        
        request2 = Mock()
        request2.user_id = "user2"
        
        # Each user should have separate limits
        for i in range(2):
            result = await test_endpoint(request1)
            assert result["user"] == "user1"
            
            result = await test_endpoint(request2)
            assert result["user"] == "user2"
        
        # Both users should now be rate limited
        from fastapi import HTTPException
        
        with pytest.raises(HTTPException):
            await test_endpoint(request1)
        
        with pytest.raises(HTTPException):
            await test_endpoint(request2)


class TestRateLimiterIntegration:
    """Integration tests for rate limiters"""
    
    @pytest.mark.asyncio
    async def test_concurrent_rate_limiting(self):
        """Test rate limiting under concurrent access"""
        limiter = MemoryRateLimiter()
        
        async def make_request(key, limit, window):
            return await limiter.check_rate_limit(key, limit, window)
        
        # Create many concurrent requests
        tasks = []
        for i in range(20):
            task = asyncio.create_task(make_request("concurrent_test", 10, 60))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        
        # Count allowed requests
        allowed_count = sum(1 for allowed, info in results if allowed)
        blocked_count = sum(1 for allowed, info in results if not allowed)
        
        # Should allow exactly 10 requests
        assert allowed_count == 10
        assert blocked_count == 10
    
    @pytest.mark.asyncio
    async def test_rate_limiter_performance(self):
        """Test rate limiter performance characteristics"""
        limiter = MemoryRateLimiter()
        
        # Measure performance of many rate limit checks
        start_time = time.time()
        
        for i in range(1000):
            key = f"perf_test_{i % 100}"  # 100 different keys
            await limiter.check_rate_limit(key, 100, 60)
        
        elapsed = time.time() - start_time
        
        # Should complete 1000 checks quickly (less than 1 second)
        assert elapsed < 1.0
    
    @pytest.mark.asyncio
    async def test_memory_usage_cleanup(self):
        """Test that rate limiter cleans up memory properly"""
        limiter = MemoryRateLimiter(cache_size=100, cleanup_interval=0)
        
        # Create many keys that will expire
        for i in range(500):
            key = f"memory_test_{i}"
            await limiter.check_rate_limit(key, 10, 1)  # 1 second window
        
        # Wait for expiration
        await asyncio.sleep(1.1)
        
        # Force cleanup by adding another key
        await limiter.check_rate_limit("trigger_cleanup", 10, 60)
        
        # Memory usage should be reasonable
        assert len(limiter.store) <= 100  # Cache size limit
    
    @pytest.mark.asyncio
    async def test_different_window_sizes(self):
        """Test rate limiting with different window sizes"""
        limiter = MemoryRateLimiter()
        
        # Test very short window
        key_short = "short_window"
        for i in range(5):
            allowed, info = await limiter.check_rate_limit(key_short, 5, 1)  # 1 second
            assert allowed is True
        
        # Should be blocked
        allowed, info = await limiter.check_rate_limit(key_short, 5, 1)
        assert allowed is False
        
        # Test long window
        key_long = "long_window"
        allowed, info = await limiter.check_rate_limit(key_long, 1000, 3600)  # 1 hour
        assert allowed is True
        assert info.window_size == 3600
    
    @pytest.mark.asyncio
    async def test_edge_cases(self):
        """Test edge cases and boundary conditions"""
        limiter = MemoryRateLimiter()
        
        # Zero limit
        allowed, info = await limiter.check_rate_limit("zero_limit", 0, 60)
        assert allowed is False
        assert info.limit == 0
        
        # Negative limit (should be treated as 0)
        allowed, info = await limiter.check_rate_limit("negative_limit", -5, 60)
        assert allowed is False
        
        # Very short window
        allowed, info = await limiter.check_rate_limit("tiny_window", 10, 0.1)
        assert allowed is True
        
        # Very long window
        allowed, info = await limiter.check_rate_limit("huge_window", 1, 86400 * 365)  # 1 year
        assert allowed is True
        assert info.window_size == 86400 * 365