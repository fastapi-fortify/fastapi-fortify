"""
Performance benchmarks for FastAPI Guard components.

These benchmarks measure the performance impact of individual security components
and overall middleware performance under various conditions.
"""
import asyncio
import time
import statistics
import psutil
import gc
from typing import List, Dict, Any
import pytest
from unittest.mock import Mock
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from fastapi_fortify.middleware.security import SecurityMiddleware
from fastapi_fortify.config.settings import SecurityConfig
from fastapi_fortify.config.presets import ProductionConfig, HighSecurityConfig
from fastapi_fortify.protection.waf import WAFProtection
from fastapi_fortify.protection.bot_detection import BotDetector
from fastapi_fortify.middleware.rate_limiter import (
    MemoryRateLimiter,
    RedisRateLimiter,
    SlidingWindowRateLimiter
)
from fastapi_fortify.protection.ip_blocklist import IPBlocklist


class PerformanceBenchmark:
    """Base class for performance benchmarks"""
    
    def __init__(self, name: str):
        self.name = name
        self.results = []
    
    def measure_time(self, func, *args, **kwargs):
        """Measure execution time of a function"""
        start = time.perf_counter()
        result = func(*args, **kwargs)
        duration = time.perf_counter() - start
        self.results.append(duration)
        return result, duration
    
    async def measure_async_time(self, func, *args, **kwargs):
        """Measure execution time of an async function"""
        start = time.perf_counter()
        result = await func(*args, **kwargs)
        duration = time.perf_counter() - start
        self.results.append(duration)
        return result, duration
    
    def get_statistics(self) -> Dict[str, float]:
        """Get performance statistics"""
        if not self.results:
            return {}
        
        return {
            "mean": statistics.mean(self.results),
            "median": statistics.median(self.results),
            "min": min(self.results),
            "max": max(self.results),
            "stdev": statistics.stdev(self.results) if len(self.results) > 1 else 0,
            "p95": statistics.quantiles(self.results, n=20)[18] if len(self.results) > 20 else max(self.results),
            "p99": statistics.quantiles(self.results, n=100)[98] if len(self.results) > 100 else max(self.results),
            "count": len(self.results),
            "total_time": sum(self.results),
            "rps": len(self.results) / sum(self.results) if sum(self.results) > 0 else 0
        }
    
    def reset(self):
        """Reset benchmark results"""
        self.results = []


class TestWAFPerformance:
    """Test WAF component performance"""
    
    def test_waf_pattern_matching_performance(self):
        """Test WAF pattern matching performance"""
        waf = WAFProtection(mode="balanced")
        benchmark = PerformanceBenchmark("WAF Pattern Matching")
        
        # Test payloads
        payloads = [
            "normal request content",
            "user input with parameters",
            "' OR 1=1 --",  # SQL injection
            "<script>alert('xss')</script>",  # XSS
            "../../../etc/passwd",  # Path traversal
            "SELECT * FROM users WHERE id = 1",  # SQL
            "javascript:alert('xss')",  # JavaScript URL
            "normal content with some data",
            "another normal request",
            "regular user input"
        ]
        
        # Warm up
        for payload in payloads[:5]:
            waf.analyze_request_content(payload)
        
        # Benchmark
        iterations = 1000
        for i in range(iterations):
            payload = payloads[i % len(payloads)]
            benchmark.measure_time(waf.analyze_request_content, payload)
        
        stats = benchmark.get_statistics()
        
        # Performance assertions
        assert stats["mean"] < 0.001, f"WAF analysis too slow: {stats['mean']:.4f}s"
        assert stats["p95"] < 0.002, f"WAF P95 too slow: {stats['p95']:.4f}s"
        assert stats["rps"] > 1000, f"WAF RPS too low: {stats['rps']:.0f}"
        
        print(f"\nWAF Performance Results:")
        print(f"  Mean time: {stats['mean']*1000:.2f}ms")
        print(f"  P95 time: {stats['p95']*1000:.2f}ms")
        print(f"  P99 time: {stats['p99']*1000:.2f}ms")
        print(f"  Requests/sec: {stats['rps']:.0f}")
    
    def test_waf_custom_patterns_performance(self):
        """Test performance with custom WAF patterns"""
        custom_patterns = [
            r"(?i)(union|select).*from",
            r"(?i)<script[^>]*>.*?</script>",
            r"(?i)\.\.\/.*etc\/passwd",
            r"(?i)(drop|create|alter).*table",
            r"(?i)javascript:",
            r"(?i)on\w+\s*=",
            r"(?i)(exec|eval|system)",
            r"(?i)file_get_contents",
            r"(?i)base64_decode",
            r"(?i)\$\(.*\)"
        ]
        
        waf = WAFProtection(mode="strict", custom_patterns=custom_patterns)
        benchmark = PerformanceBenchmark("WAF Custom Patterns")
        
        test_content = "normal request with some parameters and data"
        
        # Benchmark custom pattern matching
        iterations = 1000
        for i in range(iterations):
            benchmark.measure_time(waf.analyze_request_content, test_content)
        
        stats = benchmark.get_statistics()
        
        # Should still be fast with custom patterns
        assert stats["mean"] < 0.002, f"Custom patterns too slow: {stats['mean']:.4f}s"
        assert stats["rps"] > 500, f"Custom patterns RPS too low: {stats['rps']:.0f}"
        
        print(f"\nWAF Custom Patterns Performance:")
        print(f"  Mean time: {stats['mean']*1000:.2f}ms")
        print(f"  Requests/sec: {stats['rps']:.0f}")


class TestBotDetectionPerformance:
    """Test bot detection performance"""
    
    def test_user_agent_analysis_performance(self):
        """Test user agent analysis performance"""
        detector = BotDetector(mode="balanced")
        benchmark = PerformanceBenchmark("Bot Detection")
        
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "facebookexternalhit/1.1",
            "Twitterbot/1.0",
            "bot/1.0",
            "crawler/2.0",
            "spider/1.5",
            "scrapy/2.5.0"
        ]
        
        # Benchmark user agent analysis
        iterations = 1000
        for i in range(iterations):
            user_agent = user_agents[i % len(user_agents)]
            benchmark.measure_time(detector.is_bot, user_agent)
        
        stats = benchmark.get_statistics()
        
        # Should be very fast
        assert stats["mean"] < 0.0005, f"Bot detection too slow: {stats['mean']:.4f}s"
        assert stats["rps"] > 2000, f"Bot detection RPS too low: {stats['rps']:.0f}"
        
        print(f"\nBot Detection Performance:")
        print(f"  Mean time: {stats['mean']*1000:.2f}ms")
        print(f"  Requests/sec: {stats['rps']:.0f}")
    
    def test_behavioral_analysis_performance(self):
        """Test behavioral analysis performance"""
        detector = BotDetector(mode="balanced")
        benchmark = PerformanceBenchmark("Behavioral Analysis")
        
        # Mock request for behavioral analysis
        mock_request = Mock()
        mock_request.headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0)"}
        mock_request.client.host = "192.168.1.100"
        mock_request.method = "GET"
        mock_request.url.path = "/api/data"
        
        # Benchmark behavioral analysis
        iterations = 500  # Lower iterations for more complex analysis
        for i in range(iterations):
            benchmark.measure_time(detector.track_behavior, mock_request)
        
        stats = benchmark.get_statistics()
        
        # Behavioral analysis can be slower but should still be reasonable
        assert stats["mean"] < 0.005, f"Behavioral analysis too slow: {stats['mean']:.4f}s"
        assert stats["rps"] > 200, f"Behavioral analysis RPS too low: {stats['rps']:.0f}"
        
        print(f"\nBehavioral Analysis Performance:")
        print(f"  Mean time: {stats['mean']*1000:.2f}ms")
        print(f"  Requests/sec: {stats['rps']:.0f}")


class TestRateLimiterPerformance:
    """Test rate limiter performance"""
    
    def test_memory_rate_limiter_performance(self):
        """Test memory rate limiter performance"""
        limiter = MemoryRateLimiter()
        benchmark = PerformanceBenchmark("Memory Rate Limiter")
        
        # Benchmark rate limiting checks
        iterations = 1000
        for i in range(iterations):
            key = f"user_{i % 100}"  # 100 different users
            benchmark.measure_time(limiter.is_allowed, key, 100, 3600)
        
        stats = benchmark.get_statistics()
        
        # Should be very fast for memory-based rate limiting
        assert stats["mean"] < 0.001, f"Memory rate limiter too slow: {stats['mean']:.4f}s"
        assert stats["rps"] > 1000, f"Memory rate limiter RPS too low: {stats['rps']:.0f}"
        
        print(f"\nMemory Rate Limiter Performance:")
        print(f"  Mean time: {stats['mean']*1000:.2f}ms")
        print(f"  Requests/sec: {stats['rps']:.0f}")
    
    def test_sliding_window_rate_limiter_performance(self):
        """Test sliding window rate limiter performance"""
        limiter = SlidingWindowRateLimiter(window_size=3600, precision=60)
        benchmark = PerformanceBenchmark("Sliding Window Rate Limiter")
        
        # Benchmark sliding window rate limiting
        iterations = 1000
        for i in range(iterations):
            key = f"user_{i % 50}"  # 50 different users
            benchmark.measure_time(limiter.is_allowed, key, 100, 3600)
        
        stats = benchmark.get_statistics()
        
        # Sliding window is more accurate but slightly slower
        assert stats["mean"] < 0.002, f"Sliding window too slow: {stats['mean']:.4f}s"
        assert stats["rps"] > 500, f"Sliding window RPS too low: {stats['rps']:.0f}"
        
        print(f"\nSliding Window Rate Limiter Performance:")
        print(f"  Mean time: {stats['mean']*1000:.2f}ms")
        print(f"  Requests/sec: {stats['rps']:.0f}")
    
    @pytest.mark.skipif(not pytest.redis_available, reason="Redis not available")
    def test_redis_rate_limiter_performance(self):
        """Test Redis rate limiter performance"""
        limiter = RedisRateLimiter(redis_url="redis://localhost:6379/15")
        benchmark = PerformanceBenchmark("Redis Rate Limiter")
        
        # Benchmark Redis rate limiting
        iterations = 500  # Lower iterations due to Redis latency
        for i in range(iterations):
            key = f"user_{i % 25}"  # 25 different users
            result, duration = benchmark.measure_time(limiter.is_allowed, key, 100, 3600)
        
        stats = benchmark.get_statistics()
        
        # Redis has network latency but should still be reasonable
        assert stats["mean"] < 0.01, f"Redis rate limiter too slow: {stats['mean']:.4f}s"
        assert stats["rps"] > 100, f"Redis rate limiter RPS too low: {stats['rps']:.0f}"
        
        print(f"\nRedis Rate Limiter Performance:")
        print(f"  Mean time: {stats['mean']*1000:.2f}ms")
        print(f"  Requests/sec: {stats['rps']:.0f}")


class TestIPBlocklistPerformance:
    """Test IP blocklist performance"""
    
    def test_ip_blocking_performance(self):
        """Test IP blocking performance"""
        blocklist = IPBlocklist(
            static_blocks=["192.168.1.100", "10.0.0.0/8"],
            whitelist=["127.0.0.1", "192.168.1.0/24"]
        )
        benchmark = PerformanceBenchmark("IP Blocklist")
        
        test_ips = [
            "192.168.1.50",   # Whitelisted
            "192.168.1.100",  # Blocked
            "10.5.5.5",       # Blocked (CIDR)
            "8.8.8.8",        # Not blocked
            "127.0.0.1",      # Whitelisted
            "203.0.113.1",    # Not blocked
            "172.16.1.1",     # Not blocked
            "192.168.2.1",    # Not blocked
            "10.0.0.1",       # Blocked (CIDR)
            "1.1.1.1"         # Not blocked
        ]
        
        # Benchmark IP blocking checks
        iterations = 1000
        for i in range(iterations):
            ip = test_ips[i % len(test_ips)]
            benchmark.measure_time(blocklist.is_blocked, ip)
        
        stats = benchmark.get_statistics()
        
        # IP blocking should be very fast
        assert stats["mean"] < 0.001, f"IP blocking too slow: {stats['mean']:.4f}s"
        assert stats["rps"] > 1000, f"IP blocking RPS too low: {stats['rps']:.0f}"
        
        print(f"\nIP Blocklist Performance:")
        print(f"  Mean time: {stats['mean']*1000:.2f}ms")
        print(f"  Requests/sec: {stats['rps']:.0f}")
    
    def test_large_blocklist_performance(self):
        """Test performance with large blocklist"""
        # Create large blocklist
        large_blocklist = []
        for i in range(1000):
            large_blocklist.append(f"192.168.{i//255}.{i%255}")
        
        blocklist = IPBlocklist(static_blocks=large_blocklist)
        benchmark = PerformanceBenchmark("Large IP Blocklist")
        
        # Test with various IPs
        test_ips = [f"192.168.{i//255}.{i%255}" for i in range(0, 1000, 100)]
        test_ips.extend(["8.8.8.8", "1.1.1.1", "127.0.0.1"])
        
        # Benchmark large blocklist
        iterations = 500
        for i in range(iterations):
            ip = test_ips[i % len(test_ips)]
            benchmark.measure_time(blocklist.is_blocked, ip)
        
        stats = benchmark.get_statistics()
        
        # Should still be fast with large blocklist
        assert stats["mean"] < 0.002, f"Large blocklist too slow: {stats['mean']:.4f}s"
        assert stats["rps"] > 500, f"Large blocklist RPS too low: {stats['rps']:.0f}"
        
        print(f"\nLarge IP Blocklist Performance:")
        print(f"  Mean time: {stats['mean']*1000:.2f}ms")
        print(f"  Requests/sec: {stats['rps']:.0f}")


class TestMiddlewarePerformance:
    """Test overall middleware performance"""
    
    def test_minimal_middleware_performance(self):
        """Test performance with minimal configuration"""
        config = SecurityConfig(
            waf_enabled=False,
            bot_detection_enabled=False,
            ip_blocklist_enabled=False,
            rate_limiting_enabled=False,
            auth_monitoring_enabled=False
        )
        
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello World"}
        
        app.add_middleware(SecurityMiddleware, config=config)
        
        client = TestClient(app)
        benchmark = PerformanceBenchmark("Minimal Middleware")
        
        # Benchmark minimal middleware
        iterations = 1000
        for i in range(iterations):
            start = time.perf_counter()
            response = client.get("/")
            duration = time.perf_counter() - start
            benchmark.results.append(duration)
            assert response.status_code == 200
        
        stats = benchmark.get_statistics()
        
        # Minimal overhead
        assert stats["mean"] < 0.01, f"Minimal middleware too slow: {stats['mean']:.4f}s"
        assert stats["rps"] > 100, f"Minimal middleware RPS too low: {stats['rps']:.0f}"
        
        print(f"\nMinimal Middleware Performance:")
        print(f"  Mean time: {stats['mean']*1000:.2f}ms")
        print(f"  Requests/sec: {stats['rps']:.0f}")
    
    def test_production_middleware_performance(self):
        """Test performance with production configuration"""
        config = ProductionConfig()
        
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello World"}
        
        @app.get("/api/data")
        async def get_data():
            return {"data": "test"}
        
        app.add_middleware(SecurityMiddleware, config=config)
        
        client = TestClient(app)
        benchmark = PerformanceBenchmark("Production Middleware")
        
        # Mix of endpoints
        endpoints = ["/", "/api/data"]
        
        # Benchmark production middleware
        iterations = 500  # Lower iterations due to full security stack
        for i in range(iterations):
            endpoint = endpoints[i % len(endpoints)]
            start = time.perf_counter()
            response = client.get(endpoint)
            duration = time.perf_counter() - start
            benchmark.results.append(duration)
            assert response.status_code == 200
        
        stats = benchmark.get_statistics()
        
        # Production should still be reasonable
        assert stats["mean"] < 0.05, f"Production middleware too slow: {stats['mean']:.4f}s"
        assert stats["rps"] > 20, f"Production middleware RPS too low: {stats['rps']:.0f}"
        
        print(f"\nProduction Middleware Performance:")
        print(f"  Mean time: {stats['mean']*1000:.2f}ms")
        print(f"  P95 time: {stats['p95']*1000:.2f}ms")
        print(f"  Requests/sec: {stats['rps']:.0f}")
    
    def test_high_security_middleware_performance(self):
        """Test performance with high security configuration"""
        config = HighSecurityConfig()
        
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello World"}
        
        app.add_middleware(SecurityMiddleware, config=config)
        
        client = TestClient(app)
        benchmark = PerformanceBenchmark("High Security Middleware")
        
        # Benchmark high security middleware
        iterations = 200  # Lower iterations due to maximum security
        for i in range(iterations):
            start = time.perf_counter()
            response = client.get("/")
            duration = time.perf_counter() - start
            benchmark.results.append(duration)
            assert response.status_code == 200
        
        stats = benchmark.get_statistics()
        
        # High security will be slower but should still be usable
        assert stats["mean"] < 0.1, f"High security middleware too slow: {stats['mean']:.4f}s"
        assert stats["rps"] > 10, f"High security middleware RPS too low: {stats['rps']:.0f}"
        
        print(f"\nHigh Security Middleware Performance:")
        print(f"  Mean time: {stats['mean']*1000:.2f}ms")
        print(f"  P95 time: {stats['p95']*1000:.2f}ms") 
        print(f"  Requests/sec: {stats['rps']:.0f}")


class TestMemoryUsage:
    """Test memory usage of components"""
    
    def test_middleware_memory_usage(self):
        """Test memory usage of middleware components"""
        process = psutil.Process()
        
        # Baseline memory
        gc.collect()
        baseline_memory = process.memory_info().rss
        
        # Create middleware with full security
        config = ProductionConfig()
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello"}
        
        app.add_middleware(SecurityMiddleware, config=config)
        
        client = TestClient(app)
        
        # Memory after middleware creation
        gc.collect()
        middleware_memory = process.memory_info().rss
        middleware_overhead = middleware_memory - baseline_memory
        
        # Process some requests
        for i in range(1000):
            response = client.get("/")
            assert response.status_code == 200
        
        # Memory after processing requests
        gc.collect()
        final_memory = process.memory_info().rss
        total_overhead = final_memory - baseline_memory
        
        # Memory usage assertions
        assert middleware_overhead < 200 * 1024 * 1024, f"Middleware uses too much memory: {middleware_overhead/1024/1024:.1f}MB"
        assert total_overhead < 300 * 1024 * 1024, f"Total memory overhead too high: {total_overhead/1024/1024:.1f}MB"
        
        print(f"\nMemory Usage:")
        print(f"  Baseline: {baseline_memory/1024/1024:.1f}MB")
        print(f"  Middleware overhead: {middleware_overhead/1024/1024:.1f}MB")
        print(f"  Total overhead: {total_overhead/1024/1024:.1f}MB")
    
    def test_memory_stability_under_load(self):
        """Test memory stability under sustained load"""
        config = SecurityConfig(
            waf_enabled=True,
            bot_detection_enabled=True,
            rate_limiting_enabled=True,
            ip_blocklist_enabled=True
        )
        
        app = FastAPI()
        
        @app.get("/test")
        async def test_endpoint():
            return {"data": "test"}
        
        app.add_middleware(SecurityMiddleware, config=config)
        client = TestClient(app)
        
        process = psutil.Process()
        memory_samples = []
        
        # Sustained load test
        for batch in range(10):  # 10 batches
            # Process batch of requests
            for i in range(100):  # 100 requests per batch
                response = client.get("/test")
                assert response.status_code == 200
            
            # Sample memory usage
            gc.collect()
            memory_usage = process.memory_info().rss
            memory_samples.append(memory_usage)
        
        # Memory should be stable (not continuously growing)
        memory_growth = memory_samples[-1] - memory_samples[0]
        max_memory = max(memory_samples)
        min_memory = min(memory_samples)
        memory_variance = max_memory - min_memory
        
        # Memory shouldn't grow significantly over time
        assert memory_growth < 50 * 1024 * 1024, f"Memory leak detected: {memory_growth/1024/1024:.1f}MB growth"
        assert memory_variance < 100 * 1024 * 1024, f"Memory usage too variable: {memory_variance/1024/1024:.1f}MB variance"
        
        print(f"\nMemory Stability:")
        print(f"  Initial: {memory_samples[0]/1024/1024:.1f}MB")
        print(f"  Final: {memory_samples[-1]/1024/1024:.1f}MB")
        print(f"  Growth: {memory_growth/1024/1024:.1f}MB")
        print(f"  Variance: {memory_variance/1024/1024:.1f}MB")


# Benchmark configuration
def pytest_configure(config):
    """Configure pytest for benchmarks"""
    # Check if Redis is available
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, db=15)
        r.ping()
        config.redis_available = True
    except:
        config.redis_available = False


# Benchmark runner
if __name__ == "__main__":
    """Run benchmarks directly"""
    import sys
    
    print("FastAPI Guard Performance Benchmarks")
    print("=" * 50)
    
    # WAF Benchmarks
    print("\n🛡️  WAF Performance Tests")
    test_waf = TestWAFPerformance()
    test_waf.test_waf_pattern_matching_performance()
    test_waf.test_waf_custom_patterns_performance()
    
    # Bot Detection Benchmarks
    print("\n🤖  Bot Detection Performance Tests")
    test_bot = TestBotDetectionPerformance()
    test_bot.test_user_agent_analysis_performance()
    test_bot.test_behavioral_analysis_performance()
    
    # Rate Limiter Benchmarks
    print("\n⏱️   Rate Limiter Performance Tests")
    test_rl = TestRateLimiterPerformance()
    test_rl.test_memory_rate_limiter_performance()
    test_rl.test_sliding_window_rate_limiter_performance()
    
    # IP Blocklist Benchmarks
    print("\n🚫  IP Blocklist Performance Tests")
    test_ip = TestIPBlocklistPerformance()
    test_ip.test_ip_blocking_performance()
    test_ip.test_large_blocklist_performance()
    
    # Middleware Benchmarks
    print("\n🔧  Middleware Performance Tests")
    test_mw = TestMiddlewarePerformance()
    test_mw.test_minimal_middleware_performance()
    test_mw.test_production_middleware_performance()
    test_mw.test_high_security_middleware_performance()
    
    # Memory Tests
    print("\n💾  Memory Usage Tests")
    test_mem = TestMemoryUsage()
    test_mem.test_middleware_memory_usage()
    test_mem.test_memory_stability_under_load()
    
    print("\n✅  All benchmarks completed!")