"""
Load tests for FastAPI Guard.

These tests simulate realistic load scenarios to measure performance
under concurrent requests and sustained traffic.
"""
import asyncio
import aiohttp
import time
import threading
import statistics
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
import uvicorn
import multiprocessing
import requests

from fastapi_fortify.middleware.security import SecurityMiddleware
from fastapi_fortify.config.settings import SecurityConfig
from fastapi_fortify.config.presets import ProductionConfig, HighSecurityConfig


class LoadTestResult:
    """Container for load test results"""
    
    def __init__(self, name: str):
        self.name = name
        self.response_times = []
        self.status_codes = []
        self.errors = []
        self.start_time = None
        self.end_time = None
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
    
    def add_result(self, response_time: float, status_code: int, error: str = None):
        """Add a single request result"""
        self.response_times.append(response_time)
        self.status_codes.append(status_code)
        self.total_requests += 1
        
        if error:
            self.errors.append(error)
            self.failed_requests += 1
        else:
            self.successful_requests += 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        if not self.response_times:
            return {}
        
        duration = self.end_time - self.start_time if self.end_time and self.start_time else 0
        
        return {
            "name": self.name,
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "success_rate": self.successful_requests / self.total_requests * 100,
            "duration_seconds": duration,
            "requests_per_second": self.total_requests / duration if duration > 0 else 0,
            "response_times": {
                "mean": statistics.mean(self.response_times),
                "median": statistics.median(self.response_times),
                "min": min(self.response_times),
                "max": max(self.response_times),
                "p95": statistics.quantiles(self.response_times, n=20)[18] if len(self.response_times) > 20 else max(self.response_times),
                "p99": statistics.quantiles(self.response_times, n=100)[98] if len(self.response_times) > 100 else max(self.response_times),
                "stdev": statistics.stdev(self.response_times) if len(self.response_times) > 1 else 0
            },
            "status_codes": {
                code: self.status_codes.count(code) 
                for code in set(self.status_codes)
            },
            "error_count": len(self.errors),
            "unique_errors": len(set(self.errors))
        }


class LoadTestRunner:
    """Load test execution engine"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.session = None
    
    def single_request(self, endpoint: str, method: str = "GET", data: dict = None) -> tuple:
        """Make a single HTTP request and measure performance"""
        url = f"{self.base_url}{endpoint}"
        
        start_time = time.perf_counter()
        error = None
        
        try:
            if method.upper() == "GET":
                response = requests.get(url, timeout=10)
            elif method.upper() == "POST":
                response = requests.post(url, json=data, timeout=10)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            response_time = time.perf_counter() - start_time
            return response_time, response.status_code, None
            
        except Exception as e:
            response_time = time.perf_counter() - start_time
            return response_time, 0, str(e)
    
    async def async_single_request(self, session: aiohttp.ClientSession, endpoint: str, method: str = "GET", data: dict = None) -> tuple:
        """Make a single async HTTP request"""
        url = f"{self.base_url}{endpoint}"
        
        start_time = time.perf_counter()
        error = None
        
        try:
            if method.upper() == "GET":
                async with session.get(url) as response:
                    await response.text()
                    response_time = time.perf_counter() - start_time
                    return response_time, response.status, None
            elif method.upper() == "POST":
                async with session.post(url, json=data) as response:
                    await response.text()
                    response_time = time.perf_counter() - start_time
                    return response_time, response.status, None
            else:
                raise ValueError(f"Unsupported method: {method}")
                
        except Exception as e:
            response_time = time.perf_counter() - start_time
            return response_time, 0, str(e)
    
    def concurrent_load_test(
        self, 
        endpoint: str,
        concurrent_users: int = 10,
        requests_per_user: int = 100,
        method: str = "GET",
        data: dict = None
    ) -> LoadTestResult:
        """Run concurrent load test using threads"""
        result = LoadTestResult(f"Concurrent Load Test - {concurrent_users} users, {requests_per_user} req/user")
        result.start_time = time.perf_counter()
        
        def user_simulation():
            """Simulate a single user making multiple requests"""
            user_results = []
            for _ in range(requests_per_user):
                response_time, status_code, error = self.single_request(endpoint, method, data)
                user_results.append((response_time, status_code, error))
            return user_results
        
        # Run concurrent users
        with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
            futures = [executor.submit(user_simulation) for _ in range(concurrent_users)]
            
            for future in as_completed(futures):
                try:
                    user_results = future.result()
                    for response_time, status_code, error in user_results:
                        result.add_result(response_time, status_code, error)
                except Exception as e:
                    result.errors.append(str(e))
        
        result.end_time = time.perf_counter()
        return result
    
    async def async_load_test(
        self,
        endpoint: str,
        concurrent_requests: int = 100,
        total_requests: int = 1000,
        method: str = "GET",
        data: dict = None
    ) -> LoadTestResult:
        """Run async load test"""
        result = LoadTestResult(f"Async Load Test - {concurrent_requests} concurrent, {total_requests} total")
        result.start_time = time.perf_counter()
        
        async def make_requests_batch(session: aiohttp.ClientSession, batch_size: int):
            """Make a batch of concurrent requests"""
            tasks = []
            for _ in range(batch_size):
                task = asyncio.create_task(
                    self.async_single_request(session, endpoint, method, data)
                )
                tasks.append(task)
            
            return await asyncio.gather(*tasks, return_exceptions=True)
        
        # Calculate batches
        num_batches = total_requests // concurrent_requests
        remaining_requests = total_requests % concurrent_requests
        
        async with aiohttp.ClientSession() as session:
            # Process main batches
            for _ in range(num_batches):
                batch_results = await make_requests_batch(session, concurrent_requests)
                for response_time, status_code, error in batch_results:
                    if isinstance(response_time, Exception):
                        result.add_result(0, 0, str(response_time))
                    else:
                        result.add_result(response_time, status_code, error)
            
            # Process remaining requests
            if remaining_requests > 0:
                batch_results = await make_requests_batch(session, remaining_requests)
                for response_time, status_code, error in batch_results:
                    if isinstance(response_time, Exception):
                        result.add_result(0, 0, str(response_time))
                    else:
                        result.add_result(response_time, status_code, error)
        
        result.end_time = time.perf_counter()
        return result
    
    def sustained_load_test(
        self,
        endpoint: str,
        requests_per_second: int = 50,
        duration_seconds: int = 60,
        method: str = "GET",
        data: dict = None
    ) -> LoadTestResult:
        """Run sustained load test at specific RPS"""
        result = LoadTestResult(f"Sustained Load Test - {requests_per_second} RPS for {duration_seconds}s")
        result.start_time = time.perf_counter()
        
        request_interval = 1.0 / requests_per_second
        end_time = time.time() + duration_seconds
        
        def worker():
            """Worker thread for making requests"""
            while time.time() < end_time:
                start = time.time()
                response_time, status_code, error = self.single_request(endpoint, method, data)
                result.add_result(response_time, status_code, error)
                
                # Sleep to maintain desired RPS
                elapsed = time.time() - start
                sleep_time = max(0, request_interval - elapsed)
                if sleep_time > 0:
                    time.sleep(sleep_time)
        
        # Start worker threads
        num_workers = min(10, requests_per_second)  # Limit number of workers
        threads = []
        
        for _ in range(num_workers):
            thread = threading.Thread(target=worker)
            thread.start()
            threads.append(thread)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        result.end_time = time.perf_counter()
        return result


class TestBasicLoadScenarios:
    """Test basic load scenarios"""
    
    @pytest.fixture
    def test_app(self):
        """Create test FastAPI app with security middleware"""
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello World"}
        
        @app.get("/api/data")
        async def get_data():
            return {"data": [1, 2, 3, 4, 5]}
        
        @app.post("/api/process")
        async def process_data(data: dict):
            return {"processed": True, "input": data}
        
        config = ProductionConfig()
        app.add_middleware(SecurityMiddleware, config=config)
        
        return app
    
    def test_light_load(self, test_app):
        """Test light load scenario"""
        client = TestClient(test_app)
        runner = LoadTestRunner()
        
        # Override single_request to use TestClient
        def single_request_override(endpoint, method="GET", data=None):
            start_time = time.perf_counter()
            try:
                if method.upper() == "GET":
                    response = client.get(endpoint)
                elif method.upper() == "POST":
                    response = client.post(endpoint, json=data)
                else:
                    raise ValueError(f"Unsupported method: {method}")
                
                response_time = time.perf_counter() - start_time
                return response_time, response.status_code, None
            except Exception as e:
                response_time = time.perf_counter() - start_time
                return response_time, 0, str(e)
        
        runner.single_request = single_request_override
        
        # Run light load test
        result = runner.concurrent_load_test(
            endpoint="/",
            concurrent_users=5,
            requests_per_user=50
        )
        
        stats = result.get_statistics()
        
        # Assertions for light load
        assert stats["success_rate"] >= 95, f"Success rate too low: {stats['success_rate']:.1f}%"
        assert stats["response_times"]["mean"] < 0.1, f"Mean response time too high: {stats['response_times']['mean']:.3f}s"
        assert stats["response_times"]["p95"] < 0.2, f"P95 response time too high: {stats['response_times']['p95']:.3f}s"
        
        print(f"\nLight Load Test Results:")
        print(f"  Total requests: {stats['total_requests']}")
        print(f"  Success rate: {stats['success_rate']:.1f}%")
        print(f"  Mean response time: {stats['response_times']['mean']*1000:.1f}ms")
        print(f"  P95 response time: {stats['response_times']['p95']*1000:.1f}ms")
        print(f"  Requests/sec: {stats['requests_per_second']:.1f}")
    
    def test_moderate_load(self, test_app):
        """Test moderate load scenario"""
        client = TestClient(test_app)
        runner = LoadTestRunner()
        
        # Override single_request to use TestClient
        def single_request_override(endpoint, method="GET", data=None):
            start_time = time.perf_counter()
            try:
                if method.upper() == "GET":
                    response = client.get(endpoint)
                elif method.upper() == "POST":
                    response = client.post(endpoint, json=data)
                else:
                    raise ValueError(f"Unsupported method: {method}")
                
                response_time = time.perf_counter() - start_time
                return response_time, response.status_code, None
            except Exception as e:
                response_time = time.perf_counter() - start_time
                return response_time, 0, str(e)
        
        runner.single_request = single_request_override
        
        # Run moderate load test
        result = runner.concurrent_load_test(
            endpoint="/api/data",
            concurrent_users=20,
            requests_per_user=100
        )
        
        stats = result.get_statistics()
        
        # Assertions for moderate load
        assert stats["success_rate"] >= 90, f"Success rate too low: {stats['success_rate']:.1f}%"
        assert stats["response_times"]["mean"] < 0.2, f"Mean response time too high: {stats['response_times']['mean']:.3f}s"
        assert stats["response_times"]["p95"] < 0.5, f"P95 response time too high: {stats['response_times']['p95']:.3f}s"
        
        print(f"\nModerate Load Test Results:")
        print(f"  Total requests: {stats['total_requests']}")
        print(f"  Success rate: {stats['success_rate']:.1f}%")
        print(f"  Mean response time: {stats['response_times']['mean']*1000:.1f}ms")
        print(f"  P95 response time: {stats['response_times']['p95']*1000:.1f}ms")
        print(f"  Requests/sec: {stats['requests_per_second']:.1f}")
    
    def test_mixed_endpoints_load(self, test_app):
        """Test load across mixed endpoints"""
        client = TestClient(test_app)
        
        endpoints = [
            ("/", "GET", None),
            ("/api/data", "GET", None),
            ("/api/process", "POST", {"data": "test"})
        ]
        
        results = []
        
        for endpoint, method, data in endpoints:
            runner = LoadTestRunner()
            
            def single_request_override(ep, m="GET", d=None):
                start_time = time.perf_counter()
                try:
                    if m.upper() == "GET":
                        response = client.get(ep)
                    elif m.upper() == "POST":
                        response = client.post(ep, json=d)
                    else:
                        raise ValueError(f"Unsupported method: {m}")
                    
                    response_time = time.perf_counter() - start_time
                    return response_time, response.status_code, None
                except Exception as e:
                    response_time = time.perf_counter() - start_time
                    return response_time, 0, str(e)
            
            runner.single_request = single_request_override
            
            result = runner.concurrent_load_test(
                endpoint=endpoint,
                concurrent_users=10,
                requests_per_user=50,
                method=method,
                data=data
            )
            
            results.append((endpoint, result.get_statistics()))
        
        print(f"\nMixed Endpoints Load Test Results:")
        for endpoint, stats in results:
            print(f"  {endpoint}:")
            print(f"    Success rate: {stats['success_rate']:.1f}%")
            print(f"    Mean response time: {stats['response_times']['mean']*1000:.1f}ms")
            print(f"    Requests/sec: {stats['requests_per_second']:.1f}")
            
            # Basic assertions
            assert stats["success_rate"] >= 85, f"{endpoint} success rate too low: {stats['success_rate']:.1f}%"


class TestSecurityImpactLoad:
    """Test load performance with different security configurations"""
    
    def create_app_with_config(self, config: SecurityConfig):
        """Create app with specific security configuration"""
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello World"}
        
        @app.get("/api/test")
        async def test_endpoint():
            return {"test": "data"}
        
        app.add_middleware(SecurityMiddleware, config=config)
        return app
    
    def test_no_security_baseline(self):
        """Test baseline performance with no security"""
        config = SecurityConfig(
            waf_enabled=False,
            bot_detection_enabled=False,
            ip_blocklist_enabled=False,
            rate_limiting_enabled=False,
            auth_monitoring_enabled=False
        )
        
        app = self.create_app_with_config(config)
        client = TestClient(app)
        runner = LoadTestRunner()
        
        def single_request_override(endpoint, method="GET", data=None):
            start_time = time.perf_counter()
            response = client.get(endpoint)
            response_time = time.perf_counter() - start_time
            return response_time, response.status_code, None
        
        runner.single_request = single_request_override
        
        result = runner.concurrent_load_test(
            endpoint="/",
            concurrent_users=50,
            requests_per_user=20
        )
        
        stats = result.get_statistics()
        
        print(f"\nNo Security Baseline:")
        print(f"  Mean response time: {stats['response_times']['mean']*1000:.1f}ms")
        print(f"  P95 response time: {stats['response_times']['p95']*1000:.1f}ms")
        print(f"  Requests/sec: {stats['requests_per_second']:.1f}")
        
        return stats
    
    def test_waf_only_load(self):
        """Test load with WAF only"""
        config = SecurityConfig(
            waf_enabled=True,
            waf_mode="balanced",
            bot_detection_enabled=False,
            ip_blocklist_enabled=False,
            rate_limiting_enabled=False,
            auth_monitoring_enabled=False
        )
        
        app = self.create_app_with_config(config)
        client = TestClient(app)
        runner = LoadTestRunner()
        
        def single_request_override(endpoint, method="GET", data=None):
            start_time = time.perf_counter()
            response = client.get(endpoint)
            response_time = time.perf_counter() - start_time
            return response_time, response.status_code, None
        
        runner.single_request = single_request_override
        
        result = runner.concurrent_load_test(
            endpoint="/",
            concurrent_users=50,
            requests_per_user=20
        )
        
        stats = result.get_statistics()
        
        print(f"\nWAF Only:")
        print(f"  Mean response time: {stats['response_times']['mean']*1000:.1f}ms")
        print(f"  P95 response time: {stats['response_times']['p95']*1000:.1f}ms")
        print(f"  Requests/sec: {stats['requests_per_second']:.1f}")
        
        return stats
    
    def test_full_security_load(self):
        """Test load with full security enabled"""
        config = ProductionConfig()
        
        app = self.create_app_with_config(config)
        client = TestClient(app)
        runner = LoadTestRunner()
        
        def single_request_override(endpoint, method="GET", data=None):
            start_time = time.perf_counter()
            response = client.get(endpoint)
            response_time = time.perf_counter() - start_time
            return response_time, response.status_code, None
        
        runner.single_request = single_request_override
        
        result = runner.concurrent_load_test(
            endpoint="/",
            concurrent_users=50,
            requests_per_user=20
        )
        
        stats = result.get_statistics()
        
        print(f"\nFull Security:")
        print(f"  Mean response time: {stats['response_times']['mean']*1000:.1f}ms")
        print(f"  P95 response time: {stats['response_times']['p95']*1000:.1f}ms")
        print(f"  Requests/sec: {stats['requests_per_second']:.1f}")
        
        return stats
    
    def test_security_overhead_comparison(self):
        """Compare overhead of different security configurations"""
        print(f"\nSecurity Overhead Comparison:")
        
        baseline_stats = self.test_no_security_baseline()
        waf_stats = self.test_waf_only_load()
        full_stats = self.test_full_security_load()
        
        # Calculate overhead
        waf_overhead = (waf_stats['response_times']['mean'] / baseline_stats['response_times']['mean'] - 1) * 100
        full_overhead = (full_stats['response_times']['mean'] / baseline_stats['response_times']['mean'] - 1) * 100
        
        print(f"\nOverhead Analysis:")
        print(f"  WAF overhead: {waf_overhead:.1f}%")
        print(f"  Full security overhead: {full_overhead:.1f}%")
        
        # Overhead should be reasonable
        assert waf_overhead < 100, f"WAF overhead too high: {waf_overhead:.1f}%"
        assert full_overhead < 300, f"Full security overhead too high: {full_overhead:.1f}%"


class TestRateLimitingLoad:
    """Test load scenarios that trigger rate limiting"""
    
    def test_rate_limit_enforcement(self):
        """Test that rate limiting works under load"""
        config = SecurityConfig(
            waf_enabled=False,
            bot_detection_enabled=False,
            ip_blocklist_enabled=False,
            rate_limiting_enabled=True,
            rate_limit_requests=100,  # Low limit for testing
            rate_limit_window=60,
            auth_monitoring_enabled=False
        )
        
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello World"}
        
        app.add_middleware(SecurityMiddleware, config=config)
        client = TestClient(app)
        
        # Make requests that should trigger rate limiting
        responses = []
        for i in range(150):  # Exceed the limit
            response = client.get("/")
            responses.append(response.status_code)
        
        # Count status codes
        status_200 = responses.count(200)
        status_429 = responses.count(429)
        
        print(f"\nRate Limiting Load Test:")
        print(f"  200 OK responses: {status_200}")
        print(f"  429 Rate Limited responses: {status_429}")
        print(f"  Rate limit enforcement: {status_429 > 0}")
        
        # Should have some rate limited responses
        assert status_429 > 0, "Rate limiting not enforced"
        assert status_200 <= 100, f"Too many requests allowed: {status_200}"
    
    def test_rate_limit_under_concurrent_load(self):
        """Test rate limiting under concurrent load"""
        config = SecurityConfig(
            rate_limiting_enabled=True,
            rate_limit_requests=200,  # Higher limit for concurrent test
            rate_limit_window=60
        )
        
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello World"}
        
        app.add_middleware(SecurityMiddleware, config=config)
        client = TestClient(app)
        
        def make_requests(num_requests):
            """Make multiple requests and return status codes"""
            status_codes = []
            for _ in range(num_requests):
                response = client.get("/")
                status_codes.append(response.status_code)
            return status_codes
        
        # Run concurrent users
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_requests, 30) for _ in range(10)]
            all_status_codes = []
            
            for future in as_completed(futures):
                status_codes = future.result()
                all_status_codes.extend(status_codes)
        
        # Analyze results
        total_requests = len(all_status_codes)
        status_200 = all_status_codes.count(200)
        status_429 = all_status_codes.count(429)
        
        print(f"\nConcurrent Rate Limiting Test:")
        print(f"  Total requests: {total_requests}")
        print(f"  200 OK responses: {status_200}")
        print(f"  429 Rate Limited responses: {status_429}")
        print(f"  Success rate: {status_200/total_requests*100:.1f}%")
        
        # Should handle concurrent requests properly
        assert status_200 + status_429 == total_requests, "Unexpected status codes"
        assert status_200 <= 200, f"Rate limit exceeded: {status_200} allowed"


class TestStressTest:
    """Stress tests to find breaking points"""
    
    def test_high_concurrency_stress(self):
        """Test very high concurrency"""
        config = SecurityConfig(
            # Optimize for performance
            waf_enabled=True,
            waf_mode="permissive",
            bot_detection_enabled=False,
            rate_limiting_enabled=True,
            rate_limit_requests=10000,  # High limit
            rate_limit_window=60
        )
        
        app = FastAPI()
        
        @app.get("/")
        async def root():
            return {"message": "Hello World"}
        
        app.add_middleware(SecurityMiddleware, config=config)
        client = TestClient(app)
        runner = LoadTestRunner()
        
        def single_request_override(endpoint, method="GET", data=None):
            start_time = time.perf_counter()
            try:
                response = client.get(endpoint)
                response_time = time.perf_counter() - start_time
                return response_time, response.status_code, None
            except Exception as e:
                response_time = time.perf_counter() - start_time
                return response_time, 0, str(e)
        
        runner.single_request = single_request_override
        
        # High concurrency test
        result = runner.concurrent_load_test(
            endpoint="/",
            concurrent_users=100,  # High concurrency
            requests_per_user=10   # Fewer requests per user to avoid timeout
        )
        
        stats = result.get_statistics()
        
        print(f"\nHigh Concurrency Stress Test:")
        print(f"  Total requests: {stats['total_requests']}")
        print(f"  Success rate: {stats['success_rate']:.1f}%")
        print(f"  Mean response time: {stats['response_times']['mean']*1000:.1f}ms")
        print(f"  P95 response time: {stats['response_times']['p95']*1000:.1f}ms")
        print(f"  Max response time: {stats['response_times']['max']*1000:.1f}ms")
        print(f"  Requests/sec: {stats['requests_per_second']:.1f}")
        print(f"  Error count: {stats['error_count']}")
        
        # Should handle high concurrency reasonably well
        assert stats["success_rate"] >= 80, f"Success rate too low under stress: {stats['success_rate']:.1f}%"
        assert stats["response_times"]["mean"] < 1.0, f"Mean response time too high: {stats['response_times']['mean']:.3f}s"


# Test runner for direct execution
if __name__ == "__main__":
    """Run load tests directly"""
    import sys
    
    print("FastAPI Guard Load Tests")
    print("=" * 40)
    
    # Basic load scenarios
    print("\n🚀  Basic Load Scenarios")
    
    # Note: These tests would typically run against a real server
    # For this example, we'll use TestClient which has limitations
    print("Note: Running with TestClient (limited concurrency simulation)")
    
    # Security impact comparison
    print("\n🔒  Security Impact Analysis")
    test_security = TestSecurityImpactLoad()
    test_security.test_security_overhead_comparison()
    
    # Rate limiting tests
    print("\n⏱️   Rate Limiting Load Tests")
    test_rl = TestRateLimitingLoad()
    test_rl.test_rate_limit_enforcement()
    test_rl.test_rate_limit_under_concurrent_load()
    
    # Stress tests
    print("\n💥  Stress Tests")
    test_stress = TestStressTest()
    test_stress.test_high_concurrency_stress()
    
    print("\n✅  All load tests completed!")
    print("\n📊  For realistic load testing, deploy to a server and use:")
    print("     - Artillery (https://artillery.io/)")
    print("     - Locust (https://locust.io/)")
    print("     - wrk (https://github.com/wg/wrk)")
    print("     - Apache Bench (ab)")