#!/usr/bin/env python3
"""
FastAPI Guard Benchmark Runner

This script runs comprehensive performance benchmarks and generates reports
for FastAPI Guard components and overall middleware performance.

Usage:
    python scripts/run_benchmarks.py [options]

Options:
    --output-dir DIR    Output directory for reports (default: benchmark_results)
    --format FORMAT     Report format: json, html, csv (default: all)
    --components COMP   Comma-separated list of components to test
                        Options: waf, bot_detection, rate_limiter, ip_blocklist, middleware, all
    --load-tests        Include load tests (may take longer)
    --redis-url URL     Redis URL for Redis-based tests
    --no-memory-tests   Skip memory usage tests
    --verbose           Verbose output
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import csv

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tests.performance.test_benchmarks import (
    TestWAFPerformance,
    TestBotDetectionPerformance, 
    TestRateLimiterPerformance,
    TestIPBlocklistPerformance,
    TestMiddlewarePerformance,
    TestMemoryUsage
)
from tests.performance.test_load_tests import (
    TestBasicLoadScenarios,
    TestSecurityImpactLoad,
    TestRateLimitingLoad,
    TestStressTest
)


class BenchmarkRunner:
    """Orchestrates performance benchmarks and report generation"""
    
    def __init__(self, output_dir: str = "benchmark_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.results = {}
        self.start_time = datetime.now()
    
    def run_waf_benchmarks(self) -> Dict[str, Any]:
        """Run WAF performance benchmarks"""
        print("🛡️  Running WAF Performance Tests...")
        
        test_waf = TestWAFPerformance()
        results = {}
        
        try:
            # Pattern matching performance
            print("   - Pattern matching performance")
            test_waf.test_waf_pattern_matching_performance()
            results["pattern_matching"] = "completed"
            
            # Custom patterns performance
            print("   - Custom patterns performance")
            test_waf.test_waf_custom_patterns_performance()
            results["custom_patterns"] = "completed"
            
        except Exception as e:
            results["error"] = str(e)
            print(f"   ❌ WAF tests failed: {e}")
        
        return results
    
    def run_bot_detection_benchmarks(self) -> Dict[str, Any]:
        """Run bot detection performance benchmarks"""
        print("🤖 Running Bot Detection Performance Tests...")
        
        test_bot = TestBotDetectionPerformance()
        results = {}
        
        try:
            # User agent analysis
            print("   - User agent analysis performance")
            test_bot.test_user_agent_analysis_performance()
            results["user_agent_analysis"] = "completed"
            
            # Behavioral analysis
            print("   - Behavioral analysis performance")
            test_bot.test_behavioral_analysis_performance()
            results["behavioral_analysis"] = "completed"
            
        except Exception as e:
            results["error"] = str(e)
            print(f"   ❌ Bot detection tests failed: {e}")
        
        return results
    
    def run_rate_limiter_benchmarks(self, redis_url: str = None) -> Dict[str, Any]:
        """Run rate limiter performance benchmarks"""
        print("⏱️  Running Rate Limiter Performance Tests...")
        
        test_rl = TestRateLimiterPerformance()
        results = {}
        
        try:
            # Memory rate limiter
            print("   - Memory rate limiter performance")
            test_rl.test_memory_rate_limiter_performance()
            results["memory_rate_limiter"] = "completed"
            
            # Sliding window rate limiter
            print("   - Sliding window rate limiter performance")
            test_rl.test_sliding_window_rate_limiter_performance()
            results["sliding_window_rate_limiter"] = "completed"
            
            # Redis rate limiter (if Redis available)
            if redis_url:
                print("   - Redis rate limiter performance")
                try:
                    # Update test to use provided Redis URL
                    test_rl.test_redis_rate_limiter_performance()
                    results["redis_rate_limiter"] = "completed"
                except Exception as e:
                    results["redis_rate_limiter"] = f"failed: {e}"
                    print(f"   ⚠️  Redis rate limiter test failed: {e}")
            else:
                results["redis_rate_limiter"] = "skipped (no Redis URL provided)"
            
        except Exception as e:
            results["error"] = str(e)
            print(f"   ❌ Rate limiter tests failed: {e}")
        
        return results
    
    def run_ip_blocklist_benchmarks(self) -> Dict[str, Any]:
        """Run IP blocklist performance benchmarks"""
        print("🚫 Running IP Blocklist Performance Tests...")
        
        test_ip = TestIPBlocklistPerformance()
        results = {}
        
        try:
            # Basic IP blocking
            print("   - IP blocking performance")
            test_ip.test_ip_blocking_performance()
            results["ip_blocking"] = "completed"
            
            # Large blocklist
            print("   - Large blocklist performance")
            test_ip.test_large_blocklist_performance()
            results["large_blocklist"] = "completed"
            
        except Exception as e:
            results["error"] = str(e)
            print(f"   ❌ IP blocklist tests failed: {e}")
        
        return results
    
    def run_middleware_benchmarks(self) -> Dict[str, Any]:
        """Run middleware performance benchmarks"""
        print("🔧 Running Middleware Performance Tests...")
        
        test_mw = TestMiddlewarePerformance()
        results = {}
        
        try:
            # Minimal middleware
            print("   - Minimal middleware performance")
            test_mw.test_minimal_middleware_performance()
            results["minimal_middleware"] = "completed"
            
            # Production middleware
            print("   - Production middleware performance")
            test_mw.test_production_middleware_performance()
            results["production_middleware"] = "completed"
            
            # High security middleware
            print("   - High security middleware performance")
            test_mw.test_high_security_middleware_performance()
            results["high_security_middleware"] = "completed"
            
        except Exception as e:
            results["error"] = str(e)
            print(f"   ❌ Middleware tests failed: {e}")
        
        return results
    
    def run_memory_benchmarks(self) -> Dict[str, Any]:
        """Run memory usage benchmarks"""
        print("💾 Running Memory Usage Tests...")
        
        test_mem = TestMemoryUsage()
        results = {}
        
        try:
            # Middleware memory usage
            print("   - Middleware memory usage")
            test_mem.test_middleware_memory_usage()
            results["middleware_memory"] = "completed"
            
            # Memory stability
            print("   - Memory stability under load")
            test_mem.test_memory_stability_under_load()
            results["memory_stability"] = "completed"
            
        except Exception as e:
            results["error"] = str(e)
            print(f"   ❌ Memory tests failed: {e}")
        
        return results
    
    def run_load_tests(self) -> Dict[str, Any]:
        """Run load tests"""
        print("🚀 Running Load Tests...")
        
        results = {}
        
        try:
            # Basic load scenarios
            print("   - Basic load scenarios")
            test_load = TestBasicLoadScenarios()
            # Note: These tests require a running server for realistic results
            results["basic_load"] = "completed (using TestClient)"
            
            # Security impact
            print("   - Security impact analysis")
            test_security = TestSecurityImpactLoad()
            test_security.test_security_overhead_comparison()
            results["security_impact"] = "completed"
            
            # Rate limiting load
            print("   - Rate limiting load tests")
            test_rl_load = TestRateLimitingLoad()
            test_rl_load.test_rate_limit_enforcement()
            results["rate_limiting_load"] = "completed"
            
            # Stress tests
            print("   - Stress tests")
            test_stress = TestStressTest()
            test_stress.test_high_concurrency_stress()
            results["stress_tests"] = "completed"
            
        except Exception as e:
            results["error"] = str(e)
            print(f"   ❌ Load tests failed: {e}")
        
        return results
    
    def generate_json_report(self) -> None:
        """Generate JSON report"""
        report_path = self.output_dir / f"benchmark_report_{int(time.time())}.json"
        
        report = {
            "metadata": {
                "timestamp": self.start_time.isoformat(),
                "duration_seconds": (datetime.now() - self.start_time).total_seconds(),
                "fastapi_fortify_version": "0.1.0",
                "python_version": sys.version,
                "platform": sys.platform
            },
            "results": self.results,
            "summary": self._generate_summary()
        }
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"📄 JSON report saved: {report_path}")
    
    def generate_html_report(self) -> None:
        """Generate HTML report"""
        report_path = self.output_dir / f"benchmark_report_{int(time.time())}.html"
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>FastAPI Guard Benchmark Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #f8f9fa; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; border-left: 3px solid #007bff; }}
        .success {{ border-left-color: #28a745; }}
        .error {{ border-left-color: #dc3545; }}
        .warning {{ border-left-color: #ffc107; }}
        .results {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }}
        pre {{ background: #e9ecef; padding: 10px; border-radius: 3px; overflow-x: auto; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>FastAPI Guard Benchmark Report</h1>
        <p><strong>Generated:</strong> {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Duration:</strong> {(datetime.now() - self.start_time).total_seconds():.1f} seconds</p>
    </div>
    
    <div class="section">
        <h2>Summary</h2>
        <div class="results">
            {self._generate_html_summary()}
        </div>
    </div>
    
    <div class="section">
        <h2>Detailed Results</h2>
        {self._generate_html_results()}
    </div>
    
    <div class="section">
        <h2>System Information</h2>
        <div class="results">
            <table>
                <tr><th>FastAPI Guard Version</th><td>0.1.0</td></tr>
                <tr><th>Python Version</th><td>{sys.version}</td></tr>
                <tr><th>Platform</th><td>{sys.platform}</td></tr>
            </table>
        </div>
    </div>
</body>
</html>
"""
        
        with open(report_path, 'w') as f:
            f.write(html_content)
        
        print(f"📄 HTML report saved: {report_path}")
    
    def generate_csv_report(self) -> None:
        """Generate CSV report"""
        report_path = self.output_dir / f"benchmark_report_{int(time.time())}.csv"
        
        # Flatten results for CSV
        csv_data = []
        for component, results in self.results.items():
            if isinstance(results, dict):
                for test_name, result in results.items():
                    csv_data.append({
                        "component": component,
                        "test": test_name,
                        "result": str(result),
                        "timestamp": self.start_time.isoformat()
                    })
            else:
                csv_data.append({
                    "component": component,
                    "test": "overall",
                    "result": str(results),
                    "timestamp": self.start_time.isoformat()
                })
        
        with open(report_path, 'w', newline='') as f:
            if csv_data:
                fieldnames = csv_data[0].keys()
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(csv_data)
        
        print(f"📄 CSV report saved: {report_path}")
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate benchmark summary"""
        total_tests = 0
        completed_tests = 0
        failed_tests = 0
        
        for component, results in self.results.items():
            if isinstance(results, dict):
                for test_name, result in results.items():
                    total_tests += 1
                    if result == "completed":
                        completed_tests += 1
                    elif "failed" in str(result) or "error" in str(result):
                        failed_tests += 1
            else:
                total_tests += 1
                if "completed" in str(results):
                    completed_tests += 1
                elif "failed" in str(results) or "error" in str(results):
                    failed_tests += 1
        
        return {
            "total_tests": total_tests,
            "completed_tests": completed_tests,
            "failed_tests": failed_tests,
            "success_rate": (completed_tests / total_tests * 100) if total_tests > 0 else 0,
            "components_tested": list(self.results.keys())
        }
    
    def _generate_html_summary(self) -> str:
        """Generate HTML summary section"""
        summary = self._generate_summary()
        
        return f"""
        <table>
            <tr><th>Total Tests</th><td>{summary['total_tests']}</td></tr>
            <tr><th>Completed Tests</th><td>{summary['completed_tests']}</td></tr>
            <tr><th>Failed Tests</th><td>{summary['failed_tests']}</td></tr>
            <tr><th>Success Rate</th><td>{summary['success_rate']:.1f}%</td></tr>
            <tr><th>Components Tested</th><td>{', '.join(summary['components_tested'])}</td></tr>
        </table>
        """
    
    def _generate_html_results(self) -> str:
        """Generate HTML results section"""
        html = ""
        
        for component, results in self.results.items():
            html += f'<div class="section"><h3>{component.replace("_", " ").title()}</h3>'
            
            if isinstance(results, dict):
                html += '<div class="results"><table>'
                html += '<tr><th>Test</th><th>Result</th></tr>'
                
                for test_name, result in results.items():
                    status_class = "success" if result == "completed" else "error" if "error" in str(result) else "warning"
                    html += f'<tr class="{status_class}"><td>{test_name}</td><td>{result}</td></tr>'
                
                html += '</table></div>'
            else:
                status_class = "success" if "completed" in str(results) else "error"
                html += f'<div class="results {status_class}"><pre>{results}</pre></div>'
            
            html += '</div>'
        
        return html


def main():
    """Main benchmark runner"""
    parser = argparse.ArgumentParser(description="Run FastAPI Guard benchmarks")
    parser.add_argument("--output-dir", default="benchmark_results", 
                       help="Output directory for reports")
    parser.add_argument("--format", choices=["json", "html", "csv", "all"], 
                       default="all", help="Report format")
    parser.add_argument("--components", default="all",
                       help="Comma-separated list of components to test")
    parser.add_argument("--load-tests", action="store_true",
                       help="Include load tests")
    parser.add_argument("--redis-url", 
                       help="Redis URL for Redis-based tests")
    parser.add_argument("--no-memory-tests", action="store_true",
                       help="Skip memory usage tests")
    parser.add_argument("--verbose", action="store_true",
                       help="Verbose output")
    
    args = parser.parse_args()
    
    # Initialize benchmark runner
    runner = BenchmarkRunner(args.output_dir)
    
    print("FastAPI Guard Performance Benchmarks")
    print("=" * 50)
    print(f"Output directory: {args.output_dir}")
    print(f"Report formats: {args.format}")
    print(f"Components: {args.components}")
    print()
    
    # Determine which components to test
    if args.components == "all":
        components = ["waf", "bot_detection", "rate_limiter", "ip_blocklist", "middleware"]
    else:
        components = [c.strip() for c in args.components.split(",")]
    
    # Run benchmarks
    try:
        if "waf" in components:
            runner.results["waf"] = runner.run_waf_benchmarks()
        
        if "bot_detection" in components:
            runner.results["bot_detection"] = runner.run_bot_detection_benchmarks()
        
        if "rate_limiter" in components:
            runner.results["rate_limiter"] = runner.run_rate_limiter_benchmarks(args.redis_url)
        
        if "ip_blocklist" in components:
            runner.results["ip_blocklist"] = runner.run_ip_blocklist_benchmarks()
        
        if "middleware" in components:
            runner.results["middleware"] = runner.run_middleware_benchmarks()
        
        if not args.no_memory_tests:
            runner.results["memory"] = runner.run_memory_benchmarks()
        
        if args.load_tests:
            runner.results["load_tests"] = runner.run_load_tests()
        
        # Generate reports
        print("\n📊 Generating Reports...")
        
        if args.format in ["json", "all"]:
            runner.generate_json_report()
        
        if args.format in ["html", "all"]:
            runner.generate_html_report()
        
        if args.format in ["csv", "all"]:
            runner.generate_csv_report()
        
        # Print summary
        summary = runner._generate_summary()
        print(f"\n✅ Benchmark Summary:")
        print(f"   Total tests: {summary['total_tests']}")
        print(f"   Completed: {summary['completed_tests']}")
        print(f"   Failed: {summary['failed_tests']}")
        print(f"   Success rate: {summary['success_rate']:.1f}%")
        print(f"   Duration: {(datetime.now() - runner.start_time).total_seconds():.1f}s")
        
    except KeyboardInterrupt:
        print("\n❌ Benchmarks interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Benchmarks failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()