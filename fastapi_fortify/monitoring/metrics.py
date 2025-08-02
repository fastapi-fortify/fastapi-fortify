"""
Security Metrics Collection and Reporting for FastAPI Guard

Provides comprehensive metrics collection, aggregation, and reporting
for all security components.
"""
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict, deque
from dataclasses import dataclass
import threading

logger = logging.getLogger(__name__)


@dataclass
class MetricPoint:
    """A single metric data point"""
    timestamp: datetime
    value: float
    tags: Dict[str, str]


class SecurityMetrics:
    """
    Security metrics collection and aggregation system
    
    Collects metrics from all security components and provides
    aggregated views for monitoring and alerting.
    """
    
    def __init__(self, retention_hours: int = 24, max_points: int = 10000):
        """
        Initialize security metrics
        
        Args:
            retention_hours: How long to retain metrics
            max_points: Maximum number of metric points to keep
        """
        self.retention_hours = retention_hours
        self.max_points = max_points
        
        # Thread-safe storage
        self._lock = threading.RLock()
        self._metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_points))
        
        # Aggregated counters
        self._counters: Dict[str, int] = defaultdict(int)
        
        # Last cleanup time
        self._last_cleanup = time.time()
        self._cleanup_interval = 300  # 5 minutes
        
        logger.info(f"Security metrics initialized - Retention: {retention_hours}h")
    
    def record_metric(
        self,
        name: str,
        value: float,
        tags: Optional[Dict[str, str]] = None
    ):
        """
        Record a metric point
        
        Args:
            name: Metric name
            value: Metric value
            tags: Optional tags for the metric
        """
        with self._lock:
            self._metrics[name].append(MetricPoint(
                timestamp=datetime.utcnow(),
                value=value,
                tags=tags or {}
            ))
            
            # Periodic cleanup
            if time.time() - self._last_cleanup > self._cleanup_interval:
                self._cleanup_expired_metrics()
    
    def increment_counter(self, name: str, value: int = 1, tags: Optional[Dict[str, str]] = None):
        """
        Increment a counter metric
        
        Args:
            name: Counter name
            value: Increment value
            tags: Optional tags
        """
        with self._lock:
            self._counters[name] += value
            
            # Also record as time series
            self.record_metric(name, value, tags)
    
    def get_metric_points(
        self,
        name: str,
        since: Optional[datetime] = None,
        limit: Optional[int] = None
    ) -> List[MetricPoint]:
        """
        Get metric points for a specific metric
        
        Args:
            name: Metric name
            since: Return points since this timestamp
            limit: Maximum number of points to return
            
        Returns:
            List of metric points
        """
        with self._lock:
            points = list(self._metrics.get(name, []))
            
            # Filter by timestamp
            if since:
                points = [p for p in points if p.timestamp >= since]
            
            # Apply limit
            if limit:
                points = points[-limit:]
            
            return points
    
    def get_counter_value(self, name: str) -> int:
        """Get current counter value"""
        with self._lock:
            return self._counters.get(name, 0)
    
    def get_all_counters(self) -> Dict[str, int]:
        """Get all counter values"""
        with self._lock:
            return dict(self._counters)
    
    def get_metric_summary(self, name: str, hours: int = 1) -> Dict[str, Any]:
        """
        Get summary statistics for a metric
        
        Args:
            name: Metric name
            hours: Hours to analyze
            
        Returns:
            Summary statistics
        """
        since = datetime.utcnow() - timedelta(hours=hours)
        points = self.get_metric_points(name, since=since)
        
        if not points:
            return {"name": name, "count": 0, "period_hours": hours}
        
        values = [p.value for p in points]
        
        return {
            "name": name,
            "count": len(values),
            "period_hours": hours,
            "min": min(values),
            "max": max(values),
            "avg": sum(values) / len(values),
            "sum": sum(values),
            "first_timestamp": points[0].timestamp.isoformat(),
            "last_timestamp": points[-1].timestamp.isoformat()
        }
    
    def get_all_metrics_summary(self, hours: int = 1) -> Dict[str, Any]:
        """Get summary for all metrics"""
        with self._lock:
            metric_names = list(self._metrics.keys())
        
        summaries = {}
        for name in metric_names:
            summaries[name] = self.get_metric_summary(name, hours)
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "period_hours": hours,
            "metrics": summaries,
            "counters": self.get_all_counters(),
            "total_metric_types": len(metric_names)
        }
    
    def _cleanup_expired_metrics(self):
        """Remove expired metric points"""
        cutoff_time = datetime.utcnow() - timedelta(hours=self.retention_hours)
        
        with self._lock:
            for name, points in self._metrics.items():
                # Remove expired points
                while points and points[0].timestamp < cutoff_time:
                    points.popleft()
        
        self._last_cleanup = time.time()
        logger.debug("Cleaned up expired metrics")
    
    def reset_metrics(self):
        """Reset all metrics (useful for testing)"""
        with self._lock:
            self._metrics.clear()
            self._counters.clear()
        
        logger.info("All metrics have been reset")
    
    def export_metrics(self, format: str = "dict") -> Any:
        """
        Export all metrics in specified format
        
        Args:
            format: Export format ("dict", "prometheus", etc.)
            
        Returns:
            Metrics in requested format
        """
        if format == "dict":
            return self.get_all_metrics_summary(hours=self.retention_hours)
        elif format == "prometheus":
            # Basic Prometheus format
            lines = []
            
            # Export counters
            for name, value in self.get_all_counters().items():
                safe_name = name.replace("-", "_").replace(".", "_")
                lines.append(f"fastapi_fortify_{safe_name}_total {value}")
            
            # Export recent metric summaries
            summaries = self.get_all_metrics_summary(hours=1)
            for name, summary in summaries["metrics"].items():
                safe_name = name.replace("-", "_").replace(".", "_")
                lines.append(f"fastapi_fortify_{safe_name}_count {summary['count']}")
                if summary["count"] > 0:
                    lines.append(f"fastapi_fortify_{safe_name}_sum {summary['sum']}")
                    lines.append(f"fastapi_fortify_{safe_name}_avg {summary['avg']}")
            
            return "\n".join(lines)
        else:
            raise ValueError(f"Unsupported export format: {format}")


# Global metrics instance
_global_metrics: Optional[SecurityMetrics] = None


def get_global_metrics() -> SecurityMetrics:
    """Get or create global metrics instance"""
    global _global_metrics
    if _global_metrics is None:
        _global_metrics = SecurityMetrics()
    return _global_metrics


def record_security_event(event_type: str, details: Optional[Dict[str, Any]] = None):
    """Helper function to record security events"""
    metrics = get_global_metrics()
    metrics.increment_counter(f"security_events.{event_type}", 1, details or {})