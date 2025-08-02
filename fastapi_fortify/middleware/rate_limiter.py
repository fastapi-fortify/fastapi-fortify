"""
Rate limiting implementations for FastAPI Guard

Provides both in-memory and Redis-based rate limiting with
sliding window algorithms for accurate rate limiting.
"""
import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Any
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class RateLimitInfo:
    """Rate limit tracking information"""
    requests: int
    window_start: float
    window_size: int
    limit: int
    
    @property
    def remaining(self) -> int:
        """Get remaining requests in current window"""
        return max(0, self.limit - self.requests)
    
    @property
    def reset_time(self) -> float:
        """Get timestamp when window resets"""
        return self.window_start + self.window_size
    
    @property
    def seconds_until_reset(self) -> int:
        """Get seconds until window resets"""
        return max(0, int(self.reset_time - time.time()))


class RateLimiter(ABC):
    """Abstract base class for rate limiters"""
    
    @abstractmethod
    async def check_rate_limit(self, key: str, limit: int, window: int) -> Tuple[bool, RateLimitInfo]:
        """
        Check if request is within rate limit
        
        Args:
            key: Unique identifier for rate limiting (e.g., IP address)
            limit: Maximum requests allowed in window
            window: Time window in seconds
            
        Returns:
            Tuple of (allowed, rate_limit_info)
        """
        pass
    
    @abstractmethod
    async def reset_rate_limit(self, key: str) -> bool:
        """
        Reset rate limit for a key
        
        Args:
            key: Unique identifier to reset
            
        Returns:
            True if reset successfully
        """
        pass


class MemoryRateLimiter(RateLimiter):
    """
    In-memory rate limiter using sliding window algorithm
    
    Good for single-instance deployments or development.
    Data is lost when application restarts.
    """
    
    def __init__(self, cache_size: int = 10000, cleanup_interval: int = 300):
        """
        Initialize memory-based rate limiter
        
        Args:
            cache_size: Maximum number of keys to track
            cleanup_interval: How often to clean expired entries (seconds)
        """
        self.cache_size = cache_size
        self.cleanup_interval = cleanup_interval
        
        # Storage for rate limit data
        self.store: Dict[str, RateLimitInfo] = {}
        
        # Cleanup tracking
        self.last_cleanup = time.time()
        
        logger.info(f"Memory rate limiter initialized - Cache size: {cache_size}")
    
    async def check_rate_limit(self, key: str, limit: int, window: int) -> Tuple[bool, RateLimitInfo]:
        """Check rate limit using sliding window algorithm"""
        # Periodic cleanup
        await self._cleanup_expired()
        
        current_time = time.time()
        
        # Get or create rate limit info
        if key not in self.store:
            # First request for this key
            self.store[key] = RateLimitInfo(
                requests=1,
                window_start=current_time,
                window_size=window,
                limit=limit
            )
            return True, self.store[key]
        
        info = self.store[key]
        
        # Check if we need to reset the window
        if current_time >= info.reset_time:
            # Window has expired, start new window
            info.requests = 1
            info.window_start = current_time
            info.window_size = window
            info.limit = limit
            return True, info
        
        # Check if we're within the limit
        if info.requests >= limit:
            # Rate limit exceeded
            return False, info
        
        # Increment request count
        info.requests += 1
        return True, info
    
    async def reset_rate_limit(self, key: str) -> bool:
        """Reset rate limit for a specific key"""
        if key in self.store:
            del self.store[key]
            logger.info(f"Reset rate limit for key: {key}")
            return True
        return False
    
    async def _cleanup_expired(self):
        """Remove expired entries to prevent memory leaks"""
        current_time = time.time()
        
        # Only cleanup periodically
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        # Find expired keys
        expired_keys = []
        for key, info in self.store.items():
            if current_time >= info.reset_time:
                expired_keys.append(key)
        
        # Remove expired keys
        for key in expired_keys:
            del self.store[key]
        
        # If store is too large, remove oldest entries
        if len(self.store) > self.cache_size:
            # Sort by window_start (oldest first) and remove excess
            sorted_items = sorted(self.store.items(), key=lambda x: x[1].window_start)
            excess_count = len(self.store) - self.cache_size
            
            for i in range(excess_count):
                key = sorted_items[i][0]
                del self.store[key]
        
        self.last_cleanup = current_time
        
        if expired_keys:
            logger.debug(f"Cleaned up {len(expired_keys)} expired rate limit entries")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics"""
        return {
            "type": "memory",
            "total_keys": len(self.store),
            "cache_size_limit": self.cache_size,
            "cleanup_interval": self.cleanup_interval,
            "last_cleanup": self.last_cleanup
        }
    
    def get_all_limits(self) -> Dict[str, Dict[str, Any]]:
        """Get all current rate limits (for debugging)"""
        current_time = time.time()
        result = {}
        
        for key, info in self.store.items():
            result[key] = {
                "requests": info.requests,
                "limit": info.limit,
                "remaining": info.remaining,
                "window_size": info.window_size,
                "seconds_until_reset": info.seconds_until_reset,
                "expired": current_time >= info.reset_time
            }
        
        return result


class RedisRateLimiter(RateLimiter):
    """
    Redis-based rate limiter for distributed deployments
    
    Requires Redis connection. Data persists across application restarts
    and works across multiple application instances.
    """
    
    def __init__(
        self, 
        redis_url: str = "redis://localhost:6379",
        key_prefix: str = "fastapi_fortify:rate_limit:",
        connection_pool_size: int = 10
    ):
        """
        Initialize Redis-based rate limiter
        
        Args:
            redis_url: Redis connection URL
            key_prefix: Prefix for Redis keys
            connection_pool_size: Redis connection pool size
        """
        self.redis_url = redis_url
        self.key_prefix = key_prefix
        self.connection_pool_size = connection_pool_size
        
        # Redis connection will be initialized on first use
        self._redis = None
        
        logger.info(f"Redis rate limiter configured - URL: {redis_url}")
    
    async def _get_redis(self):
        """Get Redis connection (lazy initialization)"""
        if self._redis is None:
            try:
                import redis.asyncio as redis
                
                self._redis = redis.from_url(
                    self.redis_url,
                    encoding="utf-8",
                    decode_responses=True,
                    max_connections=self.connection_pool_size
                )
                
                # Test connection
                await self._redis.ping()
                logger.info("Redis connection established")
                
            except ImportError:
                raise ImportError(
                    "Redis support requires 'redis' package. "
                    "Install with: pip install redis"
                )
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {e}")
                raise
        
        return self._redis
    
    async def check_rate_limit(self, key: str, limit: int, window: int) -> Tuple[bool, RateLimitInfo]:
        """Check rate limit using Redis sliding window algorithm"""
        redis = await self._get_redis()
        redis_key = f"{self.key_prefix}{key}"
        current_time = time.time()
        
        try:
            # Use Redis pipeline for atomic operations
            pipe = redis.pipeline()
            
            # Remove expired entries from sorted set
            pipe.zremrangebyscore(redis_key, 0, current_time - window)
            
            # Count current requests in window
            pipe.zcard(redis_key)
            
            # Add current request
            pipe.zadd(redis_key, {str(current_time): current_time})
            
            # Set expiration for the key
            pipe.expire(redis_key, window + 1)
            
            # Execute pipeline
            results = await pipe.execute()
            
            # Get current request count (after cleanup, before adding new request)
            current_requests = results[1]
            
            # Create rate limit info
            window_start = current_time - (current_time % window)  # Align to window
            info = RateLimitInfo(
                requests=current_requests + 1,  # Include the current request
                window_start=window_start,
                window_size=window,
                limit=limit
            )
            
            # Check if limit exceeded
            if current_requests >= limit:
                # Remove the request we just added since it's over limit
                await redis.zrem(redis_key, str(current_time))
                return False, info
            
            return True, info
            
        except Exception as e:
            logger.error(f"Redis rate limit check failed: {e}")
            # Fail open - allow request if Redis is unavailable
            info = RateLimitInfo(
                requests=1,
                window_start=current_time,
                window_size=window,
                limit=limit
            )
            return True, info
    
    async def reset_rate_limit(self, key: str) -> bool:
        """Reset rate limit for a specific key"""
        try:
            redis = await self._get_redis()
            redis_key = f"{self.key_prefix}{key}"
            
            deleted = await redis.delete(redis_key)
            logger.info(f"Reset rate limit for key: {key}")
            return deleted > 0
            
        except Exception as e:
            logger.error(f"Failed to reset rate limit for {key}: {e}")
            return False
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics"""
        try:
            redis = await self._get_redis()
            
            # Get all rate limit keys
            keys = await redis.keys(f"{self.key_prefix}*")
            
            return {
                "type": "redis",
                "redis_url": self.redis_url,
                "key_prefix": self.key_prefix,
                "total_keys": len(keys),
                "connection_pool_size": self.connection_pool_size
            }
            
        except Exception as e:
            logger.error(f"Failed to get Redis stats: {e}")
            return {
                "type": "redis",
                "error": str(e)
            }
    
    async def cleanup(self):
        """Cleanup Redis connections"""
        if self._redis:
            await self._redis.close()
            logger.info("Redis connections closed")


class SlidingWindowRateLimiter(MemoryRateLimiter):
    """
    Enhanced memory rate limiter with precise sliding window
    
    More accurate than fixed window but uses more memory.
    Tracks individual request timestamps for precise sliding window.
    """
    
    def __init__(self, cache_size: int = 10000, cleanup_interval: int = 300):
        super().__init__(cache_size, cleanup_interval)
        
        # Store individual request timestamps for precise sliding window
        self.request_logs: Dict[str, list] = defaultdict(list)
    
    async def check_rate_limit(self, key: str, limit: int, window: int) -> Tuple[bool, RateLimitInfo]:
        """Check rate limit using precise sliding window"""
        await self._cleanup_expired()
        
        current_time = time.time()
        cutoff_time = current_time - window
        
        # Get request log for this key
        request_log = self.request_logs[key]
        
        # Remove requests outside the window
        self.request_logs[key] = [ts for ts in request_log if ts > cutoff_time]
        request_log = self.request_logs[key]
        
        # Check if we're within the limit
        current_requests = len(request_log)
        
        if current_requests >= limit:
            # Rate limit exceeded
            info = RateLimitInfo(
                requests=current_requests,
                window_start=cutoff_time,
                window_size=window,
                limit=limit
            )
            return False, info
        
        # Add current request
        request_log.append(current_time)
        
        # Create rate limit info
        info = RateLimitInfo(
            requests=current_requests + 1,
            window_start=cutoff_time,
            window_size=window,
            limit=limit
        )
        
        return True, info
    
    async def reset_rate_limit(self, key: str) -> bool:
        """Reset rate limit for a specific key"""
        if key in self.request_logs:
            del self.request_logs[key]
        if key in self.store:
            del self.store[key]
        logger.info(f"Reset sliding window rate limit for key: {key}")
        return True
    
    async def _cleanup_expired(self):
        """Enhanced cleanup for sliding window data"""
        await super()._cleanup_expired()
        
        current_time = time.time()
        
        # Cleanup request logs (keep only last 1 hour of data)
        cutoff_time = current_time - 3600  # 1 hour
        
        expired_keys = []
        for key, request_log in self.request_logs.items():
            # Remove old requests
            self.request_logs[key] = [ts for ts in request_log if ts > cutoff_time]
            
            # If no recent requests, mark for removal
            if not self.request_logs[key]:
                expired_keys.append(key)
        
        # Remove empty logs
        for key in expired_keys:
            del self.request_logs[key]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get enhanced statistics"""
        base_stats = super().get_stats()
        base_stats.update({
            "type": "sliding_window",
            "request_logs_count": len(self.request_logs),
            "total_logged_requests": sum(len(log) for log in self.request_logs.values())
        })
        return base_stats


# Factory function for creating rate limiters
def create_rate_limiter(
    limiter_type: str = "memory",
    redis_url: Optional[str] = None,
    **kwargs
) -> RateLimiter:
    """
    Create rate limiter of specified type
    
    Args:
        limiter_type: "memory", "redis", or "sliding_window"
        redis_url: Redis URL (required for redis type)
        **kwargs: Additional arguments for rate limiter
        
    Returns:
        Configured RateLimiter instance
    """
    if limiter_type == "redis":
        if not redis_url:
            raise ValueError("Redis URL required for Redis rate limiter")
        return RedisRateLimiter(redis_url=redis_url, **kwargs)
    elif limiter_type == "sliding_window":
        return SlidingWindowRateLimiter(**kwargs)
    else:  # memory (default)
        return MemoryRateLimiter(**kwargs)


# Decorator for easy rate limiting
def rate_limit(key_func, limit: int, window: int, limiter: Optional[RateLimiter] = None):
    """
    Decorator for rate limiting functions
    
    Args:
        key_func: Function to generate rate limit key from request
        limit: Request limit
        window: Time window in seconds
        limiter: Rate limiter instance (creates default if None)
    """
    if limiter is None:
        limiter = MemoryRateLimiter()
    
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Extract request from args (assumes first arg is request)
            request = args[0] if args else None
            
            if request:
                key = key_func(request)
                allowed, info = await limiter.check_rate_limit(key, limit, window)
                
                if not allowed:
                    from fastapi import HTTPException
                    raise HTTPException(
                        status_code=429,
                        detail=f"Rate limit exceeded. Try again in {info.seconds_until_reset} seconds"
                    )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator