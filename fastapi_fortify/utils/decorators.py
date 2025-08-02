"""
Utility decorators for FastAPI Guard

Provides convenient decorators for common security patterns.
"""
import logging
from functools import wraps
from typing import Callable, Optional, Any
from fastapi import HTTPException, Request, status
from fastapi_fortify.utils.security_utils import SecurityDecision

logger = logging.getLogger(__name__)


def require_auth(
    auth_func: Optional[Callable] = None,
    error_message: str = "Authentication required"
):
    """
    Decorator to require authentication for endpoints
    
    Args:
        auth_func: Function to validate authentication
        error_message: Custom error message
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request from args
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            
            if not request:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Request object not found"
                )
            
            # Check authentication
            if auth_func:
                is_authenticated = await auth_func(request)
                if not is_authenticated:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=error_message
                    )
            else:
                # Default auth check (look for Authorization header)
                auth_header = request.headers.get("authorization")
                if not auth_header or not auth_header.startswith("Bearer "):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=error_message
                    )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def rate_limit(
    requests: int,
    window_seconds: int = 3600,
    key_func: Optional[Callable] = None,
    error_message: str = "Rate limit exceeded"
):
    """
    Decorator to apply rate limiting to endpoints
    
    Args:
        requests: Maximum requests allowed
        window_seconds: Time window in seconds
        key_func: Function to generate rate limit key
        error_message: Custom error message
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request from args
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            
            if not request:
                # If no request found, skip rate limiting
                return await func(*args, **kwargs)
            
            # Generate rate limit key
            if key_func:
                key = key_func(request)
            else:
                # Default to IP address
                client_ip = request.client.host if request.client else "unknown"
                key = f"rate_limit:{client_ip}"
            
            # TODO: Implement rate limiting logic
            # This would integrate with the rate limiter component
            logger.debug(f"Rate limit check for key: {key} ({requests}/{window_seconds}s)")
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def block_bots(
    mode: str = "balanced",
    allow_search_engines: bool = True,
    custom_patterns: Optional[list] = None
):
    """
    Decorator to apply bot detection to endpoints
    
    Args:
        mode: Detection mode ("permissive", "balanced", "strict")
        allow_search_engines: Whether to allow legitimate search bots
        custom_patterns: Additional bot patterns
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request from args
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            
            if not request:
                # If no request found, skip bot detection
                return await func(*args, **kwargs)
            
            # Get user agent
            user_agent = request.headers.get("user-agent", "")
            
            # TODO: Implement bot detection logic
            # This would integrate with the bot detector component
            logger.debug(f"Bot detection check for UA: {user_agent[:50]}...")
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def security_headers(
    csp: Optional[str] = None,
    hsts: bool = True,
    frame_options: str = "DENY",
    content_type_options: bool = True
):
    """
    Decorator to add security headers to responses
    
    Args:
        csp: Content Security Policy
        hsts: Enable HTTP Strict Transport Security
        frame_options: X-Frame-Options value
        content_type_options: Enable X-Content-Type-Options
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            response = await func(*args, **kwargs)
            
            # Add security headers to response
            if hasattr(response, 'headers'):
                if csp:
                    response.headers["Content-Security-Policy"] = csp
                
                if hsts:
                    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
                
                if frame_options:
                    response.headers["X-Frame-Options"] = frame_options
                
                if content_type_options:
                    response.headers["X-Content-Type-Options"] = "nosniff"
                
                response.headers["X-XSS-Protection"] = "1; mode=block"
                response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            
            return response
        
        return wrapper
    return decorator


def log_security_event(
    event_type: str,
    include_request_data: bool = True,
    include_response_data: bool = False
):
    """
    Decorator to log security events
    
    Args:
        event_type: Type of security event
        include_request_data: Whether to include request data
        include_response_data: Whether to include response data
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request from args
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            
            # Log the security event
            event_data = {"event_type": event_type}
            
            if request and include_request_data:
                event_data.update({
                    "method": request.method,
                    "url": str(request.url),
                    "client_ip": request.client.host if request.client else "unknown",
                    "user_agent": request.headers.get("user-agent", "")
                })
            
            try:
                response = await func(*args, **kwargs)
                
                if include_response_data and hasattr(response, 'status_code'):
                    event_data["response_status"] = response.status_code
                
                logger.info(f"Security event: {event_data}")
                return response
                
            except Exception as e:
                event_data["error"] = str(e)
                logger.error(f"Security event failed: {event_data}")
                raise
        
        return wrapper
    return decorator


def validate_input(
    max_length: Optional[int] = None,
    allowed_chars: Optional[str] = None,
    block_patterns: Optional[list] = None
):
    """
    Decorator to validate input parameters
    
    Args:
        max_length: Maximum input length
        allowed_chars: Regex pattern for allowed characters
        block_patterns: List of patterns to block
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Validate string arguments
            for arg in args:
                if isinstance(arg, str):
                    if max_length and len(arg) > max_length:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Input too long (max {max_length} characters)"
                        )
                    
                    # Additional validation would go here
                    
            # Validate keyword arguments
            for key, value in kwargs.items():
                if isinstance(value, str):
                    if max_length and len(value) > max_length:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Parameter '{key}' too long (max {max_length} characters)"
                        )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator