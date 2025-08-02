"""
IP address utilities for FastAPI Guard
"""
from ipaddress import ip_address, ip_network, AddressValueError
from typing import List, Optional
from fastapi import Request


def get_client_ip(request: Request) -> str:
    """
    Get the real client IP considering proxies and load balancers
    
    Checks headers in order of preference:
    1. Fly-Client-IP (Fly.io specific)
    2. X-Forwarded-For (standard proxy header)
    3. X-Real-IP (nginx proxy header)
    4. Direct connection IP
    
    Args:
        request: FastAPI Request object
        
    Returns:
        Client IP address as string
    """
    # Check Fly.io headers first
    fly_client_ip = request.headers.get('fly-client-ip')
    if fly_client_ip:
        return fly_client_ip.strip()
    
    # Check standard proxy headers
    forwarded_for = request.headers.get('x-forwarded-for')
    if forwarded_for:
        # X-Forwarded-For can contain multiple IPs, first is the client
        return forwarded_for.split(',')[0].strip()
    
    real_ip = request.headers.get('x-real-ip')
    if real_ip:
        return real_ip.strip()
    
    # Fallback to direct connection
    if hasattr(request.client, 'host') and request.client.host:
        return request.client.host
    
    return 'unknown'


def is_valid_ip(ip: str) -> bool:
    """
    Check if string is a valid IP address (IPv4 or IPv6)
    
    Args:
        ip: IP address string to validate
        
    Returns:
        True if valid IP address, False otherwise
    """
    try:
        ip_address(ip)
        return True
    except (AddressValueError, ValueError):
        return False


def is_valid_cidr(cidr: str) -> bool:
    """
    Check if string is a valid CIDR notation
    
    Args:
        cidr: CIDR notation string to validate (e.g., "192.168.1.0/24")
        
    Returns:
        True if valid CIDR notation, False otherwise
    """
    try:
        ip_network(cidr, strict=False)
        return True
    except (AddressValueError, ValueError):
        return False


def ip_in_network(ip: str, network: str) -> bool:
    """
    Check if IP address is within a network range
    
    Args:
        ip: IP address to check
        network: Network in CIDR notation (e.g., "192.168.1.0/24")
        
    Returns:
        True if IP is in network, False otherwise
    """
    try:
        ip_obj = ip_address(ip)
        network_obj = ip_network(network, strict=False)
        return ip_obj in network_obj
    except (AddressValueError, ValueError):
        return False


def ip_matches_patterns(ip: str, patterns: List[str]) -> Optional[str]:
    """
    Check if IP matches any of the given patterns
    
    Patterns can be:
    - Single IP: "192.168.1.1"
    - CIDR range: "192.168.1.0/24"
    - Wildcard: "192.168.1.*" (converted to CIDR)
    
    Args:
        ip: IP address to check
        patterns: List of IP patterns to match against
        
    Returns:
        Matching pattern if found, None otherwise
    """
    if not is_valid_ip(ip):
        return None
    
    for pattern in patterns:
        try:
            if "/" in pattern:
                # CIDR notation
                if ip_in_network(ip, pattern):
                    return pattern
            elif "*" in pattern:
                # Wildcard pattern - convert to CIDR
                if pattern.endswith(".*"):
                    # Convert "192.168.1.*" to "192.168.1.0/24"
                    base = pattern[:-2]  # Remove ".*"
                    parts = base.split(".")
                    if len(parts) == 3:
                        cidr = f"{base}.0/24"
                        if ip_in_network(ip, cidr):
                            return pattern
            else:
                # Single IP
                if ip == pattern:
                    return pattern
        except (AddressValueError, ValueError):
            continue
    
    return None


def is_private_ip(ip: str) -> bool:
    """
    Check if IP address is in private network ranges
    
    Private ranges:
    - 10.0.0.0/8 (Class A)
    - 172.16.0.0/12 (Class B)  
    - 192.168.0.0/16 (Class C)
    - 127.0.0.0/8 (Loopback)
    - ::1 (IPv6 loopback)
    - fc00::/7 (IPv6 private)
    
    Args:
        ip: IP address to check
        
    Returns:
        True if private IP, False otherwise
    """
    try:
        ip_obj = ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback
    except (AddressValueError, ValueError):
        return False


def is_public_ip(ip: str) -> bool:
    """
    Check if IP address is public (not private/reserved)
    
    Args:
        ip: IP address to check
        
    Returns:
        True if public IP, False otherwise  
    """
    try:
        ip_obj = ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or 
                   ip_obj.is_reserved or ip_obj.is_multicast)
    except (AddressValueError, ValueError):
        return False


def normalize_ip_list(ip_list: List[str]) -> List[str]:
    """
    Normalize and validate a list of IP addresses/ranges
    
    Removes invalid entries and normalizes format
    
    Args:
        ip_list: List of IP addresses/CIDR ranges
        
    Returns:
        List of valid, normalized IP addresses/ranges
    """
    normalized = []
    
    for ip_or_range in ip_list:
        ip_or_range = ip_or_range.strip()
        
        if not ip_or_range:
            continue
            
        try:
            if "/" in ip_or_range:
                # CIDR notation
                network = ip_network(ip_or_range, strict=False)
                normalized.append(str(network))
            else:
                # Single IP
                ip_obj = ip_address(ip_or_range)
                normalized.append(str(ip_obj))
        except (AddressValueError, ValueError):
            # Skip invalid entries
            continue
    
    return normalized