"""
IP Blocklist Management for FastAPI Guard

Advanced IP blocking with static blocklists, dynamic blocking,
threat intelligence feeds, and automatic expiration.
"""
import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Set, Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from pathlib import Path
from ipaddress import ip_address, ip_network, AddressValueError
import httpx

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BlocklistEntry:
    """Represents a blocked IP or network"""
    ip_or_network: str
    reason: str
    source: str
    blocked_at: datetime
    expires_at: Optional[datetime] = None
    severity: str = "medium"  # low, medium, high, critical
    
    def is_expired(self) -> bool:
        """Check if blocklist entry has expired"""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at
    
    def matches_ip(self, ip: str) -> bool:
        """Check if this entry matches the given IP"""
        try:
            target_ip = ip_address(ip)
            if '/' in self.ip_or_network:
                # CIDR notation
                network = ip_network(self.ip_or_network, strict=False)
                return target_ip in network
            else:
                # Single IP
                blocked_ip = ip_address(self.ip_or_network)
                return target_ip == blocked_ip
        except (AddressValueError, ValueError) as e:
            logger.warning(f"Invalid IP format in blocklist check: {e}")
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "ip_or_network": self.ip_or_network,
            "reason": self.reason,
            "source": self.source,
            "blocked_at": self.blocked_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "severity": self.severity
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BlocklistEntry":
        """Create from dictionary"""
        return cls(
            ip_or_network=data["ip_or_network"],
            reason=data["reason"],
            source=data["source"],
            blocked_at=datetime.fromisoformat(data["blocked_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None,
            severity=data.get("severity", "medium")
        )


@dataclass
class ThreatFeedConfig:
    """Configuration for threat intelligence feeds"""
    name: str
    url: str
    format: str = "text"  # text, json, csv
    update_interval: int = 3600  # seconds
    enabled: bool = True
    severity: str = "high"
    max_entries: int = 50000  # Prevent memory issues
    timeout: int = 30  # HTTP timeout
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


class IPBlocklistManager:
    """
    Comprehensive IP blocklist management system
    
    Features:
    - Static blocklists from files
    - Dynamic temporary blocking
    - Threat intelligence feed integration
    - Automatic expiration
    - Performance-optimized lookups
    - CIDR range support
    """
    
    def __init__(
        self,
        static_blocklist_file: Optional[str] = None,
        threat_feeds: Optional[List[Dict[str, Any]]] = None,
        auto_block_threshold: int = 5,
        whitelist_ips: Optional[List[str]] = None,
        block_private_networks: bool = False,
        cache_size: int = 100000,
        cleanup_interval: int = 300
    ):
        """
        Initialize IP blocklist manager
        
        Args:
            static_blocklist_file: Path to static blocklist JSON file
            threat_feeds: List of threat intelligence feed configurations
            auto_block_threshold: Auto-block after N violations
            whitelist_ips: List of IPs/networks to never block
            block_private_networks: Whether to block private network access
            cache_size: Maximum cache entries
            cleanup_interval: Cleanup interval in seconds
        """
        # Configuration
        self.static_blocklist_file = static_blocklist_file
        self.auto_block_threshold = auto_block_threshold
        self.block_private_networks = block_private_networks
        self.cache_size = cache_size
        self.cleanup_interval = cleanup_interval
        
        # Storage
        self.static_blocklist: Set[BlocklistEntry] = set()
        self.dynamic_blocklist: Set[BlocklistEntry] = set()
        self.whitelist: Set[str] = set()
        self.violation_counts: Dict[str, int] = {}
        
        # Threat intelligence feeds
        self.threat_feeds: List[ThreatFeedConfig] = []
        if threat_feeds:
            for feed_data in threat_feeds:
                self.threat_feeds.append(ThreatFeedConfig(**feed_data))
        
        # Whitelist setup
        if whitelist_ips:
            self.whitelist.update(whitelist_ips)
        
        # Cache for fast lookups
        self._ip_cache: Dict[str, Tuple[bool, str, datetime]] = {}
        self._cache_ttl = 300  # 5 minutes
        
        # Background task tracking
        self._background_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
        
        # Statistics
        self.stats = {
            "queries": 0,
            "blocks": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "feed_updates": 0,
            "last_update": None
        }
        
        # Initialize
        self._load_static_blocklist()
        self._start_background_tasks()
        
        logger.info(f"IP Blocklist Manager initialized - Static: {len(self.static_blocklist)}, "
                   f"Feeds: {len(self.threat_feeds)}, Whitelist: {len(self.whitelist)}")
    
    def _load_static_blocklist(self):
        """Load static blocklist from file"""
        if not self.static_blocklist_file:
            return
        
        blocklist_path = Path(self.static_blocklist_file)
        
        if not blocklist_path.exists():
            # Create default static blocklist
            default_entries = []
            
            # Add private network blocks if enabled
            if self.block_private_networks:
                private_networks = [
                    ("10.0.0.0/8", "Private network - Class A"),
                    ("172.16.0.0/12", "Private network - Class B"),
                    ("192.168.0.0/16", "Private network - Class C"),
                    ("169.254.0.0/16", "Link-local addresses"),
                    ("224.0.0.0/4", "Multicast addresses")
                ]
                
                for network, reason in private_networks:
                    entry = BlocklistEntry(
                        ip_or_network=network,
                        reason=reason,
                        source="static_default",
                        blocked_at=datetime.utcnow(),
                        severity="low"
                    )
                    default_entries.append(entry.to_dict())
            
            # Save default blocklist
            try:
                with open(blocklist_path, 'w') as f:
                    json.dump(default_entries, f, indent=2)
                logger.info(f"Created default static blocklist: {blocklist_path}")
            except Exception as e:
                logger.error(f"Failed to create default blocklist: {e}")
            
            return
        
        # Load existing blocklist
        try:
            with open(blocklist_path, 'r') as f:
                data = json.load(f)
            
            for entry_data in data:
                try:
                    entry = BlocklistEntry.from_dict(entry_data)
                    self.static_blocklist.add(entry)
                except Exception as e:
                    logger.warning(f"Invalid blocklist entry: {entry_data} - {e}")
            
            logger.info(f"Loaded {len(self.static_blocklist)} static blocklist entries")
            
        except Exception as e:
            logger.error(f"Failed to load static blocklist: {e}")
    
    def _start_background_tasks(self):
        """Start background tasks for feed updates and cleanup"""
        if self.threat_feeds:
            self._background_task = asyncio.create_task(self._background_worker())
    
    async def _background_worker(self):
        """Background worker for feed updates and cleanup"""
        try:
            while not self._shutdown_event.is_set():
                try:
                    # Update threat feeds
                    await self._update_threat_feeds()
                    
                    # Cleanup expired entries
                    self._cleanup_expired_entries()
                    
                    # Cleanup cache
                    self._cleanup_cache()
                    
                    # Wait for next update
                    await asyncio.sleep(min(feed.update_interval for feed in self.threat_feeds))
                    
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Error in background worker: {e}")
                    await asyncio.sleep(60)  # Wait before retrying
                    
        except asyncio.CancelledError:
            logger.info("Background worker cancelled")
    
    async def _update_threat_feeds(self):
        """Update all enabled threat intelligence feeds"""
        if not self.threat_feeds:
            return
        
        logger.info("Updating threat intelligence feeds...")
        updated_feeds = 0
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            for feed in self.threat_feeds:
                if not feed.enabled:
                    continue
                
                try:
                    await self._process_threat_feed(client, feed)
                    updated_feeds += 1
                except Exception as e:
                    logger.error(f"Failed to update feed {feed.name}: {e}")
        
        if updated_feeds > 0:
            self.stats["feed_updates"] += updated_feeds
            self.stats["last_update"] = datetime.utcnow().isoformat()
            logger.info(f"Updated {updated_feeds} threat intelligence feeds")
    
    async def _process_threat_feed(self, client: httpx.AsyncClient, feed: ThreatFeedConfig):
        """Process a single threat intelligence feed"""
        try:
            response = await client.get(feed.url, timeout=feed.timeout)
            response.raise_for_status()
            
            if feed.format == "text":
                await self._process_text_feed(response.text, feed)
            elif feed.format == "json":
                await self._process_json_feed(response.json(), feed)
            elif feed.format == "csv":
                await self._process_csv_feed(response.text, feed)
            else:
                logger.warning(f"Unsupported feed format: {feed.format}")
                
        except Exception as e:
            logger.error(f"Error processing feed {feed.name}: {e}")
            raise
    
    async def _process_text_feed(self, content: str, feed: ThreatFeedConfig):
        """Process text-based threat feed (one IP per line)"""
        lines = content.strip().split('\n')
        added_count = 0
        
        for line in lines[:feed.max_entries]:  # Limit entries
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#') or line.startswith(';'):
                continue
            
            # Extract IP (handle comments at end of line)
            ip = line.split('#')[0].split(';')[0].strip()
            
            if self._is_valid_ip_or_network(ip):
                self._add_dynamic_entry(
                    ip_or_network=ip,
                    reason=f"Threat intelligence: {feed.name}",
                    source=feed.name,
                    expires_hours=24,
                    severity=feed.severity
                )
                added_count += 1
        
        logger.debug(f"Added {added_count} entries from feed {feed.name}")
    
    async def _process_json_feed(self, data: Dict[str, Any], feed: ThreatFeedConfig):
        """Process JSON-based threat feed"""
        # Handle different JSON structures
        if "ips" in data:
            # Simple format: {"ips": ["1.2.3.4", "5.6.7.8"]}
            ips = data["ips"][:feed.max_entries]
            for ip in ips:
                if self._is_valid_ip_or_network(ip):
                    self._add_dynamic_entry(
                        ip_or_network=ip,
                        reason=f"Threat intelligence: {feed.name}",
                        source=feed.name,
                        expires_hours=24,
                        severity=feed.severity
                    )
        
        elif isinstance(data, list):
            # Array of IP objects
            for item in data[:feed.max_entries]:
                if isinstance(item, dict) and "ip" in item:
                    ip = item["ip"]
                    reason = item.get("reason", f"Threat intelligence: {feed.name}")
                    
                    if self._is_valid_ip_or_network(ip):
                        self._add_dynamic_entry(
                            ip_or_network=ip,
                            reason=reason,
                            source=feed.name,
                            expires_hours=24,
                            severity=feed.severity
                        )
                elif isinstance(item, str):
                    # Array of IP strings
                    if self._is_valid_ip_or_network(item):
                        self._add_dynamic_entry(
                            ip_or_network=item,
                            reason=f"Threat intelligence: {feed.name}",
                            source=feed.name,
                            expires_hours=24,
                            severity=feed.severity
                        )
    
    async def _process_csv_feed(self, content: str, feed: ThreatFeedConfig):
        """Process CSV-based threat feed"""
        lines = content.strip().split('\n')
        
        # Skip header if present
        if lines and ('ip' in lines[0].lower() or 'address' in lines[0].lower()):
            lines = lines[1:]
        
        for line in lines[:feed.max_entries]:
            parts = line.split(',')
            if parts:
                ip = parts[0].strip().strip('"')
                reason = parts[1].strip().strip('"') if len(parts) > 1 else f"Threat intelligence: {feed.name}"
                
                if self._is_valid_ip_or_network(ip):
                    self._add_dynamic_entry(
                        ip_or_network=ip,
                        reason=reason,
                        source=feed.name,
                        expires_hours=24,
                        severity=feed.severity
                    )
    
    def _is_valid_ip_or_network(self, ip_str: str) -> bool:
        """Check if string is valid IP or CIDR network"""
        try:
            if '/' in ip_str:
                ip_network(ip_str, strict=False)
            else:
                ip_address(ip_str)
            return True
        except (AddressValueError, ValueError):
            return False
    
    def _add_dynamic_entry(
        self, 
        ip_or_network: str, 
        reason: str, 
        source: str,
        expires_hours: int = 24,
        severity: str = "medium"
    ):
        """Add entry to dynamic blocklist"""
        try:
            # Validate IP format
            if not self._is_valid_ip_or_network(ip_or_network):
                return
            
            entry = BlocklistEntry(
                ip_or_network=ip_or_network,
                reason=reason,
                source=source,
                blocked_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(hours=expires_hours),
                severity=severity
            )
            
            # Remove existing entry if present (to update)
            self.dynamic_blocklist.discard(entry)
            self.dynamic_blocklist.add(entry)
            
            # Clear cache for this IP
            self._clear_ip_cache(ip_or_network)
            
        except Exception as e:
            logger.warning(f"Failed to add dynamic entry {ip_or_network}: {e}")
    
    def is_blocked(self, ip: str) -> Tuple[bool, Optional[str]]:
        """
        Check if IP is blocked
        
        Args:
            ip: IP address to check
            
        Returns:
            Tuple of (is_blocked, reason)
        """
        self.stats["queries"] += 1
        
        # Check cache first
        cached_result = self._get_cached_result(ip)
        if cached_result is not None:
            self.stats["cache_hits"] += 1
            return cached_result
        
        self.stats["cache_misses"] += 1
        
        # Check whitelist first
        if self._is_whitelisted(ip):
            result = (False, "whitelisted")
            self._cache_result(ip, result)
            return result
        
        # Check static blocklist
        for entry in self.static_blocklist:
            if entry.matches_ip(ip):
                result = (True, f"Static blocklist: {entry.reason}")
                self._cache_result(ip, result)
                self.stats["blocks"] += 1
                return result
        
        # Check dynamic blocklist
        for entry in self.dynamic_blocklist:
            if not entry.is_expired() and entry.matches_ip(ip):
                result = (True, f"Dynamic blocklist: {entry.reason}")
                self._cache_result(ip, result)
                self.stats["blocks"] += 1
                return result
        
        # Not blocked
        result = (False, None)
        self._cache_result(ip, result)
        return result
    
    def _is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted"""
        try:
            client_ip = ip_address(ip)
            for whitelist_entry in self.whitelist:
                try:
                    if '/' in whitelist_entry:
                        # CIDR notation
                        if client_ip in ip_network(whitelist_entry, strict=False):
                            return True
                    else:
                        # Single IP
                        if client_ip == ip_address(whitelist_entry):
                            return True
                except (AddressValueError, ValueError):
                    continue
        except (AddressValueError, ValueError):
            pass
        
        return False
    
    def _get_cached_result(self, ip: str) -> Optional[Tuple[bool, Optional[str]]]:
        """Get cached lookup result"""
        if ip in self._ip_cache:
            is_blocked, reason, cached_at = self._ip_cache[ip]
            
            # Check if cache entry is still valid
            if (datetime.utcnow() - cached_at).seconds < self._cache_ttl:
                return (is_blocked, reason)
            else:
                # Cache expired
                del self._ip_cache[ip]
        
        return None
    
    def _cache_result(self, ip: str, result: Tuple[bool, Optional[str]]):
        """Cache lookup result"""
        if len(self._ip_cache) >= self.cache_size:
            # Remove oldest entries
            oldest_entries = sorted(
                self._ip_cache.items(),
                key=lambda x: x[1][2]  # cached_at timestamp
            )
            
            # Remove oldest 10%
            remove_count = max(1, len(oldest_entries) // 10)
            for i in range(remove_count):
                del self._ip_cache[oldest_entries[i][0]]
        
        is_blocked, reason = result
        self._ip_cache[ip] = (is_blocked, reason, datetime.utcnow())
    
    def _clear_ip_cache(self, ip_or_network: str):
        """Clear cache entries that might match this IP/network"""
        # For single IPs, just remove that entry
        if '/' not in ip_or_network:
            self._ip_cache.pop(ip_or_network, None)
            return
        
        # For networks, remove all IPs that might be in that network
        try:
            network = ip_network(ip_or_network, strict=False)
            to_remove = []
            
            for cached_ip in self._ip_cache:
                try:
                    if ip_address(cached_ip) in network:
                        to_remove.append(cached_ip)
                except (AddressValueError, ValueError):
                    continue
            
            for ip in to_remove:
                del self._ip_cache[ip]
                
        except (AddressValueError, ValueError):
            pass
    
    def add_temporary_block(
        self, 
        ip: str, 
        reason: str, 
        hours: int = 24, 
        severity: str = "medium"
    ):
        """Add IP to temporary blocklist"""
        self._add_dynamic_entry(ip, reason, "manual", hours, severity)
        logger.warning(f"Added temporary block for {ip}: {reason} (expires in {hours}h)")
    
    def add_violation(self, ip: str) -> bool:
        """
        Add violation for IP and auto-block if threshold reached
        
        Args:
            ip: IP address that violated rules
            
        Returns:
            True if IP was auto-blocked
        """
        if ip not in self.violation_counts:
            self.violation_counts[ip] = 0
        
        self.violation_counts[ip] += 1
        
        # Check if threshold reached
        if self.violation_counts[ip] >= self.auto_block_threshold:
            self.add_temporary_block(
                ip=ip,
                reason=f"Auto-blocked after {self.violation_counts[ip]} violations",
                hours=24,
                severity="high"
            )
            
            # Reset violation count
            self.violation_counts[ip] = 0
            return True
        
        return False
    
    def remove_block(self, ip: str) -> bool:
        """Remove IP from blocklist"""
        removed = False
        
        # Remove from dynamic blocklist
        to_remove = [entry for entry in self.dynamic_blocklist 
                    if entry.ip_or_network == ip]
        for entry in to_remove:
            self.dynamic_blocklist.remove(entry)
            removed = True
        
        # Clear cache
        self._clear_ip_cache(ip)
        
        # Reset violation count
        self.violation_counts.pop(ip, None)
        
        if removed:
            logger.info(f"Removed {ip} from blocklist")
        
        return removed
    
    def _cleanup_expired_entries(self):
        """Remove expired entries from dynamic blocklist"""
        expired_entries = [entry for entry in self.dynamic_blocklist if entry.is_expired()]
        
        for entry in expired_entries:
            self.dynamic_blocklist.remove(entry)
        
        if expired_entries:
            logger.info(f"Removed {len(expired_entries)} expired blocklist entries")
    
    def _cleanup_cache(self):
        """Cleanup old cache entries"""
        current_time = datetime.utcnow()
        expired_keys = []
        
        for ip, (_, _, cached_at) in self._ip_cache.items():
            if (current_time - cached_at).seconds > self._cache_ttl:
                expired_keys.append(ip)
        
        for key in expired_keys:
            del self._ip_cache[key]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get blocklist statistics"""
        return {
            "static_entries": len(self.static_blocklist),
            "dynamic_entries": len(self.dynamic_blocklist),
            "whitelist_entries": len(self.whitelist),
            "cache_entries": len(self._ip_cache),
            "threat_feeds_configured": len(self.threat_feeds),
            "violation_counts": len(self.violation_counts),
            "auto_block_threshold": self.auto_block_threshold,
            **self.stats
        }
    
    def export_blocklist(self, include_expired: bool = False) -> List[Dict[str, Any]]:
        """Export current blocklist for debugging/backup"""
        entries = []
        
        # Static entries
        for entry in self.static_blocklist:
            entry_dict = entry.to_dict()
            entry_dict["type"] = "static"
            entries.append(entry_dict)
        
        # Dynamic entries
        for entry in self.dynamic_blocklist:
            if include_expired or not entry.is_expired():
                entry_dict = entry.to_dict()
                entry_dict["type"] = "dynamic"
                entry_dict["expired"] = entry.is_expired()
                entries.append(entry_dict)
        
        return entries
    
    def get_blocked_count_by_source(self) -> Dict[str, int]:
        """Get count of blocked IPs by source"""
        counts = {}
        
        for entry in self.static_blocklist:
            counts[entry.source] = counts.get(entry.source, 0) + 1
        
        for entry in self.dynamic_blocklist:
            if not entry.is_expired():
                counts[entry.source] = counts.get(entry.source, 0) + 1
        
        return counts
    
    async def shutdown(self):
        """Shutdown blocklist manager and cleanup resources"""
        if self._background_task:
            self._shutdown_event.set()
            self._background_task.cancel()
            try:
                await self._background_task
            except asyncio.CancelledError:
                pass
        
        logger.info("IP Blocklist Manager shutdown complete")


# Factory function for easy creation
def create_ip_blocklist_manager(
    security_level: str = "balanced",
    **kwargs
) -> IPBlocklistManager:
    """
    Create IP blocklist manager with predefined security levels
    
    Args:
        security_level: "permissive", "balanced", or "strict"
        **kwargs: Additional IPBlocklistManager arguments
        
    Returns:
        Configured IPBlocklistManager instance
    """
    if security_level == "permissive":
        return IPBlocklistManager(
            auto_block_threshold=10,  # Higher threshold
            block_private_networks=False,
            **kwargs
        )
    elif security_level == "strict":
        return IPBlocklistManager(
            auto_block_threshold=3,  # Lower threshold
            block_private_networks=True,
            **kwargs
        )
    else:  # balanced
        return IPBlocklistManager(
            auto_block_threshold=5,
            block_private_networks=False,
            **kwargs
        )