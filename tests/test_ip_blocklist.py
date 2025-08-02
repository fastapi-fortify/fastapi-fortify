"""
Tests for IP Blocklist Management module
"""
import pytest
import json
import tempfile
import os
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch

from fastapi_fortify.protection.ip_blocklist import (
    IPBlocklistManager,
    BlocklistEntry,
    ThreatFeedConfig,
    create_ip_blocklist_manager
)


class TestBlocklistEntry:
    """Test BlocklistEntry dataclass"""
    
    def test_blocklist_entry_creation(self):
        """Test creating blocklist entries"""
        entry = BlocklistEntry(
            ip_or_network="192.168.1.1",
            reason="Test block",
            source="manual",
            blocked_at=datetime.utcnow()
        )
        
        assert entry.ip_or_network == "192.168.1.1"
        assert entry.reason == "Test block"
        assert entry.source == "manual"
        assert entry.severity == "medium"  # Default
        assert entry.expires_at is None  # Default
    
    def test_blocklist_entry_expiration(self):
        """Test blocklist entry expiration logic"""
        now = datetime.utcnow()
        
        # Non-expiring entry
        entry = BlocklistEntry(
            ip_or_network="192.168.1.1",
            reason="Permanent block",
            source="manual",
            blocked_at=now
        )
        assert entry.is_expired() is False
        
        # Expired entry
        entry = BlocklistEntry(
            ip_or_network="192.168.1.2",
            reason="Temporary block", 
            source="manual",
            blocked_at=now,
            expires_at=now - timedelta(hours=1)  # Expired 1 hour ago
        )
        assert entry.is_expired() is True
        
        # Future expiration
        entry = BlocklistEntry(
            ip_or_network="192.168.1.3",
            reason="Future block",
            source="manual", 
            blocked_at=now,
            expires_at=now + timedelta(hours=1)  # Expires in 1 hour
        )
        assert entry.is_expired() is False
    
    def test_ip_matching(self, test_ips):
        """Test IP matching logic"""
        # Single IP entry
        entry = BlocklistEntry(
            ip_or_network="192.168.1.100",
            reason="Test",
            source="test",
            blocked_at=datetime.utcnow()
        )
        
        assert entry.matches_ip("192.168.1.100") is True
        assert entry.matches_ip("192.168.1.101") is False
        assert entry.matches_ip("10.0.0.1") is False
        
        # CIDR network entry
        entry = BlocklistEntry(
            ip_or_network="192.168.1.0/24",
            reason="Network block",
            source="test",
            blocked_at=datetime.utcnow()
        )
        
        assert entry.matches_ip("192.168.1.1") is True
        assert entry.matches_ip("192.168.1.255") is True
        assert entry.matches_ip("192.168.2.1") is False
        assert entry.matches_ip("10.0.0.1") is False
    
    def test_invalid_ip_handling(self):
        """Test handling of invalid IP addresses"""
        entry = BlocklistEntry(
            ip_or_network="192.168.1.1",
            reason="Test",
            source="test",
            blocked_at=datetime.utcnow()
        )
        
        # Invalid IP addresses should not match
        assert entry.matches_ip("invalid.ip") is False
        assert entry.matches_ip("999.999.999.999") is False
        assert entry.matches_ip("") is False
    
    def test_serialization(self):
        """Test entry serialization and deserialization"""
        now = datetime.utcnow()
        entry = BlocklistEntry(
            ip_or_network="192.168.1.1",
            reason="Test block",
            source="manual",
            blocked_at=now,
            expires_at=now + timedelta(hours=24),
            severity="high"
        )
        
        # Serialize to dict
        entry_dict = entry.to_dict()
        assert entry_dict["ip_or_network"] == "192.168.1.1"
        assert entry_dict["reason"] == "Test block"
        assert entry_dict["severity"] == "high"
        assert "blocked_at" in entry_dict
        assert "expires_at" in entry_dict
        
        # Deserialize from dict
        restored_entry = BlocklistEntry.from_dict(entry_dict)
        assert restored_entry.ip_or_network == entry.ip_or_network
        assert restored_entry.reason == entry.reason
        assert restored_entry.severity == entry.severity
        assert restored_entry.blocked_at == entry.blocked_at
        assert restored_entry.expires_at == entry.expires_at


class TestThreatFeedConfig:
    """Test ThreatFeedConfig dataclass"""
    
    def test_threat_feed_config_creation(self):
        """Test creating threat feed configurations"""
        config = ThreatFeedConfig(
            name="test-feed",
            url="https://example.com/threats.txt"
        )
        
        assert config.name == "test-feed"
        assert config.url == "https://example.com/threats.txt"
        assert config.format == "text"  # Default
        assert config.enabled is True  # Default
        assert config.severity == "high"  # Default
        assert config.max_entries == 50000  # Default
    
    def test_threat_feed_config_serialization(self):
        """Test threat feed config serialization"""
        config = ThreatFeedConfig(
            name="test-feed",
            url="https://example.com/threats.txt",
            format="json",
            enabled=False,
            severity="critical"
        )
        
        config_dict = config.to_dict()
        assert config_dict["name"] == "test-feed"
        assert config_dict["format"] == "json"
        assert config_dict["enabled"] is False
        assert config_dict["severity"] == "critical"


class TestIPBlocklistManager:
    """Test IP blocklist manager functionality"""
    
    def test_initialization_without_files(self):
        """Test initialization without any files"""
        manager = IPBlocklistManager()
        
        assert len(manager.static_blocklist) == 0
        assert len(manager.dynamic_blocklist) == 0
        assert len(manager.whitelist) == 0
        assert manager.auto_block_threshold == 5
        assert not manager.block_private_networks
    
    def test_initialization_with_custom_settings(self):
        """Test initialization with custom settings"""
        whitelist_ips = ["192.168.1.1", "10.0.0.1"]
        
        manager = IPBlocklistManager(
            auto_block_threshold=3,
            whitelist_ips=whitelist_ips,
            block_private_networks=True,
            cache_size=50000
        )
        
        assert manager.auto_block_threshold == 3
        assert manager.block_private_networks is True
        assert manager.cache_size == 50000
        assert len(manager.whitelist) == 2
        assert "192.168.1.1" in manager.whitelist
    
    def test_static_blocklist_loading(self, temp_blocklist_file):
        """Test loading static blocklist from file"""
        # Create test blocklist data
        test_entries = [
            {
                "ip_or_network": "192.168.1.100",
                "reason": "Test block",
                "source": "manual",
                "blocked_at": datetime.utcnow().isoformat(),
                "severity": "high"
            }
        ]
        
        # Write test data to file
        with open(temp_blocklist_file, 'w') as f:
            json.dump(test_entries, f)
        
        # Initialize manager with test file
        manager = IPBlocklistManager(static_blocklist_file=temp_blocklist_file)
        
        assert len(manager.static_blocklist) == 1
        entry = list(manager.static_blocklist)[0]
        assert entry.ip_or_network == "192.168.1.100"
        assert entry.reason == "Test block"
        assert entry.severity == "high"
    
    def test_private_network_blocking(self, temp_blocklist_file):
        """Test blocking private networks when enabled"""
        manager = IPBlocklistManager(
            static_blocklist_file=temp_blocklist_file,
            block_private_networks=True
        )
        
        # Should create default private network blocks
        assert len(manager.static_blocklist) > 0
        
        # Check that some private networks are blocked
        is_blocked, reason = manager.is_blocked("10.0.0.1")
        assert is_blocked is True
        assert "private network" in reason.lower()
    
    def test_ip_blocking_and_checking(self):
        """Test basic IP blocking and checking"""
        manager = IPBlocklistManager()
        
        # Initially not blocked
        is_blocked, reason = manager.is_blocked("192.168.1.100")
        assert is_blocked is False
        
        # Add temporary block
        manager.add_temporary_block(
            ip="192.168.1.100",
            reason="Test block",
            hours=24,
            severity="medium"
        )
        
        # Should now be blocked
        is_blocked, reason = manager.is_blocked("192.168.1.100")
        assert is_blocked is True
        assert "Test block" in reason
        
    def test_cidr_network_blocking(self):
        """Test blocking CIDR networks"""
        manager = IPBlocklistManager()
        
        # Block entire network
        manager.add_temporary_block(
            ip="192.168.1.0/24",
            reason="Network block",
            hours=24
        )
        
        # All IPs in network should be blocked
        for i in range(1, 255):
            is_blocked, reason = manager.is_blocked(f"192.168.1.{i}")
            assert is_blocked is True
            assert "Network block" in reason
        
        # IPs outside network should not be blocked
        is_blocked, reason = manager.is_blocked("192.168.2.1")
        assert is_blocked is False
    
    def test_whitelist_functionality(self):
        """Test IP whitelisting"""
        whitelist_ips = ["192.168.1.100", "10.0.0.0/8"]
        manager = IPBlocklistManager(whitelist_ips=whitelist_ips)
        
        # Block an IP that's whitelisted
        manager.add_temporary_block("192.168.1.100", "Should be overridden", 24)
        
        # Should not be blocked due to whitelist
        is_blocked, reason = manager.is_blocked("192.168.1.100")
        assert is_blocked is False
        assert "whitelisted" in reason
        
        # Test CIDR whitelist
        is_blocked, reason = manager.is_blocked("10.0.0.50")
        assert is_blocked is False
        assert "whitelisted" in reason
    
    def test_violation_tracking_and_auto_blocking(self):
        """Test violation tracking and automatic blocking"""
        manager = IPBlocklistManager(auto_block_threshold=3)
        
        ip = "192.168.1.200"
        
        # Add violations below threshold
        for i in range(2):
            blocked = manager.add_violation(ip)
            assert blocked is False  # Should not be auto-blocked yet
        
        # Third violation should trigger auto-block
        blocked = manager.add_violation(ip)
        assert blocked is True
        
        # IP should now be blocked
        is_blocked, reason = manager.is_blocked(ip)
        assert is_blocked is True
        assert "auto-blocked" in reason.lower()
    
    def test_block_removal(self):
        """Test removing blocks"""
        manager = IPBlocklistManager()
        
        ip = "192.168.1.300"
        
        # Add block
        manager.add_temporary_block(ip, "Test block", 24)
        is_blocked, _ = manager.is_blocked(ip)
        assert is_blocked is True
        
        # Remove block
        removed = manager.remove_block(ip)
        assert removed is True
        
        # Should no longer be blocked
        is_blocked, _ = manager.is_blocked(ip)
        assert is_blocked is False
        
        # Removing non-existent block should return False
        removed = manager.remove_block("1.2.3.4")
        assert removed is False
    
    def test_expired_entry_cleanup(self):
        """Test cleanup of expired entries"""
        manager = IPBlocklistManager()
        
        # Add entry that's already expired
        past_time = datetime.utcnow() - timedelta(hours=2)
        expired_entry = BlocklistEntry(
            ip_or_network="192.168.1.400",
            reason="Expired",
            source="test",
            blocked_at=past_time,
            expires_at=past_time + timedelta(hours=1)  # Expired 1 hour ago
        )
        manager.dynamic_blocklist.add(expired_entry)
        
        # Should be blocked initially (cleanup hasn't run)
        is_blocked, reason = manager.is_blocked("192.168.1.400")
        assert is_blocked is False  # Actually, is_blocked checks expiration
        
        # Force cleanup
        manager._cleanup_expired_entries()
        
        # Entry should be removed from blocklist
        assert expired_entry not in manager.dynamic_blocklist
    
    def test_cache_functionality(self):
        """Test IP lookup caching"""
        manager = IPBlocklistManager()
        
        ip = "192.168.1.500"
        
        # First lookup (cache miss)
        is_blocked1, reason1 = manager.is_blocked(ip)
        cache_misses1 = manager.stats["cache_misses"]
        
        # Second lookup (cache hit)
        is_blocked2, reason2 = manager.is_blocked(ip)
        cache_hits = manager.stats["cache_hits"]
        cache_misses2 = manager.stats["cache_misses"]
        
        assert is_blocked1 == is_blocked2
        assert cache_hits > 0
        assert cache_misses2 == cache_misses1  # No additional cache miss
    
    def test_statistics(self):
        """Test statistics collection"""
        manager = IPBlocklistManager()
        
        # Add some data
        manager.add_temporary_block("192.168.1.1", "Test1", 24)
        manager.add_temporary_block("192.168.1.2", "Test2", 24)
        manager.add_violation("192.168.1.3")
        
        # Perform some lookups
        manager.is_blocked("192.168.1.1")
        manager.is_blocked("192.168.1.100")
        
        stats = manager.get_stats()
        
        assert stats["dynamic_entries"] >= 2
        assert stats["queries"] >= 2
        assert stats["auto_block_threshold"] == manager.auto_block_threshold
        assert "violation_counts" in stats
    
    def test_blocklist_export(self):
        """Test blocklist export functionality"""
        manager = IPBlocklistManager()
        
        # Add some entries
        manager.add_temporary_block("192.168.1.1", "Test1", 24, "high")
        manager.add_temporary_block("192.168.1.2", "Test2", 24, "medium")
        
        # Export without expired entries
        exported = manager.export_blocklist(include_expired=False)
        assert len(exported) >= 2
        
        for entry in exported:
            assert "type" in entry
            assert "ip_or_network" in entry
            assert "reason" in entry
    
    def test_blocked_count_by_source(self):
        """Test getting blocked count by source"""
        manager = IPBlocklistManager()
        
        # Add entries from different sources
        manager.add_temporary_block("192.168.1.1", "Manual block", 24)
        manager._add_dynamic_entry("192.168.1.2", "Feed block", "threat_feed", 24)
        manager._add_dynamic_entry("192.168.1.3", "Another manual", "manual", 24)
        
        counts = manager.get_blocked_count_by_source()
        
        assert counts.get("manual", 0) >= 2
        assert counts.get("threat_feed", 0) >= 1
    
    @pytest.mark.asyncio
    async def test_threat_feed_processing_text(self):
        """Test processing text-based threat feeds"""
        manager = IPBlocklistManager()
        
        # Mock threat feed content
        feed_content = """
        # Comment line
        192.168.1.100
        10.0.0.50  # Inline comment
        172.16.0.1;Another comment style
        
        invalid.ip.address
        """
        
        feed_config = ThreatFeedConfig(
            name="test-feed",
            url="https://example.com/feed.txt",
            format="text"
        )
        
        await manager._process_text_feed(feed_content, feed_config)
        
        # Should have added valid IPs
        is_blocked, reason = manager.is_blocked("192.168.1.100")
        assert is_blocked is True
        assert "test-feed" in reason
        
        is_blocked, reason = manager.is_blocked("10.0.0.50")
        assert is_blocked is True
        
        # Invalid IP should not be added
        is_blocked, reason = manager.is_blocked("invalid.ip.address")
        assert is_blocked is False
    
    @pytest.mark.asyncio
    async def test_threat_feed_processing_json(self):
        """Test processing JSON-based threat feeds"""
        manager = IPBlocklistManager()
        
        # Test simple JSON format
        json_data = {
            "ips": ["192.168.1.200", "10.0.0.60", "172.16.0.2"]
        }
        
        feed_config = ThreatFeedConfig(
            name="json-feed",
            url="https://example.com/feed.json",
            format="json"
        )
        
        await manager._process_json_feed(json_data, feed_config)
        
        # Should have added IPs
        is_blocked, reason = manager.is_blocked("192.168.1.200")
        assert is_blocked is True
        assert "json-feed" in reason
    
    @pytest.mark.asyncio 
    async def test_threat_feed_processing_json_array(self):
        """Test processing JSON array format"""
        manager = IPBlocklistManager()
        
        # Test array of IP objects
        json_data = [
            {"ip": "192.168.1.300", "reason": "Malware C&C"},
            {"ip": "10.0.0.70", "reason": "Botnet"},
            "172.16.0.3"  # String format
        ]
        
        feed_config = ThreatFeedConfig(
            name="array-feed",
            url="https://example.com/array.json",
            format="json"
        )
        
        await manager._process_json_feed(json_data, feed_config)
        
        # Should have added all IPs
        is_blocked, reason = manager.is_blocked("192.168.1.300")
        assert is_blocked is True
        
        is_blocked, reason = manager.is_blocked("172.16.0.3")
        assert is_blocked is True
    
    @pytest.mark.asyncio
    async def test_threat_feed_processing_csv(self):
        """Test processing CSV-based threat feeds"""
        manager = IPBlocklistManager()
        
        csv_content = """ip,reason,confidence
192.168.1.400,"Malware host",high
10.0.0.80,"Spam source",medium
172.16.0.4,"Botnet member",high"""
        
        feed_config = ThreatFeedConfig(
            name="csv-feed",
            url="https://example.com/feed.csv",
            format="csv"
        )
        
        await manager._process_csv_feed(csv_content, feed_config)
        
        # Should have added IPs with reasons
        is_blocked, reason = manager.is_blocked("192.168.1.400")
        assert is_blocked is True
        
        is_blocked, reason = manager.is_blocked("10.0.0.80")
        assert is_blocked is True
    
    def test_ip_validation(self):
        """Test IP address validation"""
        manager = IPBlocklistManager()
        
        # Valid IPs
        assert manager._is_valid_ip_or_network("192.168.1.1") is True
        assert manager._is_valid_ip_or_network("10.0.0.0/8") is True
        assert manager._is_valid_ip_or_network("2001:db8::1") is True
        
        # Invalid IPs
        assert manager._is_valid_ip_or_network("invalid.ip") is False
        assert manager._is_valid_ip_or_network("999.999.999.999") is False
        assert manager._is_valid_ip_or_network("") is False

    @pytest.mark.asyncio
    async def test_shutdown(self):
        """Test manager shutdown"""
        manager = IPBlocklistManager()
        
        # Shutdown should complete without errors
        await manager.shutdown()
        
        # Background task should be cancelled
        assert manager._background_task is None or manager._background_task.cancelled()


class TestIPBlocklistFactory:
    """Test IP blocklist factory functions"""
    
    def test_create_ip_blocklist_manager_permissive(self):
        """Test creating permissive IP blocklist manager"""
        manager = create_ip_blocklist_manager("permissive")
        
        assert manager.auto_block_threshold == 10  # Higher threshold
        assert manager.block_private_networks is False
    
    def test_create_ip_blocklist_manager_balanced(self):
        """Test creating balanced IP blocklist manager"""
        manager = create_ip_blocklist_manager("balanced")
        
        assert manager.auto_block_threshold == 5
        assert manager.block_private_networks is False
    
    def test_create_ip_blocklist_manager_strict(self):
        """Test creating strict IP blocklist manager"""
        manager = create_ip_blocklist_manager("strict")
        
        assert manager.auto_block_threshold == 3  # Lower threshold
        assert manager.block_private_networks is True
    
    def test_create_ip_blocklist_manager_with_custom_args(self):
        """Test creating manager with custom arguments"""
        manager = create_ip_blocklist_manager(
            "balanced",
            cache_size=5000,
            cleanup_interval=600
        )
        
        assert manager.cache_size == 5000
        assert manager.cleanup_interval == 600


class TestIPBlocklistIntegration:
    """Integration tests for IP blocklist manager"""
    
    @pytest.mark.asyncio
    async def test_full_threat_feed_workflow(self):
        """Test complete threat feed processing workflow"""
        # Mock HTTP responses for threat feeds
        with patch('httpx.AsyncClient') as mock_client:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = "192.168.1.500\n10.0.0.90\n# Comment\n"
            mock_response.raise_for_status = Mock()
            
            mock_client.return_value.__aenter__.return_value.get.return_value = mock_response
            
            # Create manager with threat feeds
            threat_feeds = [{
                "name": "test-feed",
                "url": "https://example.com/threats.txt",
                "format": "text",
                "enabled": True
            }]
            
            manager = IPBlocklistManager(threat_feeds=threat_feeds)
            
            # Process feeds
            await manager._update_threat_feeds()
            
            # IPs from feed should be blocked
            is_blocked, reason = manager.is_blocked("192.168.1.500")
            assert is_blocked is True
            assert "test-feed" in reason
    
    def test_memory_usage_with_large_blocklists(self):
        """Test memory usage with large blocklists"""
        manager = IPBlocklistManager(cache_size=1000)
        
        # Add many entries
        for i in range(5000):
            ip = f"192.168.{i // 256}.{i % 256}"
            manager.add_temporary_block(ip, f"Block {i}", 24)
        
        # Cache should be limited
        # Perform many lookups to fill cache
        for i in range(2000):
            ip = f"10.0.{i // 256}.{i % 256}"
            manager.is_blocked(ip)
        
        # Cache should respect size limit
        assert len(manager._ip_cache) <= manager.cache_size
    
    def test_concurrent_access_safety(self):
        """Test thread safety of blocklist operations"""
        manager = IPBlocklistManager()
        
        import threading
        import time
        
        def add_blocks():
            for i in range(100):
                ip = f"192.168.100.{i}"
                manager.add_temporary_block(ip, f"Concurrent {i}", 1)
                time.sleep(0.001)  # Small delay
        
        def check_blocks():
            for i in range(100):
                ip = f"192.168.100.{i}"
                manager.is_blocked(ip)
                time.sleep(0.001)  # Small delay
        
        # Run concurrent operations
        threads = [
            threading.Thread(target=add_blocks),
            threading.Thread(target=check_blocks),
            threading.Thread(target=add_blocks)
        ]
        
        for thread in threads:
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Should complete without errors
        # Check that some blocks were added
        stats = manager.get_stats()
        assert stats["dynamic_entries"] > 0
    
    def test_performance_characteristics(self):
        """Test performance characteristics of IP checking"""
        manager = IPBlocklistManager()
        
        # Add various types of blocks
        for i in range(100):
            manager.add_temporary_block(f"192.168.1.{i}", f"Block {i}", 24)
            manager.add_temporary_block(f"10.0.{i}.0/24", f"Network {i}", 24)
        
        # Measure lookup performance
        import time
        start_time = time.time()
        
        for i in range(1000):
            manager.is_blocked(f"192.168.1.{i % 256}")
        
        elapsed = time.time() - start_time
        
        # Should be fast (less than 1 second for 1000 lookups)
        assert elapsed < 1.0
        
        # Cache should improve performance
        cache_hits = manager.stats["cache_hits"]
        assert cache_hits > 0