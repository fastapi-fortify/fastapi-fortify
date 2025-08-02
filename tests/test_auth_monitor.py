"""
Tests for Authentication Monitoring module
"""
import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch

from fastapi_fortify.monitoring.auth_monitor import (
    AuthMonitor,
    AuthEvent,
    AuthEventType,
    SecurityAlert,
    AlertSeverity,
    create_auth_monitor,
    WebhookProcessor,
    MemoryEventStore,
    LogNotifier,
    WebhookNotifier,
    SlackNotifier,
    ThreatDetector
)


class TestAuthEvent:
    """Test AuthEvent dataclass"""
    
    def test_auth_event_creation(self):
        """Test creating auth events"""
        event = AuthEvent(
            event_type=AuthEventType.LOGIN_SUCCESS,
            user_id="user123",
            email="test@example.com",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            timestamp=datetime.utcnow(),
            metadata={"session_id": "abc123"}
        )
        
        assert event.event_type == AuthEventType.LOGIN_SUCCESS
        assert event.user_id == "user123"
        assert event.email == "test@example.com"
        assert event.success is True  # Default
        assert event.location is None  # Default
    
    def test_auth_event_serialization(self):
        """Test auth event serialization"""
        now = datetime.utcnow()
        event = AuthEvent(
            event_type=AuthEventType.LOGIN_FAILED,
            user_id=None,
            email="test@example.com",
            ip_address="192.168.1.1",
            user_agent="curl/7.0",
            timestamp=now,
            metadata={"reason": "invalid_password"},
            success=False,
            location={"country": "US", "city": "New York"}
        )
        
        # Serialize to dict
        event_dict = event.to_dict()
        assert event_dict["event_type"] == "login_failed"
        assert event_dict["success"] is False
        assert event_dict["location"]["country"] == "US"
        assert event_dict["timestamp"] == now.isoformat()
        
        # Deserialize from dict
        restored_event = AuthEvent.from_dict(event_dict)
        assert restored_event.event_type == AuthEventType.LOGIN_FAILED
        assert restored_event.success is False
        assert restored_event.timestamp == event.timestamp


class TestSecurityAlert:
    """Test SecurityAlert dataclass"""
    
    def test_security_alert_creation(self):
        """Test creating security alerts"""
        alert = SecurityAlert(
            alert_type="brute_force_attack",
            severity=AlertSeverity.HIGH,
            message="Brute force attack detected",
            ip_address="192.168.1.1",
            user_id=None,
            email="target@example.com",
            evidence=[{"failed_attempts": 10}],
            timestamp=datetime.utcnow()
        )
        
        assert alert.alert_type == "brute_force_attack"
        assert alert.severity == AlertSeverity.HIGH
        assert len(alert.evidence) == 1
        assert alert.alert_id is None  # Default
    
    def test_security_alert_serialization(self):
        """Test security alert serialization"""
        now = datetime.utcnow()
        alert = SecurityAlert(
            alert_type="credential_stuffing",
            severity=AlertSeverity.MEDIUM,
            message="Potential credential stuffing",
            ip_address="192.168.1.1",
            user_id="user123",
            email="test@example.com",
            evidence=[{"unique_emails": 5}],
            timestamp=now,
            alert_id="alert123"
        )
        
        alert_dict = alert.to_dict()
        assert alert_dict["alert_id"] == "alert123"
        assert alert_dict["severity"] == "medium"
        assert alert_dict["timestamp"] == now.isoformat()


class TestMemoryEventStore:
    """Test memory event store"""
    
    @pytest.mark.asyncio
    async def test_store_and_retrieve_events(self):
        """Test storing and retrieving events"""
        store = MemoryEventStore(max_events=100)
        
        # Create test events
        event1 = AuthEvent(
            event_type=AuthEventType.LOGIN_SUCCESS,
            user_id="user1",
            email="user1@example.com",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            timestamp=datetime.utcnow(),
            metadata={}
        )
        
        event2 = AuthEvent(
            event_type=AuthEventType.LOGIN_FAILED,
            user_id=None,
            email="user2@example.com",
            ip_address="192.168.1.2",
            user_agent="curl",
            timestamp=datetime.utcnow(),
            metadata={},
            success=False
        )
        
        # Store events
        success1 = await store.store_event(event1)
        success2 = await store.store_event(event2)
        assert success1 is True
        assert success2 is True
        
        # Retrieve all events
        events = await store.get_events(limit=10)
        assert len(events) == 2
        assert events[0].event_type == AuthEventType.LOGIN_FAILED  # Most recent first
        assert events[1].event_type == AuthEventType.LOGIN_SUCCESS
    
    @pytest.mark.asyncio
    async def test_event_filtering(self):
        """Test event filtering capabilities"""
        store = MemoryEventStore()
        
        # Add various events
        now = datetime.utcnow()
        events_data = [
            ("192.168.1.1", "user1@example.com", "user1", AuthEventType.LOGIN_SUCCESS),
            ("192.168.1.1", "user1@example.com", "user1", AuthEventType.LOGIN_FAILED),
            ("192.168.1.2", "user2@example.com", "user2", AuthEventType.LOGIN_SUCCESS),
            ("192.168.1.3", "user3@example.com", "user3", AuthEventType.SIGNUP_SUCCESS),
        ]
        
        for ip, email, user_id, event_type in events_data:
            event = AuthEvent(
                event_type=event_type,
                user_id=user_id,
                email=email,
                ip_address=ip,
                user_agent="test",
                timestamp=now,
                metadata={}
            )
            await store.store_event(event)
        
        # Filter by IP
        events = await store.get_events(ip_address="192.168.1.1")
        assert len(events) == 2
        assert all(e.ip_address == "192.168.1.1" for e in events)
        
        # Filter by email
        events = await store.get_events(email="user2@example.com")
        assert len(events) == 1
        assert events[0].email == "user2@example.com"
        
        # Filter by event type
        events = await store.get_events(event_types=[AuthEventType.LOGIN_SUCCESS])
        assert len(events) == 2
        assert all(e.event_type == AuthEventType.LOGIN_SUCCESS for e in events)
        
        # Filter by time
        future_time = now + timedelta(hours=1)
        events = await store.get_events(since=future_time)
        assert len(events) == 0
    
    @pytest.mark.asyncio
    async def test_max_events_limit(self):
        """Test that store respects max events limit"""
        store = MemoryEventStore(max_events=5)
        
        # Add more events than limit
        for i in range(10):
            event = AuthEvent(
                event_type=AuthEventType.LOGIN_SUCCESS,
                user_id=f"user{i}",
                email=f"user{i}@example.com",
                ip_address="192.168.1.1",
                user_agent="test",
                timestamp=datetime.utcnow(),
                metadata={}
            )
            await store.store_event(event)
        
        # Should only keep last 5 events
        events = await store.get_events(limit=100)
        assert len(events) == 5
        # Should have kept the most recent ones
        assert events[0].user_id == "user9"
        assert events[4].user_id == "user5"


class TestThreatDetector:
    """Test threat detection algorithms"""
    
    @pytest.mark.asyncio
    async def test_brute_force_detection(self):
        """Test brute force attack detection"""
        detector = ThreatDetector(
            brute_force_threshold=3,
            brute_force_window=300
        )
        
        # Create failed login events
        ip = "192.168.1.1"
        now = datetime.utcnow()
        events = []
        
        for i in range(5):
            event = AuthEvent(
                event_type=AuthEventType.LOGIN_FAILED,
                user_id=None,
                email="target@example.com",
                ip_address=ip,
                user_agent="attacker",
                timestamp=now - timedelta(seconds=i * 30),
                metadata={},
                success=False
            )
            events.append(event)
        
        # Should detect brute force
        alert = await detector.detect_brute_force(events, ip)
        assert alert is not None
        assert alert.alert_type == "brute_force_attack"
        assert alert.severity == AlertSeverity.HIGH
        assert alert.ip_address == ip
    
    @pytest.mark.asyncio
    async def test_brute_force_not_detected_below_threshold(self):
        """Test brute force not detected when below threshold"""
        detector = ThreatDetector(
            brute_force_threshold=5,
            brute_force_window=300
        )
        
        # Create only 3 failed attempts
        ip = "192.168.1.1"
        now = datetime.utcnow()
        events = []
        
        for i in range(3):
            event = AuthEvent(
                event_type=AuthEventType.LOGIN_FAILED,
                user_id=None,
                email="target@example.com",
                ip_address=ip,
                user_agent="user",
                timestamp=now - timedelta(seconds=i * 30),
                metadata={},
                success=False
            )
            events.append(event)
        
        # Should not detect brute force
        alert = await detector.detect_brute_force(events, ip)
        assert alert is None
    
    @pytest.mark.asyncio
    async def test_credential_stuffing_detection(self):
        """Test credential stuffing detection"""
        detector = ThreatDetector(
            credential_stuffing_threshold=3,
            credential_stuffing_window=600
        )
        
        # Create failed login events with different emails
        ip = "192.168.1.1"
        now = datetime.utcnow()
        events = []
        emails = ["user1@example.com", "user2@example.com", "user3@example.com"]
        
        for i, email in enumerate(emails):
            event = AuthEvent(
                event_type=AuthEventType.LOGIN_FAILED,
                user_id=None,
                email=email,
                ip_address=ip,
                user_agent="attacker",
                timestamp=now - timedelta(seconds=i * 60),
                metadata={},
                success=False
            )
            events.append(event)
        
        # Should detect credential stuffing
        alert = await detector.detect_credential_stuffing(events, ip)
        assert alert is not None
        assert alert.alert_type == "credential_stuffing"
        assert alert.severity == AlertSeverity.MEDIUM
        assert len(alert.evidence[0]["sample_emails"]) >= 2
    
    @pytest.mark.asyncio
    async def test_excessive_signups_detection(self):
        """Test excessive signup detection"""
        detector = ThreatDetector(
            signup_limit=2,
            signup_window=3600
        )
        
        # Create signup events
        ip = "192.168.1.1"
        now = datetime.utcnow()
        events = []
        
        # Mix of successful and failed signups
        for i in range(4):
            event = AuthEvent(
                event_type=AuthEventType.SIGNUP_SUCCESS if i % 2 == 0 else AuthEventType.SIGNUP_FAILED,
                user_id=f"user{i}" if i % 2 == 0 else None,
                email=f"user{i}@example.com",
                ip_address=ip,
                user_agent="bot",
                timestamp=now - timedelta(minutes=i * 10),
                metadata={},
                success=i % 2 == 0
            )
            events.append(event)
        
        # Should detect excessive signups
        alert = await detector.detect_excessive_signups(events, ip)
        assert alert is not None
        assert alert.alert_type == "excessive_signups"
        assert alert.severity == AlertSeverity.MEDIUM


class TestAlertNotifiers:
    """Test alert notification systems"""
    
    @pytest.mark.asyncio
    async def test_log_notifier(self):
        """Test log-based alert notifier"""
        notifier = LogNotifier(log_level=logging.WARNING)
        
        alert = SecurityAlert(
            alert_type="test_alert",
            severity=AlertSeverity.HIGH,
            message="Test alert message",
            ip_address="192.168.1.1",
            user_id=None,
            email=None,
            evidence=[],
            timestamp=datetime.utcnow()
        )
        
        # Should log without error
        success = await notifier.send_alert(alert)
        assert success is True
    
    @pytest.mark.asyncio
    async def test_webhook_notifier_success(self):
        """Test webhook notifier with successful response"""
        with patch('httpx.AsyncClient') as mock_client:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_client.return_value.__aenter__.return_value.post.return_value = mock_response
            
            notifier = WebhookNotifier("https://example.com/webhook")
            
            alert = SecurityAlert(
                alert_type="test_alert",
                severity=AlertSeverity.MEDIUM,
                message="Test alert",
                ip_address="192.168.1.1",
                user_id=None,
                email=None,
                evidence=[],
                timestamp=datetime.utcnow()
            )
            
            success = await notifier.send_alert(alert)
            assert success is True
    
    @pytest.mark.asyncio
    async def test_webhook_notifier_failure(self):
        """Test webhook notifier with failed response"""
        with patch('httpx.AsyncClient') as mock_client:
            mock_response = Mock()
            mock_response.status_code = 500
            mock_client.return_value.__aenter__.return_value.post.return_value = mock_response
            
            notifier = WebhookNotifier("https://example.com/webhook")
            
            alert = SecurityAlert(
                alert_type="test_alert",
                severity=AlertSeverity.LOW,
                message="Test alert",
                ip_address="192.168.1.1",
                user_id=None,
                email=None,
                evidence=[],
                timestamp=datetime.utcnow()
            )
            
            success = await notifier.send_alert(alert)
            assert success is False
    
    @pytest.mark.asyncio
    async def test_slack_notifier(self):
        """Test Slack webhook notifier"""
        with patch('httpx.AsyncClient') as mock_client:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_client.return_value.__aenter__.return_value.post.return_value = mock_response
            
            notifier = SlackNotifier("https://hooks.slack.com/services/TEST", "#security")
            
            alert = SecurityAlert(
                alert_type="brute_force",
                severity=AlertSeverity.CRITICAL,
                message="Critical security alert",
                ip_address="192.168.1.1",
                user_id="user123",
                email="test@example.com",
                evidence=[{"attempts": 100}],
                timestamp=datetime.utcnow()
            )
            
            success = await notifier.send_alert(alert)
            assert success is True
            
            # Verify Slack payload format
            call_args = mock_client.return_value.__aenter__.return_value.post.call_args
            payload = call_args[1]["json"]
            assert "attachments" in payload
            assert payload["attachments"][0]["color"] == "#ff0000"  # Critical = red
            assert payload["channel"] == "#security"


class TestAuthMonitor:
    """Test main AuthMonitor class"""
    
    @pytest.mark.asyncio
    async def test_auth_monitor_initialization(self):
        """Test auth monitor initialization"""
        monitor = AuthMonitor()
        
        assert monitor.event_store is not None
        assert monitor.threat_detector is not None
        assert len(monitor.notifiers) >= 1
        assert monitor.stats["events_processed"] == 0
    
    @pytest.mark.asyncio
    async def test_process_login_attempt_success(self):
        """Test processing successful login"""
        monitor = AuthMonitor()
        
        alerts = await monitor.process_login_attempt(
            email="user@example.com",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            success=True,
            user_id="user123"
        )
        
        # Successful login shouldn't generate alerts
        assert len(alerts) == 0
        assert monitor.stats["events_processed"] == 1
    
    @pytest.mark.asyncio
    async def test_process_login_attempt_failure(self):
        """Test processing failed login attempts"""
        monitor = AuthMonitor(
            threat_detector=ThreatDetector(brute_force_threshold=3)
        )
        
        ip = "192.168.1.100"
        
        # First few failures shouldn't trigger alert
        for i in range(2):
            alerts = await monitor.process_login_attempt(
                email="target@example.com",
                ip_address=ip,
                user_agent="attacker",
                success=False
            )
            assert len(alerts) == 0
        
        # Third failure should trigger brute force alert
        alerts = await monitor.process_login_attempt(
            email="target@example.com",
            ip_address=ip,
            user_agent="attacker",
            success=False
        )
        
        assert len(alerts) == 1
        assert alerts[0].alert_type == "brute_force_attack"
    
    @pytest.mark.asyncio
    async def test_process_signup_attempt(self):
        """Test processing signup attempts"""
        monitor = AuthMonitor(
            threat_detector=ThreatDetector(signup_limit=2)
        )
        
        ip = "192.168.1.200"
        
        # Process multiple signups
        for i in range(3):
            alerts = await monitor.process_signup_attempt(
                email=f"newuser{i}@example.com",
                ip_address=ip,
                user_agent="bot",
                success=True,
                user_id=f"user{i}"
            )
        
        # Should detect excessive signups
        assert len(alerts) > 0
        assert any(alert.alert_type == "excessive_signups" for alert in alerts)
    
    @pytest.mark.asyncio
    async def test_get_security_summary(self):
        """Test getting security summary"""
        monitor = AuthMonitor()
        
        # Add some events
        await monitor.process_login_attempt(
            "user1@example.com", "192.168.1.1", "Mozilla", True, "user1"
        )
        await monitor.process_login_attempt(
            "user2@example.com", "192.168.1.2", "curl", False
        )
        
        summary = await monitor.get_security_summary(hours=24)
        
        assert summary["period_hours"] == 24
        assert summary["summary"]["total_events"] >= 2
        assert summary["summary"]["failed_logins"] >= 1
        assert summary["summary"]["successful_logins"] >= 1
        assert "top_failed_ips" in summary
    
    @pytest.mark.asyncio
    async def test_get_ip_analysis(self):
        """Test IP address analysis"""
        monitor = AuthMonitor()
        
        ip = "192.168.1.50"
        
        # No activity initially
        analysis = await monitor.get_ip_analysis(ip)
        assert analysis["status"] == "no_activity"
        
        # Add some activity
        await monitor.process_login_attempt(
            "user@example.com", ip, "Mozilla", True, "user1"
        )
        await monitor.process_login_attempt(
            "user@example.com", ip, "Mozilla", False
        )
        
        analysis = await monitor.get_ip_analysis(ip, hours=1)
        assert analysis["status"] == "active"
        assert analysis["analysis"]["total_events"] >= 2
        assert analysis["analysis"]["failed_logins"] >= 1
        assert analysis["analysis"]["successful_logins"] >= 1
    
    @pytest.mark.asyncio
    async def test_add_remove_notifiers(self):
        """Test adding and removing notifiers"""
        monitor = AuthMonitor()
        
        # Add custom notifier
        custom_notifier = LogNotifier()
        monitor.add_notifier(custom_notifier)
        assert custom_notifier in monitor.notifiers
        
        # Remove notifier
        monitor.remove_notifier(custom_notifier)
        assert custom_notifier not in monitor.notifiers
    
    @pytest.mark.asyncio
    async def test_concurrent_event_processing(self):
        """Test concurrent event processing"""
        monitor = AuthMonitor()
        
        # Process many events concurrently
        tasks = []
        for i in range(50):
            task = asyncio.create_task(
                monitor.process_login_attempt(
                    f"user{i}@example.com",
                    f"192.168.1.{i % 256}",
                    "test",
                    i % 2 == 0,  # Alternate success/failure
                    f"user{i}" if i % 2 == 0 else None
                )
            )
            tasks.append(task)
        
        await asyncio.gather(*tasks)
        
        # Should have processed all events
        assert monitor.stats["events_processed"] == 50
    
    @pytest.mark.asyncio
    async def test_shutdown(self):
        """Test monitor shutdown"""
        monitor = AuthMonitor()
        
        # Shutdown should complete without errors
        await monitor.shutdown()


class TestWebhookProcessor:
    """Test webhook processor for various providers"""
    
    @pytest.mark.asyncio
    async def test_process_clerk_webhook_user_created(self):
        """Test processing Clerk user.created webhook"""
        monitor = AuthMonitor()
        processor = WebhookProcessor(monitor)
        
        webhook_data = {
            "type": "user.created",
            "data": {
                "id": "user_123",
                "email_addresses": [
                    {"email_address": "newuser@example.com"}
                ]
            },
            "ip_address": "192.168.1.1",
            "user_agent": "Clerk-Webhook"
        }
        
        alerts = await processor.process_clerk_webhook(webhook_data)
        
        # Should process without errors
        assert isinstance(alerts, list)
        assert monitor.stats["events_processed"] >= 1
    
    @pytest.mark.asyncio
    async def test_process_clerk_webhook_session_created(self):
        """Test processing Clerk session.created webhook"""
        monitor = AuthMonitor()
        processor = WebhookProcessor(monitor)
        
        webhook_data = {
            "type": "session.created",
            "data": {
                "id": "session_123",
                "user_id": "user_123",
                "email_addresses": [
                    {"email_address": "user@example.com"}
                ]
            },
            "ip_address": "192.168.1.1",
            "user_agent": "Clerk-Webhook"
        }
        
        alerts = await processor.process_clerk_webhook(webhook_data)
        
        # Should process without errors
        assert isinstance(alerts, list)
    
    @pytest.mark.asyncio
    async def test_process_custom_webhook(self):
        """Test processing custom webhook format"""
        monitor = AuthMonitor()
        processor = WebhookProcessor(monitor)
        
        webhook_data = {
            "event_type": "login_failed",
            "user_id": None,
            "email": "test@example.com",
            "ip_address": "192.168.1.1",
            "user_agent": "custom-app",
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": {"reason": "invalid_password"},
            "success": False
        }
        
        alerts = await processor.process_custom_webhook(webhook_data)
        
        # Should process without errors
        assert isinstance(alerts, list)
        assert monitor.stats["events_processed"] >= 1
    
    @pytest.mark.asyncio
    async def test_process_invalid_webhook(self):
        """Test handling of invalid webhook data"""
        monitor = AuthMonitor()
        processor = WebhookProcessor(monitor)
        
        # Invalid custom webhook
        invalid_data = {
            "invalid": "data"
        }
        
        alerts = await processor.process_custom_webhook(invalid_data)
        
        # Should handle gracefully
        assert alerts == []


class TestAuthMonitorFactory:
    """Test auth monitor factory functions"""
    
    def test_create_auth_monitor_permissive(self):
        """Test creating permissive auth monitor"""
        monitor = create_auth_monitor("permissive")
        
        assert monitor.threat_detector.brute_force_threshold == 10
        assert monitor.threat_detector.signup_limit == 5
    
    def test_create_auth_monitor_balanced(self):
        """Test creating balanced auth monitor"""
        monitor = create_auth_monitor("balanced")
        
        assert monitor.threat_detector.brute_force_threshold == 5
        assert monitor.threat_detector.signup_limit == 3
    
    def test_create_auth_monitor_strict(self):
        """Test creating strict auth monitor"""
        monitor = create_auth_monitor("strict")
        
        assert monitor.threat_detector.brute_force_threshold == 3
        assert monitor.threat_detector.signup_limit == 2
    
    def test_create_auth_monitor_with_notifications(self):
        """Test creating auth monitor with notifications"""
        monitor = create_auth_monitor(
            "balanced",
            notifications=["log", "webhook"],
            webhook_url="https://example.com/webhook"
        )
        
        # Should have multiple notifiers
        assert len(monitor.notifiers) >= 2
        assert any(isinstance(n, LogNotifier) for n in monitor.notifiers)
        assert any(isinstance(n, WebhookNotifier) for n in monitor.notifiers)


class TestAuthMonitorIntegration:
    """Integration tests for auth monitoring"""
    
    @pytest.mark.asyncio
    async def test_complete_attack_scenario(self):
        """Test complete attack scenario detection"""
        monitor = AuthMonitor(
            threat_detector=ThreatDetector(
                brute_force_threshold=3,
                credential_stuffing_threshold=2
            )
        )
        
        attacker_ip = "192.168.1.99"
        
        # Stage 1: Credential stuffing attempt
        emails = ["user1@example.com", "user2@example.com", "user3@example.com"]
        alerts_total = []
        
        for email in emails:
            alerts = await monitor.process_login_attempt(
                email=email,
                ip_address=attacker_ip,
                user_agent="python-requests",
                success=False
            )
            alerts_total.extend(alerts)
        
        # Should detect both credential stuffing and brute force
        assert len(alerts_total) >= 1
        assert any(a.alert_type == "credential_stuffing" for a in alerts_total)
        assert any(a.alert_type == "brute_force_attack" for a in alerts_total)
        
        # Get IP analysis
        analysis = await monitor.get_ip_analysis(attacker_ip)
        assert analysis["status"] == "active"
        assert analysis["analysis"]["failed_logins"] >= 3
        assert analysis["analysis"]["unique_emails"] >= 2
    
    @pytest.mark.asyncio
    async def test_performance_with_high_volume(self):
        """Test performance with high volume of events"""
        monitor = AuthMonitor()
        
        # Process many events quickly
        start_time = asyncio.get_event_loop().time()
        
        tasks = []
        for i in range(1000):
            task = asyncio.create_task(
                monitor.process_event(
                    AuthEvent(
                        event_type=AuthEventType.LOGIN_SUCCESS,
                        user_id=f"user{i}",
                        email=f"user{i}@example.com",
                        ip_address=f"192.168.{i // 256}.{i % 256}",
                        user_agent="test",
                        timestamp=datetime.utcnow(),
                        metadata={}
                    )
                )
            )
            tasks.append(task)
        
        await asyncio.gather(*tasks)
        
        elapsed = asyncio.get_event_loop().time() - start_time
        
        # Should process 1000 events quickly (less than 5 seconds)
        assert elapsed < 5.0
        assert monitor.stats["events_processed"] == 1000