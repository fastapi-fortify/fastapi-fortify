"""
Authentication Monitoring for FastAPI Guard

Comprehensive authentication event monitoring, threat detection,
and alerting system for brute force, credential stuffing, and
suspicious authentication patterns.
"""
import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Set
from collections import defaultdict
from dataclasses import dataclass, asdict
from enum import Enum
from abc import ABC, abstractmethod

import httpx

logger = logging.getLogger(__name__)


class AuthEventType(Enum):
    """Types of authentication events"""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    SIGNUP_SUCCESS = "signup_success"
    SIGNUP_FAILED = "signup_failed"
    PASSWORD_RESET = "password_reset"
    ACCOUNT_LOCKED = "account_locked"
    SUSPICIOUS_LOGIN = "suspicious_login"
    BRUTE_FORCE_DETECTED = "brute_force_detected"
    CREDENTIAL_STUFFING = "credential_stuffing"
    RATE_LIMITED = "rate_limited"
    BOT_DETECTED = "bot_detected"


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AuthEvent:
    """Authentication event data"""
    event_type: AuthEventType
    user_id: Optional[str]
    email: Optional[str]
    ip_address: str
    user_agent: str
    timestamp: datetime
    metadata: Dict[str, Any]
    success: bool = True
    location: Optional[Dict[str, str]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "event_type": self.event_type.value,
            "user_id": self.user_id,
            "email": self.email,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
            "success": self.success,
            "location": self.location
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthEvent":
        """Create from dictionary"""
        return cls(
            event_type=AuthEventType(data["event_type"]),
            user_id=data.get("user_id"),
            email=data.get("email"),
            ip_address=data["ip_address"],
            user_agent=data["user_agent"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            metadata=data.get("metadata", {}),
            success=data.get("success", True),
            location=data.get("location")
        )


@dataclass
class SecurityAlert:
    """Security alert for suspicious activity"""
    alert_type: str
    severity: AlertSeverity
    message: str
    ip_address: str
    user_id: Optional[str]
    email: Optional[str]
    evidence: List[Dict[str, Any]]
    timestamp: datetime
    alert_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type,
            "severity": self.severity.value,
            "message": self.message,
            "ip_address": self.ip_address,
            "user_id": self.user_id,
            "email": self.email,
            "evidence": self.evidence,
            "timestamp": self.timestamp.isoformat()
        }


class AlertNotifier(ABC):
    """Abstract base class for alert notifications"""
    
    @abstractmethod
    async def send_alert(self, alert: SecurityAlert) -> bool:
        """Send security alert"""
        pass


class LogNotifier(AlertNotifier):
    """Simple log-based alert notifier"""
    
    def __init__(self, log_level: int = logging.WARNING):
        self.log_level = log_level
    
    async def send_alert(self, alert: SecurityAlert) -> bool:
        """Log security alert"""
        try:
            logger.log(
                self.log_level,
                f"Security Alert [{alert.severity.value.upper()}]: {alert.alert_type} - {alert.message}"
            )
            return True
        except Exception as e:
            logger.error(f"Failed to log security alert: {e}")
            return False


class WebhookNotifier(AlertNotifier):
    """Webhook-based alert notifier"""
    
    def __init__(
        self,
        webhook_url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 10
    ):
        self.webhook_url = webhook_url
        self.headers = headers or {"Content-Type": "application/json"}
        self.timeout = timeout
    
    async def send_alert(self, alert: SecurityAlert) -> bool:
        """Send alert to webhook"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.webhook_url,
                    json=alert.to_dict(),
                    headers=self.headers
                )
                return response.status_code < 400
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
            return False


class SlackNotifier(AlertNotifier):
    """Slack webhook alert notifier"""
    
    def __init__(self, webhook_url: str, channel: Optional[str] = None):
        self.webhook_url = webhook_url
        self.channel = channel
    
    async def send_alert(self, alert: SecurityAlert) -> bool:
        """Send alert to Slack"""
        try:
            color = {
                AlertSeverity.LOW: "good",
                AlertSeverity.MEDIUM: "warning",
                AlertSeverity.HIGH: "danger",
                AlertSeverity.CRITICAL: "#ff0000"
            }.get(alert.severity, "warning")
            
            payload = {
                "attachments": [{
                    "color": color,
                    "title": f"🚨 Security Alert: {alert.alert_type}",
                    "text": alert.message,
                    "fields": [
                        {"title": "Severity", "value": alert.severity.value.upper(), "short": True},
                        {"title": "IP Address", "value": alert.ip_address, "short": True},
                        {"title": "User", "value": alert.email or "Unknown", "short": True},
                        {"title": "Time", "value": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"), "short": True}
                    ],
                    "footer": "FastAPI Guard",
                    "ts": int(alert.timestamp.timestamp())
                }]
            }
            
            if self.channel:
                payload["channel"] = self.channel
            
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(self.webhook_url, json=payload)
                return response.status_code == 200
                
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
            return False


class EventStore(ABC):
    """Abstract base class for event storage"""
    
    @abstractmethod
    async def store_event(self, event: AuthEvent) -> bool:
        """Store authentication event"""
        pass
    
    @abstractmethod
    async def get_events(
        self,
        ip_address: Optional[str] = None,
        email: Optional[str] = None,
        user_id: Optional[str] = None,
        event_types: Optional[List[AuthEventType]] = None,
        since: Optional[datetime] = None,
        limit: int = 100
    ) -> List[AuthEvent]:
        """Retrieve authentication events"""
        pass


class MemoryEventStore(EventStore):
    """In-memory event storage (for development/testing)"""
    
    def __init__(self, max_events: int = 10000):
        self.max_events = max_events
        self.events: List[AuthEvent] = []
        self._lock = asyncio.Lock()
    
    async def store_event(self, event: AuthEvent) -> bool:
        """Store event in memory"""
        async with self._lock:
            self.events.append(event)
            
            # Maintain max size
            if len(self.events) > self.max_events:
                self.events = self.events[-self.max_events:]
            
            return True
    
    async def get_events(
        self,
        ip_address: Optional[str] = None,
        email: Optional[str] = None,
        user_id: Optional[str] = None,
        event_types: Optional[List[AuthEventType]] = None,
        since: Optional[datetime] = None,
        limit: int = 100
    ) -> List[AuthEvent]:
        """Retrieve events from memory"""
        async with self._lock:
            filtered_events = []
            
            for event in reversed(self.events):  # Most recent first
                # Apply filters
                if ip_address and event.ip_address != ip_address:
                    continue
                if email and event.email != email:
                    continue
                if user_id and event.user_id != user_id:
                    continue
                if event_types and event.event_type not in event_types:
                    continue
                if since and event.timestamp < since:
                    continue
                
                filtered_events.append(event)
                
                if len(filtered_events) >= limit:
                    break
            
            return filtered_events


class ThreatDetector:
    """Threat detection algorithms for authentication events"""
    
    def __init__(
        self,
        brute_force_threshold: int = 5,
        brute_force_window: int = 300,
        credential_stuffing_threshold: int = 3,
        credential_stuffing_window: int = 600,
        signup_limit: int = 3,
        signup_window: int = 3600
    ):
        self.brute_force_threshold = brute_force_threshold
        self.brute_force_window = brute_force_window
        self.credential_stuffing_threshold = credential_stuffing_threshold
        self.credential_stuffing_window = credential_stuffing_window
        self.signup_limit = signup_limit
        self.signup_window = signup_window
    
    async def detect_brute_force(
        self,
        events: List[AuthEvent],
        ip_address: str
    ) -> Optional[SecurityAlert]:
        """Detect brute force attacks from IP"""
        current_time = datetime.utcnow()
        cutoff_time = current_time - timedelta(seconds=self.brute_force_window)
        
        # Count failed login attempts from this IP
        failed_attempts = [
            event for event in events
            if (event.ip_address == ip_address and
                event.event_type == AuthEventType.LOGIN_FAILED and
                event.timestamp > cutoff_time)
        ]
        
        if len(failed_attempts) >= self.brute_force_threshold:
            return SecurityAlert(
                alert_type="brute_force_attack",
                severity=AlertSeverity.HIGH,
                message=f"Brute force attack detected from {ip_address}",
                ip_address=ip_address,
                user_id=None,
                email=failed_attempts[-1].email if failed_attempts else None,
                evidence=[{
                    "failed_attempts": len(failed_attempts),
                    "time_window": f"{self.brute_force_window}s",
                    "sample_attempts": [event.to_dict() for event in failed_attempts[-3:]]
                }],
                timestamp=current_time
            )
        
        return None
    
    async def detect_credential_stuffing(
        self,
        events: List[AuthEvent],
        ip_address: str
    ) -> Optional[SecurityAlert]:
        """Detect credential stuffing attacks"""
        current_time = datetime.utcnow()
        cutoff_time = current_time - timedelta(seconds=self.credential_stuffing_window)
        
        # Get recent failed attempts from this IP
        failed_attempts = [
            event for event in events
            if (event.ip_address == ip_address and
                event.event_type == AuthEventType.LOGIN_FAILED and
                event.timestamp > cutoff_time)
        ]
        
        # Check for multiple different email addresses
        unique_emails = set(event.email for event in failed_attempts if event.email)
        
        if (len(failed_attempts) >= self.credential_stuffing_threshold and
                len(unique_emails) >= 2):
            return SecurityAlert(
                alert_type="credential_stuffing",
                severity=AlertSeverity.MEDIUM,
                message=f"Credential stuffing detected from {ip_address}",
                ip_address=ip_address,
                user_id=None,
                email=None,
                evidence=[{
                    "failed_attempts": len(failed_attempts),
                    "unique_emails": len(unique_emails),
                    "time_window": f"{self.credential_stuffing_window}s",
                    "sample_emails": list(unique_emails)[:5]
                }],
                timestamp=current_time
            )
        
        return None
    
    async def detect_excessive_signups(
        self,
        events: List[AuthEvent],
        ip_address: str
    ) -> Optional[SecurityAlert]:
        """Detect excessive signup attempts"""
        current_time = datetime.utcnow()
        cutoff_time = current_time - timedelta(seconds=self.signup_window)
        
        # Count signups from this IP
        signups = [
            event for event in events
            if (event.ip_address == ip_address and
                event.event_type in [AuthEventType.SIGNUP_SUCCESS, AuthEventType.SIGNUP_FAILED] and
                event.timestamp > cutoff_time)
        ]
        
        if len(signups) > self.signup_limit:
            return SecurityAlert(
                alert_type="excessive_signups",
                severity=AlertSeverity.MEDIUM,
                message=f"Excessive signups from {ip_address}",
                ip_address=ip_address,
                user_id=None,
                email=None,
                evidence=[{
                    "signup_count": len(signups),
                    "time_window": f"{self.signup_window}s",
                    "successful_signups": len([s for s in signups if s.success]),
                    "failed_signups": len([s for s in signups if not s.success])
                }],
                timestamp=current_time
            )
        
        return None


class AuthMonitor:
    """
    Comprehensive authentication monitoring system
    
    Features:
    - Authentication event tracking
    - Threat detection (brute force, credential stuffing)
    - Real-time alerting
    - Webhook processing
    - Configurable storage and notifications
    """
    
    def __init__(
        self,
        event_store: Optional[EventStore] = None,
        threat_detector: Optional[ThreatDetector] = None,
        notifiers: Optional[List[AlertNotifier]] = None,
        cleanup_interval: int = 300
    ):
        """
        Initialize authentication monitor
        
        Args:
            event_store: Event storage backend
            threat_detector: Threat detection engine
            notifiers: List of alert notifiers
            cleanup_interval: Cleanup interval in seconds
        """
        self.event_store = event_store or MemoryEventStore()
        self.threat_detector = threat_detector or ThreatDetector()
        self.notifiers = notifiers or [LogNotifier()]
        self.cleanup_interval = cleanup_interval
        
        # Background task tracking
        self._background_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
        
        # Statistics
        self.stats = {
            "events_processed": 0,
            "alerts_generated": 0,
            "last_cleanup": None,
            "startup_time": datetime.utcnow().isoformat()
        }
        
        logger.info("Authentication monitor initialized")
    
    async def process_event(self, event: AuthEvent) -> List[SecurityAlert]:
        """
        Process authentication event and detect threats
        
        Args:
            event: Authentication event to process
            
        Returns:
            List of security alerts generated
        """
        alerts = []
        
        try:
            # Store the event
            await self.event_store.store_event(event)
            self.stats["events_processed"] += 1
            
            # Get recent events for threat analysis
            recent_events = await self.event_store.get_events(
                ip_address=event.ip_address,
                since=datetime.utcnow() - timedelta(hours=1),
                limit=1000
            )
            
            # Run threat detection
            threats = [
                await self.threat_detector.detect_brute_force(recent_events, event.ip_address),
                await self.threat_detector.detect_credential_stuffing(recent_events, event.ip_address),
                await self.threat_detector.detect_excessive_signups(recent_events, event.ip_address)
            ]
            
            # Filter out None results
            alerts = [alert for alert in threats if alert is not None]
            
            # Send alerts
            for alert in alerts:
                await self._send_alert(alert)
            
            logger.debug(f"Processed auth event: {event.event_type.value} from {event.ip_address}")
            
        except Exception as e:
            logger.error(f"Error processing auth event: {e}")
        
        return alerts
    
    async def process_login_attempt(
        self,
        email: str,
        ip_address: str,
        user_agent: str,
        success: bool,
        user_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[SecurityAlert]:
        """
        Process login attempt
        
        Args:
            email: User email
            ip_address: Client IP address
            user_agent: User agent string
            success: Whether login was successful
            user_id: User ID (if successful)
            metadata: Additional metadata
            
        Returns:
            List of security alerts generated
        """
        event = AuthEvent(
            event_type=AuthEventType.LOGIN_SUCCESS if success else AuthEventType.LOGIN_FAILED,
            user_id=user_id,
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            timestamp=datetime.utcnow(),
            metadata=metadata or {},
            success=success
        )
        
        return await self.process_event(event)
    
    async def process_signup_attempt(
        self,
        email: str,
        ip_address: str,
        user_agent: str,
        success: bool,
        user_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[SecurityAlert]:
        """
        Process signup attempt
        
        Args:
            email: User email
            ip_address: Client IP address
            user_agent: User agent string
            success: Whether signup was successful
            user_id: User ID (if successful)
            metadata: Additional metadata
            
        Returns:
            List of security alerts generated
        """
        event = AuthEvent(
            event_type=AuthEventType.SIGNUP_SUCCESS if success else AuthEventType.SIGNUP_FAILED,
            user_id=user_id,
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            timestamp=datetime.utcnow(),
            metadata=metadata or {},
            success=success
        )
        
        return await self.process_event(event)
    
    async def _send_alert(self, alert: SecurityAlert):
        """Send alert to all configured notifiers"""
        self.stats["alerts_generated"] += 1
        
        for notifier in self.notifiers:
            try:
                await notifier.send_alert(alert)
            except Exception as e:
                logger.error(f"Failed to send alert via {type(notifier).__name__}: {e}")
    
    async def get_security_summary(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get security summary for the last N hours
        
        Args:
            hours: Number of hours to analyze
            
        Returns:
            Security summary dictionary
        """
        since = datetime.utcnow() - timedelta(hours=hours)
        
        # Get all events in time period
        events = await self.event_store.get_events(since=since, limit=10000)
        
        # Analyze events
        login_attempts = [e for e in events if e.event_type in [AuthEventType.LOGIN_SUCCESS, AuthEventType.LOGIN_FAILED]]
        failed_logins = [e for e in events if e.event_type == AuthEventType.LOGIN_FAILED]
        signups = [e for e in events if e.event_type in [AuthEventType.SIGNUP_SUCCESS, AuthEventType.SIGNUP_FAILED]]
        
        # Get unique IPs
        unique_ips = set(event.ip_address for event in events)
        suspicious_ips = set(event.ip_address for event in failed_logins)
        
        # Top failed IPs
        ip_failure_counts = defaultdict(int)
        for event in failed_logins:
            ip_failure_counts[event.ip_address] += 1
        
        top_failed_ips = sorted(
            ip_failure_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "period_hours": hours,
            "summary": {
                "total_events": len(events),
                "login_attempts": len(login_attempts),
                "failed_logins": len(failed_logins),
                "successful_logins": len(login_attempts) - len(failed_logins),
                "signup_attempts": len(signups),
                "unique_ips": len(unique_ips),
                "suspicious_ips": len(suspicious_ips),
                "failure_rate": len(failed_logins) / max(len(login_attempts), 1)
            },
            "top_failed_ips": top_failed_ips,
            "stats": self.stats
        }
    
    async def get_ip_analysis(self, ip_address: str, hours: int = 24) -> Dict[str, Any]:
        """
        Get detailed analysis for a specific IP
        
        Args:
            ip_address: IP address to analyze
            hours: Number of hours to analyze
            
        Returns:
            IP analysis dictionary
        """
        since = datetime.utcnow() - timedelta(hours=hours)
        events = await self.event_store.get_events(ip_address=ip_address, since=since, limit=1000)
        
        if not events:
            return {"ip_address": ip_address, "status": "no_activity"}
        
        # Analyze events
        failed_logins = [e for e in events if e.event_type == AuthEventType.LOGIN_FAILED]
        successful_logins = [e for e in events if e.event_type == AuthEventType.LOGIN_SUCCESS]
        signups = [e for e in events if e.event_type in [AuthEventType.SIGNUP_SUCCESS, AuthEventType.SIGNUP_FAILED]]
        
        # Unique emails attempted
        attempted_emails = set(event.email for event in events if event.email)
        
        # User agents
        user_agents = set(event.user_agent for event in events)
        
        return {
            "ip_address": ip_address,
            "status": "active",
            "period_hours": hours,
            "analysis": {
                "total_events": len(events),
                "failed_logins": len(failed_logins),
                "successful_logins": len(successful_logins),
                "signup_attempts": len(signups),
                "unique_emails": len(attempted_emails),
                "unique_user_agents": len(user_agents),
                "first_seen": min(event.timestamp for event in events).isoformat(),
                "last_seen": max(event.timestamp for event in events).isoformat()
            },
            "samples": {
                "recent_events": [event.to_dict() for event in events[:5]],
                "attempted_emails": list(attempted_emails)[:10],
                "user_agents": list(user_agents)[:5]
            }
        }
    
    def add_notifier(self, notifier: AlertNotifier):
        """Add alert notifier"""
        self.notifiers.append(notifier)
    
    def remove_notifier(self, notifier: AlertNotifier):
        """Remove alert notifier"""
        if notifier in self.notifiers:
            self.notifiers.remove(notifier)
    
    async def shutdown(self):
        """Shutdown monitor and cleanup resources"""
        if self._background_task:
            self._shutdown_event.set()
            self._background_task.cancel()
            try:
                await self._background_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Authentication monitor shutdown complete")


class WebhookProcessor:
    """
    Webhook processor for various authentication providers
    
    Supports processing webhooks from:
    - Clerk
    - Auth0
    - Firebase Auth
    - Custom webhook formats
    """
    
    def __init__(self, auth_monitor: AuthMonitor):
        self.auth_monitor = auth_monitor
    
    async def process_clerk_webhook(self, webhook_data: Dict[str, Any]) -> List[SecurityAlert]:
        """Process Clerk webhook event"""
        event_type = webhook_data.get('type')
        data = webhook_data.get('data', {})
        
        # Extract common fields
        user_id = data.get('id')
        email_addresses = data.get('email_addresses', [])
        email = email_addresses[0].get('email_address') if email_addresses else None
        
        # These should come from request headers
        ip_address = webhook_data.get('ip_address', 'unknown')
        user_agent = webhook_data.get('user_agent', 'unknown')
        
        current_time = datetime.utcnow()
        
        # Map Clerk events to auth events
        if event_type == 'user.created':
            event = AuthEvent(
                event_type=AuthEventType.SIGNUP_SUCCESS,
                user_id=user_id,
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                timestamp=current_time,
                metadata={"webhook_type": event_type, "provider": "clerk"},
                success=True
            )
        elif event_type == 'session.created':
            event = AuthEvent(
                event_type=AuthEventType.LOGIN_SUCCESS,
                user_id=user_id,
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                timestamp=current_time,
                metadata={"webhook_type": event_type, "provider": "clerk"},
                success=True
            )
        else:
            # Unknown event type, log and return
            logger.debug(f"Unknown Clerk webhook event type: {event_type}")
            return []
        
        return await self.auth_monitor.process_event(event)
    
    async def process_auth0_webhook(self, webhook_data: Dict[str, Any]) -> List[SecurityAlert]:
        """Process Auth0 webhook event"""
        # Auth0 webhook format would be different
        # This is a placeholder for Auth0 integration
        logger.debug("Auth0 webhook processing not yet implemented")
        return []
    
    async def process_custom_webhook(self, webhook_data: Dict[str, Any]) -> List[SecurityAlert]:
        """Process custom webhook format"""
        try:
            # Expect custom format with all required fields
            event = AuthEvent.from_dict(webhook_data)
            return await self.auth_monitor.process_event(event)
        except Exception as e:
            logger.error(f"Failed to process custom webhook: {e}")
            return []


# Factory functions for easy creation
def create_auth_monitor(
    security_level: str = "balanced",
    storage_type: str = "memory",
    notifications: Optional[List[str]] = None,
    **kwargs
) -> AuthMonitor:
    """
    Create authentication monitor with predefined configurations
    
    Args:
        security_level: "permissive", "balanced", or "strict"
        storage_type: "memory" (more types can be added)
        notifications: List of notification types ["log", "webhook", "slack"]
        **kwargs: Additional configuration
        
    Returns:
        Configured AuthMonitor instance
    """
    # Configure threat detector based on security level
    if security_level == "permissive":
        threat_detector = ThreatDetector(
            brute_force_threshold=10,
            brute_force_window=600,
            credential_stuffing_threshold=5,
            signup_limit=5
        )
    elif security_level == "strict":
        threat_detector = ThreatDetector(
            brute_force_threshold=3,
            brute_force_window=180,
            credential_stuffing_threshold=2,
            signup_limit=2
        )
    else:  # balanced
        threat_detector = ThreatDetector()
    
    # Configure storage
    if storage_type == "memory":
        event_store = MemoryEventStore()
    else:
        event_store = MemoryEventStore()  # Default fallback
    
    # Configure notifications
    notifiers = []
    notification_types = notifications or ["log"]
    
    for notification_type in notification_types:
        if notification_type == "log":
            notifiers.append(LogNotifier())
        elif notification_type == "webhook" and "webhook_url" in kwargs:
            notifiers.append(WebhookNotifier(kwargs["webhook_url"]))
        elif notification_type == "slack" and "slack_webhook_url" in kwargs:
            notifiers.append(SlackNotifier(kwargs["slack_webhook_url"]))
    
    return AuthMonitor(
        event_store=event_store,
        threat_detector=threat_detector,
        notifiers=notifiers
    )