"""Authentication monitoring and security event processing for FastAPI Guard"""

from fastapi_fortify.monitoring.auth_monitor import (
    AuthMonitor,
    AuthEvent,
    AuthEventType,
    SecurityAlert,
    AlertSeverity,
    create_auth_monitor,
    WebhookProcessor
)

__all__ = [
    "AuthMonitor",
    "AuthEvent", 
    "AuthEventType",
    "SecurityAlert",
    "AlertSeverity",
    "create_auth_monitor",
    "WebhookProcessor"
]