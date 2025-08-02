"""Protection modules for FastAPI Guard"""

from fastapi_fortify.protection.waf import WAFProtection
from fastapi_fortify.protection.bot_detection import BotDetector  
from fastapi_fortify.protection.ip_blocklist import IPBlocklistManager
from fastapi_fortify.utils.security_utils import SecurityDecision

__all__ = [
    "WAFProtection",
    "BotDetector", 
    "IPBlocklistManager",
    "SecurityDecision"
]