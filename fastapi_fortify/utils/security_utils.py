"""
Security utilities and data structures for FastAPI Guard
"""
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class SecurityDecision:
    """Result of a security evaluation"""
    allowed: bool
    reason: str
    rule_type: str
    confidence: float = 1.0
    metadata: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "rule_type": self.rule_type,
            "confidence": self.confidence,
            "metadata": self.metadata
        }
    
    @classmethod
    def allow(cls, reason: str, rule_type: str, **metadata) -> "SecurityDecision":
        """Create an allow decision"""
        return cls(
            allowed=True,
            reason=reason,
            rule_type=rule_type,
            metadata=metadata
        )
    
    @classmethod
    def block(cls, reason: str, rule_type: str, confidence: float = 1.0, **metadata) -> "SecurityDecision":
        """Create a block decision"""
        return cls(
            allowed=False,
            reason=reason,
            rule_type=rule_type,
            confidence=confidence,
            metadata=metadata
        )