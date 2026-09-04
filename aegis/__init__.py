"""AegisAgent: Enterprise-grade defense-in-depth security middleware and deterministic policy gate for autonomous AI agents.
"""

from aegis.audit import AuditLogger
from aegis.detector import InjectionDetector
from aegis.middleware import AegisToolWrapper, aegis_guard
from aegis.policy_gate import PolicyGate
from aegis.sanitizer import ContextSanitizer
from aegis.taint import SessionContext
from aegis.types import (
    AuditEvent,
    PolicyDecision,
    PolicyVerdict,
    ScanResult,
    ToolCallProposal,
    ToolPrivilege,
    TrustLevel,
)

__version__ = "0.1.0"
__all__ = [
    "TrustLevel",
    "ToolPrivilege",
    "PolicyVerdict",
    "ScanResult",
    "ToolCallProposal",
    "PolicyDecision",
    "AuditEvent",
    "InjectionDetector",
    "ContextSanitizer",
    "SessionContext",
    "AuditLogger",
    "PolicyGate",
    "aegis_guard",
    "AegisToolWrapper",
]
