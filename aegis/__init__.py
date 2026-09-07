"""AegisAgent: Enterprise-grade defense-in-depth security middleware and deterministic policy gate for autonomous AI agents.
"""

from aegis.audit import AuditLogger
from aegis.capabilities import CapabilityRegistry
from aegis.detector import InjectionDetector
from aegis.dlp import DataLossPreventionEngine
from aegis.middleware import AegisToolWrapper, aegis_guard
from aegis.network_guard import OutboundNetworkGuard
from aegis.policy_gate import PolicyGate
from aegis.sanitizer import ContextSanitizer
from aegis.taint import SessionContext
from aegis.types import (
    AuditEvent,
    Capability,
    PolicyDecision,
    PolicyVerdict,
    ScanResult,
    ToolCallProposal,
    ToolPrivilege,
    TrustLevel,
)

__version__ = "0.2.0"
__all__ = [
    "TrustLevel",
    "ToolPrivilege",
    "Capability",
    "PolicyVerdict",
    "ScanResult",
    "ToolCallProposal",
    "PolicyDecision",
    "AuditEvent",
    "InjectionDetector",
    "ContextSanitizer",
    "SessionContext",
    "AuditLogger",
    "CapabilityRegistry",
    "OutboundNetworkGuard",
    "DataLossPreventionEngine",
    "PolicyGate",
    "aegis_guard",
    "AegisToolWrapper",
]
