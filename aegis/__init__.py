"""AegisAgent: Enterprise-grade defense-in-depth security middleware and deterministic policy gate for autonomous AI agents.
"""

from aegis.action_graph import ActionDependencyGraph, ActionNode
from aegis.audit import AuditLogger
from aegis.capabilities import CapabilityRegistry
from aegis.detector import InjectionDetector
from aegis.dlp import DataLossPreventionEngine
from aegis.honeytoken import HoneytokenManager
from aegis.memory_guard import MemoryEntry, MemoryGuard
from aegis.middleware import AegisToolWrapper, aegis_guard
from aegis.network_guard import OutboundNetworkGuard
from aegis.policy_gate import PolicyGate
from aegis.risk_engine import RiskEngine
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
    "MemoryEntry",
    "MemoryGuard",
    "HoneytokenManager",
    "ActionNode",
    "ActionDependencyGraph",
    "RiskEngine",
    "PolicyGate",
    "aegis_guard",
    "AegisToolWrapper",
]
