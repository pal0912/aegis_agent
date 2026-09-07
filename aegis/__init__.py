"""AegisAgent: Enterprise-grade defense-in-depth security middleware and deterministic policy gate for autonomous AI agents.
"""

from aegis.action_graph import ActionDependencyGraph, ActionNode
from aegis.audit import AuditLogger
from aegis.behavioral_guard import BehavioralGuard
from aegis.capabilities import CapabilityRegistry
from aegis.circuit_breaker import (
    AgentCircuitBreaker,
    CircuitBreakerOpenException,
    CircuitState,
)
from aegis.consensus import DualAgentConsensusGate
from aegis.data_lineage import DataLineageTracker
from aegis.declarative_policy import (
    DeclarativePolicyEngine,
    DeclarativePolicySchema,
    GlobalPolicyConfig,
    NetworkPolicyConfig,
    RolePolicyConfig,
)
from aegis.detector import AegisDetector, InjectionDetector
from aegis.dlp import DataLossPreventionEngine
from aegis.gateway import create_gateway_app
from aegis.health import SystemHealthMonitor
from aegis.honeytoken import HoneytokenManager
from aegis.identity import AgentIdentity, AgentIdentityManager
from aegis.inter_agent import InterAgentChannelGuard, InterAgentMessage
from aegis.ledger import CryptographicLedger
from aegis.mcp_guard import MCPSecurityGuard
from aegis.memory_guard import MemoryEntry, MemoryGuard
from aegis.middleware import AegisToolWrapper, aegis_guard
from aegis.multimodal import MultimodalGuard
from aegis.network_guard import OutboundNetworkGuard
from aegis.policy_gate import PolicyGate
from aegis.risk_engine import RiskEngine
from aegis.sandbox import IsolatedCodeSandbox
from aegis.sanitizer import ContextSanitizer
from aegis.taint import SessionContext
from aegis.tracer import SecurityTracer
from aegis.types import (
    AuditEvent,
    BehavioralState,
    Capability,
    FieldProvenance,
    FieldTrustLevel,
    MitreAtlasTechnique,
    MultiTierOutcome,
    PolicyDecision,
    PolicyVerdict,
    ScanResult,
    ToolCallProposal,
    ToolPrivilege,
    TraceHop,
    TrustLevel,
)

__version__ = "2.0.0"
__all__ = [
    "TrustLevel",
    "FieldTrustLevel",
    "FieldProvenance",
    "BehavioralState",
    "ToolPrivilege",
    "Capability",
    "PolicyVerdict",
    "ScanResult",
    "ToolCallProposal",
    "PolicyDecision",
    "AuditEvent",
    "TraceHop",
    "MitreAtlasTechnique",
    "MultiTierOutcome",
    "InjectionDetector",
    "AegisDetector",
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
    "MultimodalGuard",
    "SecurityTracer",
    "IsolatedCodeSandbox",
    "DualAgentConsensusGate",
    "CryptographicLedger",
    "create_gateway_app",
    "aegis_guard",
    "AegisToolWrapper",
    "AgentIdentity",
    "AgentIdentityManager",
    "InterAgentMessage",
    "InterAgentChannelGuard",
    "CircuitState",
    "CircuitBreakerOpenException",
    "AgentCircuitBreaker",
    "RolePolicyConfig",
    "NetworkPolicyConfig",
    "GlobalPolicyConfig",
    "DeclarativePolicySchema",
    "DeclarativePolicyEngine",
    "MCPSecurityGuard",
    "SystemHealthMonitor",
    "DataLineageTracker",
    "BehavioralGuard",
]
