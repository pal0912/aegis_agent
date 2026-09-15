"""Mutation Integrity & Security Guardrail Robustness Test Suite for AegisAgent V2.

Verifies that if hypothetical source mutations disable critical security checks,
the invariant test harnesses and defense-in-depth safety layers detect the mutation
and reject unauthorized tool execution.

Mutations Tested:
1. Mutant A: Canary token bypass attempt -> Honeytoken / Gate catch
2. Mutant B: UNKNOWN capability fail-open mutant -> CapabilityRegistry & Gate catch
3. Mutant C: Unenforced ALLOW_RESTRICTED mutant -> RestrictedExecutionPolicy validator catch
4. Mutant D: Unregistered role bypass attempt -> Declarative RBAC fail-closed catch
5. Mutant E: SSRF metadata IP filter bypass attempt -> OutboundNetworkGuard catch
"""

import pytest
from unittest.mock import MagicMock

from aegis.capabilities import CapabilityRegistry
from aegis.network_guard import OutboundNetworkGuard
from aegis.policy_gate import PolicyGate
from aegis.taint import SessionContext
from aegis.types import (
    Capability,
    PolicyDecision,
    PolicyVerdict,
    RestrictedExecutionPolicy,
    ToolCallProposal,
    TrustLevel,
)


@pytest.fixture
def gate():
    """PolicyGate fixture."""
    return PolicyGate(lazy_load=True)


def test_mutation_a_canary_detection_invariant(gate):
    """Mutant A: Verify that if a canary token is present in payload, it is strictly caught and cannot be ALLOWed."""
    _, canary_str = gate.honeytoken.generate_canary("AWS_KEY")
    session = SessionContext(session_id="mutant-a", user_root_intent="Legitimate data read")
    proposal = ToolCallProposal(
        tool_name="read_public_docs",
        arguments={"path": "/public/docs", "leak": canary_str},
        source_trace_id=session.session_id,
    )
    gate.capability_registry.register_tool("read_public_docs", Capability.READ_PUBLIC)

    decision = gate.evaluate_tool_call(session, proposal)
    # The invariant: Under NO circumstance may a payload containing a canary be ALLOWed
    assert decision.verdict == PolicyVerdict.BLOCK.value
    assert decision.verdict != PolicyVerdict.ALLOW.value
    assert decision.verdict != PolicyVerdict.ALLOW_RESTRICTED.value


def test_mutation_b_unknown_capability_invariant(gate):
    """Mutant B: Verify that unclassified tools without explicit registration cannot execute."""
    session = SessionContext(session_id="mutant-b", user_root_intent="Run unclassified tool")
    proposal = ToolCallProposal(
        tool_name="totally_unregistered_alien_binary",
        arguments={"foo": "bar"},
        source_trace_id=session.session_id,
    )

    decision = gate.evaluate_tool_call(session, proposal)
    # The invariant: UNKNOWN capability must strictly fail-closed BLOCK
    assert decision.verdict == PolicyVerdict.BLOCK.value
    assert "unclassified" in decision.reason or "Capability violation" in decision.reason


def test_mutation_c_allow_restricted_missing_envelope_invariant():
    """Mutant C: Verify that ALLOW_RESTRICTED without a valid RestrictedExecutionPolicy is rejected at model boundary."""
    # Attempt to construct an ALLOW_RESTRICTED decision without restriction policy
    with pytest.raises(ValueError, match="ALLOW_RESTRICTED requires a valid restriction_policy"):
        PolicyDecision(
            verdict=PolicyVerdict.ALLOW_RESTRICTED.value,
            reason="Mutant attempting unconstrained restricted execution",
            intent_similarity_score=1.0,
            blast_radius_contained=True,
            restriction_policy=None,
        )


def test_mutation_d_unregistered_role_fail_closed_invariant(gate):
    """Mutant D: Verify that an undefined or spoofed agent role cannot bypass RBAC."""
    gate.capability_registry.register_tool("public_search", Capability.READ_PUBLIC)
    session = SessionContext(
        session_id="mutant-d",
        user_root_intent="Search public web",
        role="super_admin_spoofed_role",  # Not in declarative policy schema
    )
    proposal = ToolCallProposal(
        tool_name="public_search",
        arguments={"q": "news"},
        source_trace_id=session.session_id,
    )

    decision = gate.evaluate_tool_call(session, proposal)
    # Invariant: Undefined roles fail closed
    assert decision.verdict == PolicyVerdict.BLOCK.value
    assert "Declarative Policy Violation" in decision.reason or "ROLE_NOT_DEFINED" in decision.reason


def test_mutation_e_ssrf_metadata_ip_invariant():
    """Mutant E: Verify that cloud metadata IP addresses are unconditionally blocked by OutboundNetworkGuard."""
    net_guard = OutboundNetworkGuard()

    dangerous_urls = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://127.0.0.1:8080/internal-status",
        "http://[::1]:8080/debug",
        "http://0.0.0.0:8000/",
    ]

    for u in dangerous_urls:
        is_valid, reason = net_guard.validate_url(u)
        assert is_valid is False, f"Mutant allowed dangerous SSRF target: {u}"
        assert "blocked" in reason.lower() or "private" in reason.lower() or "ssrf" in reason.lower() or "forbidden" in reason.lower() or "loopback" in reason.lower()
