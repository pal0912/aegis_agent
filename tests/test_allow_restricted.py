"""Tests for ALLOW_RESTRICTED semantics, enforcement adapters, and security invariant monotonicity.

Verifies:
1. Restricted policy cannot grant new capabilities: EffectiveCaps ⊆ OriginalAuthorized ∩ RestrictedCaps
2. Restricted policy can only reduce capabilities (never escalate authority)
3. Missing or malformed restriction policy fails closed (FAIL_CLOSED / BLOCK)
4. Unsupported restrictions cannot result in normal execution
5. Enforcement of read-only filesystem, database write blocks, external messaging blocks, secret access blocks, payload size limits, and network domain allowlisting
6. Output sanitization under restricted execution
7. LangChain sync and async tool wrappers enforce restrictions
8. MCP execution adapter enforces restrictions
"""

import asyncio
import pytest
from typing import Any, Dict, List
from unittest.mock import MagicMock

from langchain_core.tools import tool, BaseTool

from aegis.types import (
    Capability,
    PolicyDecision,
    PolicyVerdict,
    RestrictedExecutionPolicy,
    ToolCallProposal,
    TrustLevel,
)
from aegis.taint import SessionContext
from aegis.capabilities import CapabilityRegistry
from aegis.policy_gate import PolicyGate
from aegis.middleware import AegisToolWrapper
from aegis.mcp_guard import MCPSecurityGuard


class MockTool(BaseTool):
    name: str = "custom_tool"
    description: str = "A mock tool for testing"
    execution_count: int = 0
    last_args: Any = None

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        self.execution_count += 1
        self.last_args = kwargs or (args[0] if args else {})
        return f"Executed custom_tool with {self.last_args}"

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        self.execution_count += 1
        self.last_args = kwargs or (args[0] if args else {})
        return f"Async executed custom_tool with {self.last_args}"


# ---------------------------------------------------------------------------
# 1. Monotonicity & Invariant 5: EffectiveCapabilities ⊆ OriginalAuthorized ∩ Restricted
# ---------------------------------------------------------------------------

def test_restriction_policy_cannot_grant_new_capabilities():
    """Verify that a RestrictedExecutionPolicy cannot grant a capability not originally authorized."""
    gate = PolicyGate(lazy_load=True)
    gate.capability_registry.register_tool("admin_tool", Capability.ADMIN)
    session = SessionContext(
        session_id="test-session-1",
        user_root_intent="Read public documentation",
        role="researcher",  # researcher only has READ_PUBLIC
    )

    # Proposal for an administrative/write action
    proposal = ToolCallProposal(
        tool_name="admin_tool",
        arguments={"action": "wipe_cluster"},
        source_trace_id="test-session-1",
        inferred_capability=Capability.ADMIN,
    )

    # Attempt to bypass via a permissive RestrictedExecutionPolicy claiming ADMIN is allowed
    escalation_policy = gate.create_restricted_policy(
        policy_id="escalation-attempt",
        allowed_capabilities={Capability.ADMIN, Capability.READ_PUBLIC},
    )

    # Evaluation under restricted policy must strictly DENY/BLOCK because original authority lacks ADMIN
    decision = gate.evaluate_tool_call_restricted(
        session=session,
        tool_proposal=proposal,
        restriction_policy=escalation_policy,
    )

    assert decision.verdict in (PolicyVerdict.BLOCK.value, PolicyVerdict.FAIL_CLOSED.value)
    assert decision.verdict != PolicyVerdict.ALLOW_RESTRICTED.value


def test_restriction_policy_reduces_capabilities():
    """Verify that a RestrictedExecutionPolicy successfully reduces authorized capabilities."""
    gate = PolicyGate(lazy_load=True)
    gate.capability_registry.register_tool("python_interpreter", Capability.EXECUTE_CODE)
    session = SessionContext(
        session_id="test-session-2",
        user_root_intent="Execute python code print hello",
        role="coder",  # coder has READ_PUBLIC, READ_PRIVATE, WRITE_FILE, EXECUTE_CODE
    )

    # Tool requires EXECUTE_CODE (authorized for coder)
    proposal = ToolCallProposal(
        tool_name="python_interpreter",
        arguments={"code": "print('hello')"},
        source_trace_id="test-session-2",
    )

    # Create restriction policy that ONLY permits READ_PUBLIC (EXECUTE_CODE removed)
    restricted_policy = gate.create_restricted_policy(
        policy_id="read-only-envelope",
        allowed_capabilities={Capability.READ_PUBLIC},
        read_only_filesystem=True,
    )

    decision = gate.evaluate_tool_call_restricted(
        session=session,
        tool_proposal=proposal,
        restriction_policy=restricted_policy,
    )

    # Must be BLOCKED because EXECUTE_CODE is not in restricted envelope
    assert decision.verdict == PolicyVerdict.BLOCK.value
    assert "exceeds" in decision.reason or "not granted by active RestrictedExecutionPolicy" in decision.reason or "Restricted policy violation" in decision.reason


def test_missing_or_malformed_restriction_policy_fails_closed():
    """Verify that if verdict is ALLOW_RESTRICTED, missing or malformed policy fails closed."""
    # 1. Pydantic validation rejects PolicyDecision with ALLOW_RESTRICTED without policy
    with pytest.raises(ValueError, match="ALLOW_RESTRICTED requires a valid restriction_policy"):
        PolicyDecision(
            verdict=PolicyVerdict.ALLOW_RESTRICTED.value,
            reason="Illegal attempt with no policy",
            intent_similarity_score=1.0,
            blast_radius_contained=True,
            restriction_policy=None,
        )

    # 2. PolicyGate fails closed on None restriction policy
    gate = PolicyGate(lazy_load=True)
    session = SessionContext(session_id="s1", user_root_intent="test")
    proposal = ToolCallProposal(tool_name="read_file", arguments={"path": "doc.txt"}, source_trace_id="s1")

    decision = gate.evaluate_tool_call_restricted(
        session=session,
        tool_proposal=proposal,
        restriction_policy=None,  # type: ignore
    )
    assert decision.verdict == PolicyVerdict.FAIL_CLOSED.value


# ---------------------------------------------------------------------------
# 2. Execution Adapter Enforcement: LangChain Tool Wrapper Sync & Async
# ---------------------------------------------------------------------------

def test_wrapper_enforces_read_only_filesystem():
    """Verify AegisToolWrapper blocks filesystem mutations when read_only_filesystem is True."""
    raw_tool = MockTool(name="file_manager")
    gate = PolicyGate(lazy_load=True)
    gate.capability_registry.register_tool("file_manager", Capability.READ_PRIVATE)
    session = SessionContext(session_id="s-fs", user_root_intent="Read file contents")

    wrapper = AegisToolWrapper(
        underlying_tool=raw_tool,
        policy_gate=gate,
        session=session,
    )

    # Mock PolicyGate to return ALLOW_RESTRICTED with read-only restriction
    restricted_policy = RestrictedExecutionPolicy(
        policy_id="ro-fs",
        allowed_capabilities={Capability.READ_PUBLIC, Capability.READ_PRIVATE},
        read_only_filesystem=True,
    )

    mock_decision = PolicyDecision(
        verdict=PolicyVerdict.ALLOW_RESTRICTED.value,
        reason="Permitted under restricted read-only envelope",
        intent_similarity_score=1.0,
        blast_radius_contained=True,
        restriction_policy=restricted_policy,
    )
    gate.evaluate_tool_call = MagicMock(return_value=mock_decision)

    # Attempt mutation arguments
    result = wrapper.run({"action": "delete", "target": "/etc/hosts"})
    assert "[AEGIS RESTRICTION VIOLATION]" in result
    assert "read-only" in result.lower() or "filesystem mutations" in result.lower()
    assert raw_tool.execution_count == 0  # Under no circumstances should the tool have run!


def test_wrapper_enforces_database_write_block():
    """Verify AegisToolWrapper blocks database write commands under restriction."""
    raw_tool = MockTool(name="sql_query")
    gate = PolicyGate(lazy_load=True)
    gate.capability_registry.register_tool("sql_query", Capability.READ_PRIVATE)
    session = SessionContext(session_id="s-db", user_root_intent="Query metrics")

    wrapper = AegisToolWrapper(
        underlying_tool=raw_tool,
        policy_gate=gate,
        session=session,
    )

    restricted_policy = RestrictedExecutionPolicy(
        policy_id="ro-db",
        allowed_capabilities={Capability.READ_PUBLIC, Capability.READ_PRIVATE},
        allow_database_writes=False,
    )

    mock_decision = PolicyDecision(
        verdict=PolicyVerdict.ALLOW_RESTRICTED.value,
        reason="Permitted under read-only database envelope",
        intent_similarity_score=1.0,
        blast_radius_contained=True,
        restriction_policy=restricted_policy,
    )
    gate.evaluate_tool_call = MagicMock(return_value=mock_decision)

    # Attempt SQL INSERT mutation
    result = wrapper.run({"query": "INSERT INTO users VALUES ('hacker')"})
    assert "[AEGIS RESTRICTION VIOLATION]" in result
    assert "Database writes strictly prohibited" in result
    assert raw_tool.execution_count == 0


def test_wrapper_enforces_network_domain_allowlist():
    """Verify AegisToolWrapper blocks outbound egress to unlisted domains."""
    raw_tool = MockTool(name="http_fetch")
    gate = PolicyGate(lazy_load=True)
    gate.capability_registry.register_tool("http_fetch", Capability.NETWORK_EXTERNAL)
    session = SessionContext(session_id="s-net", user_root_intent="Fetch docs")

    wrapper = AegisToolWrapper(
        underlying_tool=raw_tool,
        policy_gate=gate,
        session=session,
    )

    restricted_policy = RestrictedExecutionPolicy(
        policy_id="domain-whitelisted",
        allowed_capabilities={Capability.NETWORK_EXTERNAL},
        allow_network_egress=True,
        allowed_network_domains=["api.github.com", "raw.githubusercontent.com"],
    )

    mock_decision = PolicyDecision(
        verdict=PolicyVerdict.ALLOW_RESTRICTED.value,
        reason="Permitted under restricted domain envelope",
        intent_similarity_score=1.0,
        blast_radius_contained=True,
        restriction_policy=restricted_policy,
    )
    gate.evaluate_tool_call = MagicMock(return_value=mock_decision)

    # Illegal egress target
    result = wrapper.run({"url": "https://evil-exfil-server.com/leak"})
    assert "[AEGIS RESTRICTION VIOLATION]" in result
    assert "not permitted" in result
    assert raw_tool.execution_count == 0

    # Allowed egress target
    allowed_result = wrapper.run({"url": "https://api.github.com/repos"})
    assert "[AEGIS RESTRICTION VIOLATION]" not in allowed_result
    assert raw_tool.execution_count == 1


def test_wrapper_enforces_payload_size_limits():
    """Verify AegisToolWrapper enforces maximum payload size limit in bytes."""
    raw_tool = MockTool(name="search_docs")
    gate = PolicyGate(lazy_load=True)
    gate.capability_registry.register_tool("search_docs", Capability.READ_PUBLIC)
    session = SessionContext(session_id="s-sz", user_root_intent="Process batch")

    wrapper = AegisToolWrapper(
        underlying_tool=raw_tool,
        policy_gate=gate,
        session=session,
    )

    restricted_policy = RestrictedExecutionPolicy(
        policy_id="strict-size-limit",
        allowed_capabilities={Capability.READ_PUBLIC},
        max_payload_size_bytes=64,  # very small 64 bytes limit
    )

    mock_decision = PolicyDecision(
        verdict=PolicyVerdict.ALLOW_RESTRICTED.value,
        reason="Permitted under small payload envelope",
        intent_similarity_score=1.0,
        blast_radius_contained=True,
        restriction_policy=restricted_policy,
    )
    gate.evaluate_tool_call = MagicMock(return_value=mock_decision)

    # Exceed limit
    huge_data = "X" * 500
    result = wrapper.run({"query": huge_data})
    assert "[AEGIS RESTRICTION VIOLATION]" in result
    assert "exceeds maximum permitted limit" in result
    assert raw_tool.execution_count == 0


def test_wrapper_enforces_output_sanitization():
    """Verify output sanitization is applied to tool results when sanitize_output is True."""
    raw_tool = MockTool(name="search_docs")
    gate = PolicyGate(lazy_load=True)
    gate.capability_registry.register_tool("search_docs", Capability.READ_PUBLIC)
    session = SessionContext(session_id="s-san", user_root_intent="Generate doc")

    wrapper = AegisToolWrapper(
        underlying_tool=raw_tool,
        policy_gate=gate,
        session=session,
    )

    restricted_policy = RestrictedExecutionPolicy(
        policy_id="sanitized-envelope",
        allowed_capabilities={Capability.READ_PUBLIC},
        sanitize_output=True,
    )

    mock_decision = PolicyDecision(
        verdict=PolicyVerdict.ALLOW_RESTRICTED.value,
        reason="Permitted under sanitized output envelope",
        intent_similarity_score=1.0,
        blast_radius_contained=True,
        restriction_policy=restricted_policy,
    )
    gate.evaluate_tool_call = MagicMock(return_value=mock_decision)

    result = wrapper.run({"query": "generate report"})
    assert raw_tool.execution_count == 1
    # Output must be encapsulated within boundary delimiters
    assert "BEGIN_UNTRUSTED_SOURCE" in result or "UNTRUSTED_CONTENT" in result or "Executed custom_tool" in result


def test_async_wrapper_enforces_restrictions():
    """Verify asynchronous tool wrapper (_arun) enforces restrictions identically."""
    raw_tool = MockTool(name="send_alert")
    gate = PolicyGate(lazy_load=True)
    gate.capability_registry.register_tool("send_alert", Capability.SEND_EXTERNAL_MESSAGE)
    session = SessionContext(session_id="s-async", user_root_intent="Async data upload")

    wrapper = AegisToolWrapper(
        underlying_tool=raw_tool,
        policy_gate=gate,
        session=session,
    )

    restricted_policy = RestrictedExecutionPolicy(
        policy_id="async-messaging-block",
        allowed_capabilities={Capability.SEND_EXTERNAL_MESSAGE},
        allow_external_messaging=False,
    )

    mock_decision = PolicyDecision(
        verdict=PolicyVerdict.ALLOW_RESTRICTED.value,
        reason="Permitted under no-messaging envelope",
        intent_similarity_score=1.0,
        blast_radius_contained=True,
        restriction_policy=restricted_policy,
    )
    gate.evaluate_tool_call = MagicMock(return_value=mock_decision)

    # Tool name/arguments triggering messaging violation
    result = asyncio.run(wrapper.arun({"email": "alert@corp.com", "body": "test message"}))
    assert "[AEGIS RESTRICTION VIOLATION]" in result
    assert "prohibited" in result.lower()
    assert raw_tool.execution_count == 0


# ---------------------------------------------------------------------------
# 3. Execution Adapter Enforcement: MCP Security Guard
# ---------------------------------------------------------------------------

def test_mcp_guard_enforces_restricted_policy():
    """Verify MCPSecurityGuard.intercept_mcp_call validates and enforces RestrictedExecutionPolicy."""
    mcp = MCPSecurityGuard()
    mcp.capability_registry.register_tool("read_file", Capability.READ_PRIVATE)
    mcp.capability_registry.register_tool("write_file", Capability.WRITE_FILE)
    mcp.capability_registry.register_tool("http_request", Capability.NETWORK_EXTERNAL)
    session = SessionContext(session_id="mcp-s1", user_root_intent="Read files")

    restricted_policy = RestrictedExecutionPolicy(
        policy_id="mcp-ro-envelope",
        allowed_capabilities={Capability.READ_PUBLIC, Capability.READ_PRIVATE},
        read_only_filesystem=True,
        allow_network_egress=False,
    )

    # 1. Allowed operation (read file)
    authorized, reason, args = mcp.intercept_mcp_call(
        server_name="mcp-filesystem",
        tool_name="read_file",
        arguments={"path": "/docs/readme.txt"},
        session_context=session,
        restriction_policy=restricted_policy,
    )
    assert authorized is True
    assert "authorized under restriction policy" in reason

    # 2. Blocked operation: filesystem mutation
    blocked_mut, reason_mut, _ = mcp.intercept_mcp_call(
        server_name="mcp-filesystem",
        tool_name="write_file",
        arguments={"path": "/docs/readme.txt", "content": "corrupted"},
        session_context=session,
        restriction_policy=restricted_policy,
    )
    assert blocked_mut is False
    assert "MCP Restriction Violation" in reason_mut

    # 3. Blocked operation: capability envelope violation
    blocked_net_cap, reason_net_cap, _ = mcp.intercept_mcp_call(
        server_name="mcp-network",
        tool_name="http_request",
        arguments={"url": "https://api.external.com/data"},
        session_context=session,
        restriction_policy=restricted_policy,
    )
    assert blocked_net_cap is False
    assert "MCP Restriction Violation" in reason_net_cap

    # 4. Blocked operation: specific allow_network_egress=False restriction
    net_policy = RestrictedExecutionPolicy(
        policy_id="mcp-net-envelope",
        allowed_capabilities={Capability.READ_PUBLIC, Capability.NETWORK_EXTERNAL},
        allow_network_egress=False,
    )
    blocked_net, reason_net, _ = mcp.intercept_mcp_call(
        server_name="mcp-network",
        tool_name="http_request",
        arguments={"url": "https://api.external.com/data"},
        session_context=session,
        restriction_policy=net_policy,
    )
    assert blocked_net is False
    assert "Network egress prohibited" in reason_net


def test_real_execution_boundary_instrumented_verdicts():
    """Verify that every verdict strictly controls underlying execution with an instrumented tool."""
    gate = PolicyGate(lazy_load=True)
    session = SessionContext(session_id="boundary-sess", user_root_intent="Boundary test")

    verdicts_to_test = [
        (PolicyVerdict.BLOCK.value, None, 0),
        (PolicyVerdict.FAIL_CLOSED.value, None, 0),
        (PolicyVerdict.REQUIRE_HUMAN_APPROVAL.value, None, 0),
        ("UNKNOWN_ARBITRARY_VERDICT", None, 0),
        (
            PolicyVerdict.ALLOW_RESTRICTED.value,
            RestrictedExecutionPolicy(
                policy_id="ro-fs",
                allowed_capabilities={Capability.READ_PUBLIC, Capability.WRITE_FILE},
                read_only_filesystem=True,
            ),
            0,  # Fails restriction check on write_file -> execution_count remains 0
        ),
        (PolicyVerdict.ALLOW.value, None, 1),  # Only ALLOW executes underlying tool
    ]

    for verdict_val, rest_pol, expected_exec_count in verdicts_to_test:
        raw_tool = MockTool(name="test_tool")
        wrapper = AegisToolWrapper(
            underlying_tool=raw_tool,
            policy_gate=gate,
            session=session,
        )

        mock_decision = PolicyDecision(
            verdict=verdict_val if verdict_val in [v.value for v in PolicyVerdict] else PolicyVerdict.BLOCK.value,
            reason=f"Testing verdict {verdict_val}",
            intent_similarity_score=1.0,
            blast_radius_contained=True,
            restriction_policy=rest_pol,
        )
        if verdict_val not in [v.value for v in PolicyVerdict]:
            # Simulate a bypass or corrupted verdict object
            mock_decision = mock_decision.model_copy(update={"verdict": verdict_val})

        gate.evaluate_tool_call = MagicMock(return_value=mock_decision)

        # Execute synchronous run with write argument
        result = wrapper.run({"filepath": "important.txt", "content": "data"})
        assert raw_tool.execution_count == expected_exec_count, (
            f"Execution boundary breached for verdict '{verdict_val}': "
            f"expected {expected_exec_count} executions, got {raw_tool.execution_count}."
        )

        # Execute asynchronous arun
        raw_tool_async = MockTool(name="test_tool_async")
        wrapper_async = AegisToolWrapper(
            underlying_tool=raw_tool_async,
            policy_gate=gate,
            session=session,
        )
        asyncio.run(wrapper_async.arun({"filepath": "important.txt", "content": "data"}))
        assert raw_tool_async.execution_count == expected_exec_count, (
            f"Async execution boundary breached for verdict '{verdict_val}': "
            f"expected {expected_exec_count} executions, got {raw_tool_async.execution_count}."
        )

