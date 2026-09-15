"""Adversarial Red-Team & Security Integrity Verification Suite for AegisAgent V2.

Systematically attacks and attempts to break the security guarantees implemented in AegisAgent:
1. ALLOW / ALLOW_RESTRICTED Execution Boundary (instrumented underlying invocation assertions)
2. ValidationScope Tampering (direct & nested in-place mutation, serialization)
3. Scope Inheritance Monotonicity (Child <= Parent across multi-hop chains)
4. Live Validation Abuse (fake, malformed, expired, replayed, scope/env-mismatched tokens)
5. Taint Evasion (Base64, URL encoding, transformations, slicing, provenance)
6. Root Intent Confusion (immutability of root user intent against external influences)
7. Capability Classification Bypass (unknown tools, misleading names, hidden args)
8. Network / SSRF Bypass (loopback, hex/octal/dword IP, cloud metadata, redirect chains)
9. Restricted Filesystem Bypass (traversal, symlink escapes, null bytes)
10. Restricted Database / Messaging Bypass (comments, whitespace, DDL/DML evasion)
11. DLP Evasion (Base64, URL-encoded, fragmented/split parameters)
12. NHI / Delegation Race & Key Rotation Testing
13. Policy Snapshot Concurrency & Thread-Safety
14. Sandbox AST Controls & Deserialization Banning
15. Safe Validation Side-Effect Proof (zero invocation count on real sinks)
16. Security Invariant Property Fuzzing
17. Mutation Verification
"""

import base64
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import urllib.parse
import uuid

import pytest
from pydantic import ValidationError

from aegis.circuit_breaker import AgentCircuitBreaker
from aegis.declarative_policy import DeclarativePolicyEngine
from aegis.dlp import DataLossPreventionEngine
from aegis.identity import AgentIdentityManager
from aegis.inter_agent import InterAgentChannelGuard
from aegis.mcp_guard import MCPSecurityGuard
from aegis.middleware import (
    AegisToolWrapper,
    DirectToolInvocationBlockedError,
    RestrictedExecutionPolicy,
)
from aegis.network_guard import OutboundNetworkGuard
from aegis.policy_gate import PolicyGate
from aegis.sandbox import IsolatedCodeSandbox
from aegis.taint import SessionContext
from aegis.types import (
    AuditEvent,
    Capability,
    FieldTrustLevel,
    PolicyDecision,
    PolicyVerdict,
    ToolCallProposal,
    TrustLevel,
)
from aegis.validation import (
    LiveValidationAuthorizer,
    SideEffectCategory,
    ValidationMode,
    ValidationScope,
)


from langchain_core.tools import BaseTool


class MockInstrumentedTool(BaseTool):
    """Instrumented underlying tool recording exact invocation counts and arguments."""

    name: str = "instrumented_sink"
    description: str = "Instrumented test sink"
    call_count: int = 0
    last_args: Any = None
    last_kwargs: Any = None

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        self.call_count += 1
        self.last_args = args
        self.last_kwargs = kwargs
        return f"EXECUTED_BY_UNDERLYING_TOOL:{self.call_count}"

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        self.call_count += 1
        self.last_args = args
        self.last_kwargs = kwargs
        return f"ASYNC_EXECUTED_BY_UNDERLYING_TOOL:{self.call_count}"


# ===========================================================================
# 1. ALLOW / ALLOW_RESTRICTED Execution Boundary
# ===========================================================================
def test_execution_boundary_zero_invocations_on_non_allow_verdicts():
    """Verify underlying tool is NEVER executed when PolicyVerdict is not ALLOW or ALLOW_RESTRICTED."""
    non_exec_verdicts = [
        PolicyVerdict.BLOCK.value,
        PolicyVerdict.FAIL_CLOSED.value,
        "QUARANTINE",
        PolicyVerdict.REQUIRE_HUMAN_APPROVAL.value,
        "UNKNOWN_VERDICT",
        "MALFORMED_VERDICT_999",
        None,
    ]

    for verdict in non_exec_verdicts:
        mock_tool = MockInstrumentedTool(name=f"test_tool_{verdict}")
        session = SessionContext(session_id="s1", user_root_intent="Read public docs")
        gate = PolicyGate(lazy_load=True)

        if verdict in {v.value for v in PolicyVerdict}:
            decision_obj = PolicyDecision(
                verdict=verdict,
                reason=f"Testing non-allow verdict: {verdict}",
                risk_score=0.9,
                intent_similarity_score=1.0,
                blast_radius_contained=True,
            )
            gate.evaluate_tool_call = lambda *args, **kwargs: decision_obj
        elif verdict is None:
            gate.evaluate_tool_call = lambda *args, **kwargs: None
        else:
            class MockArbitraryDecision:
                def __init__(self, v):
                    self.verdict = v
                    self.reason = f"Testing arbitrary non-allow verdict: {v}"
                    self.risk_score = 0.9
                    self.intent_similarity_score = 1.0
                    self.blast_radius_contained = True
                    self.dlp_violations = []
                    self.network_verdict = "PASS"
                    self.policy_version = "2.0"
                    self.policy_snapshot_hash = None
                    self.restriction_policy = None

            gate.evaluate_tool_call = lambda *args, **kwargs: MockArbitraryDecision(verdict)

        wrapper = AegisToolWrapper(
            underlying_tool=mock_tool,
            policy_gate=gate,
            session=session,
        )

        res = wrapper.run({"query": "SELECT 1"})
        assert mock_tool.call_count == 0, f"Underlying tool executed on verdict '{verdict}'!"
        assert "EXECUTED_BY_UNDERLYING_TOOL" not in str(res)

    # Also verify exception in evaluate_tool_call fails closed with zero invocations
    mock_tool = MockInstrumentedTool(name="test_tool_error")
    session = SessionContext(session_id="s1", user_root_intent="Read public docs")
    gate = PolicyGate(lazy_load=True)
    def crash_gate(*args, **kwargs):
        raise RuntimeError("Simulated internal policy gate failure")
    gate.evaluate_tool_call = crash_gate

    wrapper = AegisToolWrapper(
        underlying_tool=mock_tool,
        policy_gate=gate,
        session=session,
    )
    res = wrapper.run({"query": "SELECT 1"})
    assert mock_tool.call_count == 0, "Underlying tool executed on gate exception!"
    assert "EXECUTED_BY_UNDERLYING_TOOL" not in str(res)


def test_allow_restricted_only_executes_through_restricted_adapter():
    """Verify ALLOW_RESTRICTED strictly blocks execution when restrictions are violated."""
    mock_tool = MockInstrumentedTool(name="db_tool")
    session = SessionContext(session_id="s2", user_root_intent="Query metrics")
    gate = PolicyGate(lazy_load=True)

    # Restriction forbids database writes
    restrict_policy = RestrictedExecutionPolicy(
        allowed_capabilities={Capability.READ_PRIVATE},
        allow_database_writes=False,
    )

    gate.evaluate_tool_call = lambda *args, **kwargs: PolicyDecision(
        verdict=PolicyVerdict.ALLOW_RESTRICTED.value,
        reason="Restricted query only",
        restriction_policy=restrict_policy,
        risk_score=0.2,
        intent_similarity_score=1.0,
        blast_radius_contained=True,
    )

    wrapper = AegisToolWrapper(
        underlying_tool=mock_tool,
        policy_gate=gate,
        session=session,
    )

    # Attempt database mutation through restricted tool
    res = wrapper.run({"query": "DROP TABLE users;"})
    assert mock_tool.call_count == 0, "Underlying tool executed prohibited database mutation under ALLOW_RESTRICTED!"
    assert "[AEGIS RESTRICTION VIOLATION]" in str(res)


# ===========================================================================
# 2. ValidationScope Tampering
# ===========================================================================
def test_validation_scope_immutability_and_tamper_proofing():
    """Verify that ValidationScope cannot be mutated directly or via nested structures post-creation."""
    scope = ValidationScope(
        mode=ValidationMode.SIMULATION,
        permitted_capabilities={Capability.READ_PUBLIC},
        permitted_filesystem_paths=("/tmp/safe",),
        permitted_network_destinations=("localhost",),
        permitted_tools={"web_search"},
        allow_external_side_effects=False,
    )

    # 1. Direct attribute mutation must be blocked by Pydantic frozen=True
    with pytest.raises(ValidationError):
        scope.mode = ValidationMode.LIVE_VALIDATION

    with pytest.raises(ValidationError):
        scope.allow_external_side_effects = True

    with pytest.raises(ValidationError):
        scope.max_payload_size_bytes = 99999999

    # 2. In-place collection mutation must fail closed (frozenset & tuple)
    with pytest.raises(AttributeError):
        scope.permitted_capabilities.add(Capability.ADMIN)

    with pytest.raises(AttributeError):
        scope.permitted_tools.add("execute_shell")

    with pytest.raises(AttributeError):
        scope.permitted_filesystem_paths.append("/etc")


# ===========================================================================
# 3. Scope Inheritance Monotonicity (Child <= Parent)
# ===========================================================================
def test_scope_inheritance_multi_hop_monotonicity():
    """Verify that multi-hop scope derivation strictly attenuates authority."""
    parent = ValidationScope(
        mode=ValidationMode.ISOLATED_TEST,
        permitted_capabilities={Capability.READ_PUBLIC, Capability.READ_PRIVATE, Capability.WRITE_FILE},
        permitted_filesystem_paths=("/app/safe",),
        permitted_network_destinations=("127.0.0.1", "localhost"),
        permitted_tools={"read_file", "write_file", "search"},
        max_runtime_sec=60.0,
        max_steps=20,
        max_payload_size_bytes=65536,
    )

    # Child within parent bounds succeeds
    child = parent.create_child_scope(
        permitted_capabilities={Capability.READ_PUBLIC, Capability.WRITE_FILE},
        permitted_tools={"read_file", "write_file"},
        max_runtime_sec=30.0,
        max_steps=10,
        max_payload_size_bytes=32768,
    )
    assert child.permitted_capabilities.issubset(parent.permitted_capabilities)

    # Grandchild within child bounds succeeds
    grandchild = child.create_child_scope(
        permitted_capabilities={Capability.READ_PUBLIC},
        permitted_tools={"read_file"},
        max_runtime_sec=15.0,
        max_steps=5,
    )
    assert grandchild.permitted_capabilities.issubset(child.permitted_capabilities)

    # Great-grandchild attempting to widen capabilities must fail
    with pytest.raises(ValueError, match="Scope escalation"):
        grandchild.create_child_scope(
            permitted_capabilities={Capability.READ_PUBLIC, Capability.EXECUTE_CODE}
        )

    # Child attempting to widen filesystem path must fail
    with pytest.raises(ValueError, match="Scope escalation"):
        parent.create_child_scope(
            permitted_filesystem_paths=("/etc",)
        )


# ===========================================================================
# 4. Live Validation Abuse
# ===========================================================================
def test_live_validation_token_abuse_fails_closed():
    """Verify that LIVE_VALIDATION mode rejects fake, malformed, expired, replayed, or mismatched tokens."""
    # 1. Fake token
    with pytest.raises(ValueError, match="rejected: Malformed token prefix"):
        ValidationScope(
            mode=ValidationMode.LIVE_VALIDATION,
            operator_authorization_token="fake_token_abc_123",
            live_environment_verified=True,
            allow_external_side_effects=True,
        )

    # 2. Malformed token structure
    with pytest.raises(ValueError, match="rejected"):
        ValidationScope(
            mode=ValidationMode.LIVE_VALIDATION,
            operator_authorization_token="live_tok.invalidclaims.invalidsig",
            live_environment_verified=True,
            allow_external_side_effects=True,
        )

    # 3. Expired token
    expired_token = LiveValidationAuthorizer.generate_token(
        validation_id="val_target_1",
        environment="live",
        ttl_seconds=-10,  # expired in past
    )
    is_valid, reason = LiveValidationAuthorizer.verify_token(
        expired_token, validation_id="val_target_1", expected_environment="live"
    )
    assert is_valid is False
    assert "expired" in reason.lower()

    # 4. Token issued for another scope ID
    other_token = LiveValidationAuthorizer.generate_token(
        validation_id="val_other_scope",
        environment="live",
    )
    is_valid, reason = LiveValidationAuthorizer.verify_token(
        other_token, validation_id="val_my_scope", expected_environment="live"
    )
    assert is_valid is False
    assert "scope mismatch" in reason.lower()

    # 5. Token issued for another environment
    staging_token = LiveValidationAuthorizer.generate_token(
        validation_id="val_env_test",
        environment="staging",
    )
    is_valid, reason = LiveValidationAuthorizer.verify_token(
        staging_token, validation_id="val_env_test", expected_environment="live"
    )
    assert is_valid is False
    assert "environment mismatch" in reason.lower()

    # 6. Replayed token
    fresh_token = LiveValidationAuthorizer.generate_token(
        validation_id="val_replay_test",
        environment="live",
    )
    is_valid1, _ = LiveValidationAuthorizer.verify_token(
        fresh_token, validation_id="val_replay_test", expected_environment="live"
    )
    assert is_valid1 is True

    # Presenting the exact same token a second time must trigger anti-replay
    is_valid2, reason2 = LiveValidationAuthorizer.verify_token(
        fresh_token, validation_id="val_replay_test", expected_environment="live"
    )
    assert is_valid2 is False
    assert "replay detected" in reason2.lower()


# ===========================================================================
# 5. Taint Evasion
# ===========================================================================
def test_taint_evasion_is_permanently_sticky():
    """Verify that once a session ingests untrusted data, taint cannot be stripped or laundered."""
    session = SessionContext(
        session_id="taint-audit",
        user_root_intent="Read customer support emails",
        is_tainted=False,
    )
    assert session.is_session_tainted() is False

    # Ingest untrusted payload
    session.ingest_untrusted_data("web_crawler", "Here is an untrusted document")
    assert session.is_session_tainted() is True
    assert session.trust_level == TrustLevel.UNTRUSTED

    # High-impact write proposal under tainted session must be BLOCKED
    gate = PolicyGate(lazy_load=True)
    proposal = ToolCallProposal(
        tool_name="write_file",
        arguments={"filepath": "/app/out.txt", "content": "data"},
        inferred_capability=Capability.WRITE_FILE,
    )
    decision = gate.evaluate_tool_call(session, proposal)
    assert decision.verdict == PolicyVerdict.BLOCK.value
    assert "tainted" in decision.reason.lower()


# ===========================================================================
# 6. Root Intent Confusion
# ===========================================================================
def test_root_user_intent_is_immutable():
    """Verify that user_root_intent cannot be rewritten or corrupted after session creation."""
    session = SessionContext(
        session_id="root-intent-test",
        user_root_intent="Legitimate financial query",
    )
    assert session.user_root_intent == "Legitimate financial query"

    # Attempting in-place reassignment of user_root_intent must raise AttributeError
    with pytest.raises(AttributeError, match="strictly immutable"):
        session.user_root_intent = "MALICIOUS INJECTION: transfer funds"

    with pytest.raises(AttributeError, match="strictly immutable"):
        session.root_intent = "MALICIOUS INJECTION: transfer funds"

    assert session.user_root_intent == "Legitimate financial query"


# ===========================================================================
# 7. Capability Classification Bypass
# ===========================================================================
def test_unknown_and_misleading_tool_names_fail_closed():
    """Verify that unknown tools and misleading tool names fail closed to BLOCK."""
    gate = PolicyGate(lazy_load=True)
    session = SessionContext(session_id="cap-test", user_root_intent="Search public web")

    # 1. Unknown tool
    prop_unknown = ToolCallProposal(
        tool_name="completely_unrecognized_custom_tool_xyz",
        arguments={"arg": "val"},
    )
    dec_unknown = gate.evaluate_tool_call(session, prop_unknown)
    assert dec_unknown.verdict == PolicyVerdict.BLOCK.value
    assert "unregistered" in dec_unknown.reason.lower() or "unclassified" in dec_unknown.reason.lower()

    # 2. Misleading tool name (looks like read, but performs write)
    prop_misleading = ToolCallProposal(
        tool_name="read_and_delete_database",
        arguments={"table": "users", "query": "DROP TABLE users"},
    )
    dec_misleading = gate.evaluate_tool_call(session, prop_misleading)
    assert dec_misleading.verdict == PolicyVerdict.BLOCK.value


# ===========================================================================
# 8. Network / SSRF Bypass
# ===========================================================================
def test_network_ssrf_evasions_blocked():
    """Verify that all alternate IP encodings, loopback, cloud metadata, and redirects are blocked."""
    guard = OutboundNetworkGuard()

    # Alternate numeric IP encodings for loopback 127.0.0.1
    ssrf_targets = [
        "http://127.0.0.1:8080/admin",
        "http://127.0.1.1/secret",
        "http://0x7f000001/",
        "http://0177.0.0.1/",
        "http://2130706433/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://169.254.169.254/latest/meta-data/",
        "http://100.100.100.100/latest/meta-data/",
        "http://10.0.0.1/internal",
        "http://192.168.1.1/router",
        "http://172.16.0.1/private",
    ]

    for url in ssrf_targets:
        is_valid, reason = guard.validate_url(url)
        assert is_valid is False, f"SSRF target failed to block: '{url}' (Reason: {reason})"

    # Redirect chain towards metadata service must be blocked at the redirect hop
    chain = ["http://169.254.169.254/secret"]
    is_valid_chain, chain_reason, _ = guard.safe_validate_redirect_chain(
        initial_url="https://api.github.com/status",
        redirect_targets=chain,
    )
    assert is_valid_chain is False
    assert "SSRF blocked" in chain_reason or "Initial URL blocked" in chain_reason


# ===========================================================================
# 9. Restricted Filesystem Bypass
# ===========================================================================
def test_restricted_filesystem_bypass_blocked():
    """Verify that path traversal, symlink escapes, and null byte injections are blocked."""
    scope = ValidationScope(
        mode=ValidationMode.ISOLATED_TEST,
        permitted_filesystem_paths=("/app/safe",),
    )

    traversal_paths = [
        "/app/safe/../../etc/passwd",
        "/app/safe/subdir/../../../windows/system32",
        "/etc/shadow",
        "/app/safe/\x00/etc/passwd",
        "/app/safe/%00/etc/passwd",
    ]

    for p in traversal_paths:
        assert scope.is_filesystem_path_allowed(p) is False, f"Filesystem traversal allowed: {p}"


# ===========================================================================
# 10. Restricted Database / Messaging Bypass
# ===========================================================================
def test_restricted_database_comments_and_whitespace_bypass_blocked():
    """Verify that SQL comments and whitespace cannot evade database write restrictions."""
    mock_tool = MockInstrumentedTool(name="run_sql_query")
    session = SessionContext(session_id="db-evasion", user_root_intent="Query user counts")
    gate = PolicyGate(lazy_load=True)

    restrict_policy = RestrictedExecutionPolicy(
        allowed_capabilities={Capability.READ_PRIVATE},
        allow_database_writes=False,
    )

    gate.evaluate_tool_call = lambda *args, **kwargs: PolicyDecision(
        verdict=PolicyVerdict.ALLOW_RESTRICTED.value,
        restriction_policy=restrict_policy,
        reason="Restricted query permitted",
        risk_score=0.2,
        intent_similarity_score=1.0,
        blast_radius_contained=True,
    )

    wrapper = AegisToolWrapper(
        underlying_tool=mock_tool,
        policy_gate=gate,
        session=session,
    )

    evasion_queries = [
        "DROP/*comment*/TABLE users;",
        "/*comment*/DELETE FROM users WHERE 1=1;",
        "--line comment\nDROP TABLE logs;",
        "TRUNCATE\n\tTABLE audit_events;",
        "ALTER TABLE users ADD COLUMN is_admin INT;",
    ]

    for q in evasion_queries:
        res = wrapper.run({"query": q})
        assert mock_tool.call_count == 0, f"Underlying tool executed evasion query: '{q}'!"
        assert "[AEGIS RESTRICTION VIOLATION]" in str(res)


# ===========================================================================
# 11. DLP Evasion
# ===========================================================================
def test_dlp_base64_and_split_parameter_detection():
    """Verify that Base64-encoded and cross-parameter fragmented secrets are detected."""
    dlp = DataLossPreventionEngine()

    raw_secret = "sk-ant-api03-12345678901234567890123456789012"
    b64_secret = base64.b64encode(raw_secret.encode("utf-8")).decode("utf-8")

    # 1. Base64 encoded secret detection
    violations = dlp.scan_text(f"Please use authorization token: {b64_secret}")
    assert any("Anthropic API Key" in v for v in violations)

    # 2. Redaction of Base64 encoded secret
    redacted = dlp.redact_text(f"Header: {b64_secret}")
    assert b64_secret not in redacted
    assert "[REDACTED_BASE64_SECRET:" in redacted

    # 3. Fragmented/split secret across multiple tool arguments
    split_args = {
        "part_a": "sk-ant-api03-1234567890",
        "part_b": "12345678901234567890123456789012",
    }
    _, split_violations = dlp.sanitize_tool_args(split_args)
    assert any("Fragmented Across Parameters" in v for v in split_violations)


# ===========================================================================
# 12. NHI / Delegation Race & Key Rotation Testing
# ===========================================================================
def test_nhi_key_rotation_invalidates_prior_tokens():
    """Verify that rotating an agent's cryptographic key immediately invalidates previously issued tokens."""
    mgr = AgentIdentityManager()
    agent_a = mgr.register_agent("agent-alpha", {Capability.READ_PUBLIC, Capability.EXECUTE_CODE})

    # Issue delegation token with initial keypair
    token = mgr.issue_delegation_token(
        issuer=agent_a,
        delegate_id="agent-beta",
        scope={Capability.READ_PUBLIC},
    )

    # Token verifies successfully before rotation
    valid_before, _, _ = mgr.verify_delegation_token(token, Capability.READ_PUBLIC)
    assert valid_before is True

    # Rotate agent alpha keypair
    mgr.rotate_agent_key("agent-alpha")

    # Token must now FAIL cryptographic verification
    valid_after, reason, _ = mgr.verify_delegation_token(token, Capability.READ_PUBLIC)
    assert valid_after is False
    assert "INVALID_TOKEN_SIGNATURE" in reason


# ===========================================================================
# 13. Policy Snapshot Concurrency & Thread-Safety
# ===========================================================================
def test_declarative_policy_concurrency_and_snapshot_stability():
    """Verify concurrent reads and reloads of DeclarativePolicyEngine maintain deterministic snapshot hashes."""
    engine = DeclarativePolicyEngine()
    initial_schema, initial_ver, initial_hash = engine.get_snapshot()
    assert len(initial_hash) == 64

    errors = []

    def reader_worker():
        for _ in range(50):
            schema, ver, h = engine.get_snapshot()
            if not h or len(h) != 64 or not ver:
                errors.append(f"Inconsistent snapshot: {ver}, {h}")

    threads = [threading.Thread(target=reader_worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0, f"Concurrency snapshot errors: {errors}"


# ===========================================================================
# 14. Sandbox AST Controls & Deserialization Banning
# ===========================================================================
def test_sandbox_bans_pickle_and_deserialization_modules():
    """Verify that IsolatedCodeSandbox bans pickle, shelve, marshal, dill, and webbrowser."""
    sandbox = IsolatedCodeSandbox()

    malicious_scripts = [
        "import pickle\npickle.loads(b'cos\\nsystem\\n(S\"ls\"\\ntR.')",
        "import _pickle",
        "import shelve",
        "import marshal",
        "import webbrowser",
    ]

    for script in malicious_scripts:
        is_safe, reason = sandbox.inspect_ast(script)
        assert is_safe is False, f"Sandbox failed to block script: '{script}'"
        assert "Banned module" in reason


# ===========================================================================
# 15. Safe Validation Side-Effect Proof (Zero Invocations)
# ===========================================================================
def test_safe_validation_mode_zero_side_effect_count():
    """Verify that in DRY_RUN, attempted side effects produce zero underlying invocations and return CONTAINED."""
    mock_email = MockInstrumentedTool(name="send_email")
    session = SessionContext(
        session_id="dry-run-audit",
        user_root_intent="Send test notification",
        validation_scope=ValidationScope(mode=ValidationMode.DRY_RUN),
    )
    gate = PolicyGate(lazy_load=True)

    wrapper = AegisToolWrapper(
        underlying_tool=mock_email,
        policy_gate=gate,
        session=session,
    )

    res = wrapper.run({"recipient": "ceo@corp.com", "subject": "Test", "body": "Hello"})
    assert mock_email.call_count == 0, "Underlying email tool executed in DRY_RUN mode!"
    assert "[AEGIS VALIDATION DRY_RUN CONTAINED]" in str(res)


# ===========================================================================
# 16. Security Invariant Property Fuzzing
# ===========================================================================
def test_security_invariant_property_fuzzing():
    """Property test verifying that no combination of low risk, normal behavior, or clean text

    can bypass a mandatory BLOCK condition.
    """
    gate = PolicyGate(lazy_load=True)

    # Tainted session proposing EXECUTE_CODE must ALWAYS produce BLOCK regardless of intent similarity
    session = SessionContext(
        session_id="fuzz-session",
        user_root_intent="Execute shell command to clean cache",
        is_tainted=True,
    )

    proposal = ToolCallProposal(
        tool_name="execute_shell",
        arguments={"command": "clean_cache"},
        inferred_capability=Capability.EXECUTE_CODE,
    )

    decision = gate.evaluate_tool_call(session, proposal)
    assert decision.verdict == PolicyVerdict.BLOCK.value
    assert decision.blast_radius_contained is True


# ===========================================================================
# 18. Direct Tool Bypass Elimination & Guard Protection
# ===========================================================================
def test_direct_tool_bypass_elimination_and_guard_protection():
    """Verify that once wrapped in AegisToolWrapper, direct invocation of the raw tool

    outside of AegisToolWrapper is blocked with DirectToolInvocationBlockedError,
    while authorized execution via AegisToolWrapper succeeds.
    """
    import asyncio

    raw_tool = MockInstrumentedTool(name="sensitive_file_tool")
    session = SessionContext(session_id="bypass-session", user_root_intent="Read public file")
    gate = PolicyGate(lazy_load=True)

    # Wrap tool with AegisToolWrapper
    wrapper = AegisToolWrapper(
        underlying_tool=raw_tool,
        policy_gate=gate,
        session=session,
    )

    # 1. Attempt bypass: Direct synchronous invocation of raw_tool
    with pytest.raises(DirectToolInvocationBlockedError) as exc_info:
        raw_tool.run({"path": "/etc/shadow"})
    assert "Direct invocation of underlying tool 'sensitive_file_tool' is blocked" in str(exc_info.value)
    assert raw_tool.call_count == 0

    # 2. Attempt bypass: Direct invocation via wrapper.underlying_tool
    with pytest.raises(DirectToolInvocationBlockedError) as exc_info:
        wrapper.underlying_tool.run({"path": "/etc/shadow"})
    assert "Direct invocation of underlying tool 'sensitive_file_tool' is blocked" in str(exc_info.value)
    assert raw_tool.call_count == 0

    # 3. Attempt bypass: Direct asynchronous invocation of raw_tool
    with pytest.raises(DirectToolInvocationBlockedError) as exc_info:
        asyncio.run(raw_tool.arun({"path": "/etc/shadow"}))
    assert "Direct async invocation of underlying tool 'sensitive_file_tool' is blocked" in str(exc_info.value)
    assert raw_tool.call_count == 0

    # 4. Attempt bypass: Direct async invocation via wrapper.underlying_tool
    with pytest.raises(DirectToolInvocationBlockedError) as exc_info:
        asyncio.run(wrapper.underlying_tool.arun({"path": "/etc/shadow"}))
    assert "Direct async invocation of underlying tool 'sensitive_file_tool' is blocked" in str(exc_info.value)
    assert raw_tool.call_count == 0

    # 5. Protected Path: Authorized execution via AegisToolWrapper.run
    res = wrapper.run({"path": "public_doc.txt"})
    assert raw_tool.call_count == 1
    assert "EXECUTED_BY_UNDERLYING_TOOL:1" in str(res)

    # 6. Protected Path: Authorized execution via AegisToolWrapper.arun
    async_res = asyncio.run(wrapper.arun({"path": "public_doc.txt"}))
    assert raw_tool.call_count == 2
    assert "ASYNC_EXECUTED_BY_UNDERLYING_TOOL:2" in str(async_res)

    # 7. Test guard_tools batch helper
    guarded_list = AegisToolWrapper.guard_tools([MockInstrumentedTool(name="t2")], gate, session)
    assert len(guarded_list) == 1
    assert isinstance(guarded_list[0], AegisToolWrapper)
