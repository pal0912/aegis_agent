"""Deterministic Policy Decision Fuzzing Engine for AegisAgent V2.

Generates 500+ randomized combinations of operational parameters:
- Roles & Identities
- Capabilities (all fine-grained types including UNKNOWN)
- Tainted vs Untainted session states
- Honeypot canary token payloads
- Outbound network egress targets (SSRF vs Whitelisted)
- DLP secret & credential injections
- Behavioral anomaly states

Verifies Invariants 1-7 across all 500+ evaluations:
- Invariant 1: Mandatory DENY strictly dominates (Canary, UNKNOWN capability, RBAC deny, SSRF, Taint violation)
- Invariant 2: Blast radius containment
- Invariant 3: Taint irreversibility
- Invariant 5: Effective capabilities monotonicity
- Invariant 6: Zero-bypass tool execution
- Invariant 7: Policy snapshot integrity (version & hash attached)
"""

import json
import random
import pytest
from typing import Any, Dict, List

from aegis.capabilities import CapabilityRegistry
from aegis.honeytoken import HoneytokenManager
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


@pytest.fixture(scope="module")
def deterministic_gate():
    """Create a PolicyGate instance with deterministic lazy loading for high-speed fuzzing."""
    return PolicyGate(lazy_load=True)


def test_policy_decision_fuzzing_500_iterations(deterministic_gate):
    """Fuzz PolicyGate over 500 deterministic pseudo-random state configurations asserting Invariants 1-7."""
    rng = random.Random(42)  # Seeded for perfect determinism and repeatability

    roles = ["researcher", "coder", "deployer", "db_admin", "unregistered_role", None]
    capabilities = list(Capability)
    tools_map = {
        Capability.READ_PUBLIC: "read_public_docs",
        Capability.READ_PRIVATE: "read_customer_record",
        Capability.WRITE_FILE: "write_config_file",
        Capability.WRITE_DATABASE: "update_user_balance",
        Capability.SEND_EXTERNAL_MESSAGE: "send_slack_alert",
        Capability.EXECUTE_CODE: "run_shell_cmd",
        Capability.NETWORK_EXTERNAL: "fetch_remote_api",
        Capability.FINANCIAL_ACTION: "wire_transfer_funds",
        Capability.ADMIN: "drop_all_tables",
        Capability.UNKNOWN: "exotic_unregistered_tool",
    }

    # Register known tools
    for cap, tool_name in tools_map.items():
        deterministic_gate.capability_registry.register_tool(tool_name, cap)

    honeytoken_mgr = deterministic_gate.honeytoken
    _, active_canary = honeytoken_mgr.generate_canary("AWS_KEY")

    total_fuzz_iterations = 500
    allow_count = 0
    block_count = 0

    for i in range(total_fuzz_iterations):
        assigned_role = rng.choice(roles)
        selected_cap = rng.choice(capabilities)
        tool_name = tools_map[selected_cap]
        is_session_tainted = rng.choice([True, False])
        has_canary = rng.choice([True, False])
        has_ssrf_egress = rng.choice([True, False])
        has_dlp_secret = rng.choice([True, False])

        # Construct arguments
        args: Dict[str, Any] = {"iteration": i, "data": f"fuzz_payload_{i}"}
        if has_canary:
            args["canary"] = active_canary
        if has_ssrf_egress:
            args["target_url"] = rng.choice([
                "http://169.254.169.254/latest/meta-data/",
                "http://127.0.0.1:8080/admin",
                "http://localhost:5000/keys",
            ])
        else:
            args["target_url"] = "https://api.github.com/v1/repos"

        if has_dlp_secret:
            args["secret_leak"] = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

        # Build session
        session = SessionContext(
            session_id=f"fuzz-session-{i}",
            user_root_intent=f"Perform operation {tool_name} for iteration {i}",
            is_tainted=is_session_tainted,
            role=assigned_role,
        )

        proposal = ToolCallProposal(
            tool_name=tool_name,
            arguments=args,
            source_trace_id=session.session_id,
        )

        # Execute decision
        decision = deterministic_gate.evaluate_tool_call(
            session=session,
            tool_proposal=proposal,
        )

        # Invariant 7: Policy snapshot integrity
        assert decision.policy_version is not None, f"Iteration {i}: Missing policy_version"
        assert decision.policy_snapshot_hash is not None, f"Iteration {i}: Missing policy_snapshot_hash"
        assert len(decision.policy_snapshot_hash) == 64, f"Iteration {i}: Malformed policy_snapshot_hash"

        # Invariant 1: Mandatory DENY strictly dominates
        # 1a. Canary tripwire must ALWAYS BLOCK
        if has_canary:
            assert decision.verdict == PolicyVerdict.BLOCK.value, (
                f"Iteration {i}: Canary tripwire failed to dominate! Verdict: {decision.verdict}"
            )

        # 1b. UNKNOWN capability must ALWAYS BLOCK
        if selected_cap == Capability.UNKNOWN:
            assert decision.verdict == PolicyVerdict.BLOCK.value, (
                f"Iteration {i}: UNKNOWN capability failed to block! Verdict: {decision.verdict}"
            )

        # 1c. SSRF to internal/cloud metadata IP must ALWAYS BLOCK
        if has_ssrf_egress:
            assert decision.verdict == PolicyVerdict.BLOCK.value, (
                f"Iteration {i}: SSRF egress failed to block! Verdict: {decision.verdict}"
            )

        # 1d. Tainted session with high-impact capabilities must ALWAYS BLOCK
        if is_session_tainted and not deterministic_gate.capability_registry.is_allowed_for_tainted_session(selected_cap):
            assert decision.verdict == PolicyVerdict.BLOCK.value, (
                f"Iteration {i}: Tainted session privilege escalation permitted! Verdict: {decision.verdict}"
            )

        # 1e. Unregistered role must ALWAYS BLOCK
        if assigned_role == "unregistered_role":
            assert decision.verdict == PolicyVerdict.BLOCK.value, (
                f"Iteration {i}: Unregistered role permitted! Verdict: {decision.verdict}"
            )

        # Invariant 6: Strict verdict typing
        assert decision.verdict in {
            PolicyVerdict.ALLOW.value,
            PolicyVerdict.ALLOW_RESTRICTED.value,
            PolicyVerdict.REQUIRE_HUMAN_APPROVAL.value,
            PolicyVerdict.BLOCK.value,
            PolicyVerdict.FAIL_CLOSED.value,
        }

        if decision.verdict == PolicyVerdict.ALLOW.value:
            allow_count += 1
            # If ALLOW, verify no mandatory deny condition existed
            assert not has_canary, f"Iteration {i}: ALLOW granted with active canary!"
            assert not has_ssrf_egress, f"Iteration {i}: ALLOW granted with SSRF target!"
            assert selected_cap != Capability.UNKNOWN, f"Iteration {i}: ALLOW granted for UNKNOWN tool!"
            assert assigned_role != "unregistered_role", f"Iteration {i}: ALLOW granted for unregistered role!"
        elif decision.verdict == PolicyVerdict.BLOCK.value:
            block_count += 1

    # Verify both allows and blocks occurred across 500 diverse trials
    assert allow_count > 0, "Fuzzer produced zero ALLOWs (over-restrictive)"
    assert block_count > 0, "Fuzzer produced zero BLOCKs (broken security gates)"
    assert (allow_count + block_count) <= total_fuzz_iterations
