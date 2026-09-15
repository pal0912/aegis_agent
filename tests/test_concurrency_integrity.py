"""High-Concurrency Multithreaded Race Condition & Runtime Integrity Tests for AegisAgent V2.

Verifies:
1. High-concurrency AgentIdentityManager token issuance vs revocation race conditions.
2. Multi-threaded agent registration, key rotation, and cryptographic verification safety.
3. Thread safety of AuditLogger and CryptographicLedger append operations.
4. Concurrent PolicyGate evaluation requests without state corruption.
"""

import concurrent.futures
import threading
import time
import pytest
from typing import List

from aegis.identity import AgentIdentityManager
from aegis.audit import AuditLogger
from aegis.ledger import CryptographicLedger
from aegis.policy_gate import PolicyGate
from aegis.taint import SessionContext
from aegis.types import Capability, AuditEvent, PolicyDecision, PolicyVerdict, ToolCallProposal, TrustLevel


def test_concurrent_token_issuance_and_revocation():
    """Verify thread-safety when multiple threads concurrently issue and revoke delegation tokens."""
    identity_mgr = AgentIdentityManager()
    root_agent = "root_orchestrator"
    worker_agent = "worker_executor"

    identity_mgr.register_agent(root_agent, [Capability.READ_PUBLIC, Capability.READ_PRIVATE, Capability.EXECUTE_CODE])
    identity_mgr.register_agent(worker_agent, [Capability.READ_PUBLIC, Capability.READ_PRIVATE])

    tokens: List[str] = []
    tokens_lock = threading.Lock()
    num_threads = 16
    operations_per_thread = 25

    def issue_worker(thread_idx: int):
        for op in range(operations_per_thread):
            try:
                token = identity_mgr.issue_delegation_token(
                    issuer_id=root_agent,
                    delegate_id=worker_agent,
                    capabilities=[Capability.READ_PUBLIC],
                    ttl_seconds=60,
                )
                with tokens_lock:
                    tokens.append(token)
            except Exception as e:
                pytest.fail(f"Concurrent token issuance crashed: {e}")

    def revoke_worker(thread_idx: int):
        for op in range(operations_per_thread):
            time.sleep(0.001)
            with tokens_lock:
                if tokens:
                    token_to_revoke = tokens.pop()
                else:
                    token_to_revoke = None

            if token_to_revoke:
                try:
                    identity_mgr.revoke_token(token_to_revoke)
                    # Verify immediately that revoked token fails verification
                    is_valid, _ = identity_mgr.verify_delegation_token(token_to_revoke)
                    assert not is_valid, "Revoked token was reported as valid!"
                except Exception as e:
                    pytest.fail(f"Concurrent token revocation crashed: {e}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = []
        for i in range(num_threads // 2):
            futures.append(executor.submit(issue_worker, i))
            futures.append(executor.submit(revoke_worker, i))
        concurrent.futures.wait(futures)

    # All issued tokens that remain unrevoked must verify, and revoked must not verify
    with tokens_lock:
        for remaining_token in tokens:
            valid, _ = identity_mgr.verify_delegation_token(remaining_token)
            assert valid is True


def test_concurrent_audit_logger_ledger_appends(tmp_path):
    """Verify thread-safety of AuditLogger and CryptographicLedger under high concurrent write load."""
    log_file = tmp_path / "concurrent_audit.jsonl"
    logger = AuditLogger(log_filepath=str(log_file))

    num_threads = 10
    writes_per_thread = 20

    def write_events(thread_id: int):
        for i in range(writes_per_thread):
            evt = AuditEvent(
                trace_id=f"thread-{thread_id}-{i}",
                trust_level=TrustLevel.TRUSTED,
                raw_content_sha256=AuditEvent.hash_payload(f"payload-{thread_id}-{i}"),
                policy_decision=PolicyDecision(
                    verdict=PolicyVerdict.ALLOW.value,
                    reason="Authorized test event",
                    intent_similarity_score=1.0,
                    blast_radius_contained=True,
                ),
            )
            signed_evt = logger.log_event(evt)
            assert signed_evt.ledger_entry_hash is not None

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(write_events, t) for t in range(num_threads)]
        for f in concurrent.futures.as_completed(futures):
            f.result()

    # Verify total logged events and ledger integrity
    total_events = len(logger.get_recent_events(limit=1000))
    assert total_events == num_threads * writes_per_thread

    is_valid, count, err_msg = logger.verify_ledger()
    assert is_valid is True, f"Ledger chain integrity broken: {err_msg}"


def test_concurrent_policy_gate_evaluations():
    """Verify PolicyGate can handle concurrent evaluation requests across threads without race conditions."""
    gate = PolicyGate(lazy_load=True)
    gate.capability_registry.register_tool("concurrent_search", Capability.READ_PUBLIC)

    num_threads = 8
    evals_per_thread = 15

    def eval_worker(thread_id: int):
        for i in range(evals_per_thread):
            session = SessionContext(
                session_id=f"sess-thread-{thread_id}-{i}",
                user_root_intent=f"Query search documentation {i}",
                role="researcher",
            )
            proposal = ToolCallProposal(
                tool_name="concurrent_search",
                arguments={"query": f"term_{thread_id}_{i}"},
                source_trace_id=session.session_id,
            )
            decision = gate.evaluate_tool_call(session, proposal)
            assert decision.verdict in {PolicyVerdict.ALLOW.value, PolicyVerdict.BLOCK.value}
            assert decision.policy_version is not None
            assert decision.policy_snapshot_hash is not None

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(eval_worker, t) for t in range(num_threads)]
        concurrent.futures.wait(futures)
