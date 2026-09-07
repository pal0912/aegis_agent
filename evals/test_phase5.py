"""Adversarial and Multi-Agent benchmark test suite for Phase 5.

Re-exports tests from tests.test_phase5 for unified evaluation.
"""

from tests.test_phase5 import (
    TestCascadingCircuitBreaker,
    TestDeclarativePolicyEngine,
    TestInterAgentCommunicationGuard,
    TestNonHumanIdentity,
    TestPolicyGatePhase5Integration,
)

__all__ = [
    "TestNonHumanIdentity",
    "TestInterAgentCommunicationGuard",
    "TestCascadingCircuitBreaker",
    "TestDeclarativePolicyEngine",
    "TestPolicyGatePhase5Integration",
]
