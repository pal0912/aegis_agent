"""Cascading Circuit Breaker and Multi-Agent Resource Governor for AegisAgent V2.

Monitors execution loops, delegation recursion depths, token consumption budgets,
and consecutive policy violation thresholds to prevent runaway agent loops in compliance with OWASP ASI08.
"""

from enum import Enum
import logging
import time
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class CircuitState(str, Enum):
    """Execution state of the agent circuit breaker."""

    CLOSED = "CLOSED"  # Normal operation, execution permitted
    HALF_OPEN = "HALF_OPEN"  # Controlled probe / canary execution
    OPEN = "OPEN"  # Tripped / quarantined, all execution blocked


class CircuitBreakerOpenException(Exception):
    """Raised when an operation is blocked due to an open circuit breaker."""

    def __init__(
        self, reason: str, workflow_id: str = "default", metrics: Optional[Dict[str, Any]] = None
    ) -> None:
        super().__init__(f"CircuitBreaker OPEN for workflow '{workflow_id}': {reason}")
        self.reason = reason
        self.workflow_id = workflow_id
        self.metrics = metrics or {}


class AgentCircuitBreaker:
    """Enterprise multi-agent circuit breaker and cascade failure isolation governor."""

    DEFAULT_MAX_DELEGATION_DEPTH = 3
    DEFAULT_MAX_WORKFLOW_STEPS = 15
    DEFAULT_MAX_CONSECUTIVE_FAILURES = 3
    DEFAULT_MAX_TOKEN_BUDGET = 100000

    def __init__(
        self,
        max_delegation_depth: int = DEFAULT_MAX_DELEGATION_DEPTH,
        max_workflow_steps: int = DEFAULT_MAX_WORKFLOW_STEPS,
        max_consecutive_failures: int = DEFAULT_MAX_CONSECUTIVE_FAILURES,
        max_token_budget: int = DEFAULT_MAX_TOKEN_BUDGET,
    ) -> None:
        """Initialize governor thresholds and tracking state."""
        self.max_delegation_depth = max_delegation_depth
        self.max_workflow_steps = max_workflow_steps
        self.max_consecutive_failures = max_consecutive_failures
        self.max_token_budget = max_token_budget

        self._workflows: Dict[str, Dict[str, Any]] = {}
        self._global_kill_switch: bool = False

    def _get_workflow(self, workflow_id: str) -> Dict[str, Any]:
        """Fetch or initialize telemetry state for a workflow ID."""
        if workflow_id not in self._workflows:
            self._workflows[workflow_id] = {
                "state": CircuitState.CLOSED,
                "recursion_depth": 0,
                "step_count": 0,
                "consecutive_failures": 0,
                "token_consumption": 0,
                "trip_reason": None,
                "last_tripped_at": None,
            }
        return self._workflows[workflow_id]

    def record_step(self, workflow_id: str, tokens: int = 0) -> None:
        """Record an execution step/tool call and compute tokens consumed."""
        wf = self._get_workflow(workflow_id)
        wf["step_count"] += 1
        wf["token_consumption"] += max(0, tokens)

        if wf["step_count"] > self.max_workflow_steps:
            self.trip_breaker(
                workflow_id,
                f"MAX_WORKFLOW_STEPS_EXCEEDED: step_count {wf['step_count']} > limit {self.max_workflow_steps}",
            )
        elif wf["token_consumption"] > self.max_token_budget:
            self.trip_breaker(
                workflow_id,
                f"TOKEN_BUDGET_EXHAUSTED: consumed {wf['token_consumption']} > limit {self.max_token_budget}",
            )

    def record_delegation_hop(self, workflow_id: str) -> None:
        """Increment sub-agent delegation depth for this workflow."""
        wf = self._get_workflow(workflow_id)
        wf["recursion_depth"] += 1

        if wf["recursion_depth"] > self.max_delegation_depth:
            self.trip_breaker(
                workflow_id,
                f"MAX_DELEGATION_DEPTH_EXCEEDED: recursion_depth {wf['recursion_depth']} > limit {self.max_delegation_depth}",
            )

    def record_policy_violation(self, workflow_id: str) -> None:
        """Increment failure/violation count and check for trip threshold."""
        wf = self._get_workflow(workflow_id)
        wf["consecutive_failures"] += 1

        if wf["consecutive_failures"] >= self.max_consecutive_failures:
            self.trip_breaker(
                workflow_id,
                f"CONSECUTIVE_POLICY_VIOLATIONS_EXCEEDED: violations {wf['consecutive_failures']} >= threshold {self.max_consecutive_failures}",
            )

    def record_success(self, workflow_id: str) -> None:
        """Reset consecutive failure counter upon successful benign execution."""
        wf = self._get_workflow(workflow_id)
        wf["consecutive_failures"] = 0
        if wf["state"] == CircuitState.HALF_OPEN:
            wf["state"] = CircuitState.CLOSED
            logger.info(f"AgentCircuitBreaker: Workflow '{workflow_id}' recovered to CLOSED state.")

    def trip_breaker(self, workflow_id: str, reason: str) -> None:
        """Explicitly trip the circuit breaker into OPEN state."""
        wf = self._get_workflow(workflow_id)
        wf["state"] = CircuitState.OPEN
        wf["trip_reason"] = reason
        wf["last_tripped_at"] = time.time()
        logger.error(f"AgentCircuitBreaker TRIPPED for workflow '{workflow_id}': {reason}")

    def emergency_kill_all(self) -> None:
        """Emergency System Kill Switch: Immediately trip all active workflows."""
        self._global_kill_switch = True
        for wf_id, wf in self._workflows.items():
            wf["state"] = CircuitState.OPEN
            wf["trip_reason"] = "EMERGENCY_GLOBAL_KILL_SWITCH_ENGAGED"
            wf["last_tripped_at"] = time.time()
        logger.critical("EMERGENCY GLOBAL KILL SWITCH ENGAGED: All circuit breakers tripped to OPEN.")

    def reset_global_kill_switch(self) -> None:
        """Reset global kill switch status."""
        self._global_kill_switch = False
        logger.info("Global kill switch reset.")

    def reset(self, workflow_id: str) -> None:
        """Reset workflow telemetry and circuit state back to CLOSED."""
        self._workflows[workflow_id] = {
            "state": CircuitState.CLOSED,
            "recursion_depth": 0,
            "step_count": 0,
            "consecutive_failures": 0,
            "token_consumption": 0,
            "trip_reason": None,
            "last_tripped_at": None,
        }
        logger.info(f"AgentCircuitBreaker reset for workflow '{workflow_id}'.")

    def check_state(self, workflow_id: str, raise_on_open: bool = True) -> CircuitState:
        """Evaluate circuit breaker state; raises CircuitBreakerOpenException if OPEN."""
        if self._global_kill_switch:
            if raise_on_open:
                raise CircuitBreakerOpenException(
                    "EMERGENCY_GLOBAL_KILL_SWITCH_ENGAGED",
                    workflow_id,
                    self.get_metrics(workflow_id),
                )
            return CircuitState.OPEN

        wf = self._get_workflow(workflow_id)
        if wf["state"] == CircuitState.OPEN:
            if raise_on_open:
                raise CircuitBreakerOpenException(
                    wf["trip_reason"] or "CIRCUIT_BREAKER_OPEN",
                    workflow_id,
                    self.get_metrics(workflow_id),
                )
            return CircuitState.OPEN

        return wf["state"]

    def is_tripped(self, workflow_id: str) -> bool:
        """Return True if circuit breaker is currently OPEN."""
        if self._global_kill_switch:
            return True
        wf = self._get_workflow(workflow_id)
        return wf["state"] == CircuitState.OPEN

    def get_metrics(self, workflow_id: str) -> Dict[str, Any]:
        """Return snapshot of execution telemetry for a workflow."""
        wf = self._get_workflow(workflow_id)
        return dict(wf)

    def list_all_workflows(self) -> Dict[str, Dict[str, Any]]:
        """Return snapshot of all registered workflows."""
        return {wf_id: dict(data) for wf_id, data in self._workflows.items()}
