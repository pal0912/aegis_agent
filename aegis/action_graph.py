"""Behavioral action dependency graph and multi-step chain attack detector for AegisAgent V2.

Tracks execution nodes per session and enforces strict behavioral graph constraints
to prevent covert action chaining (e.g., READ_PRIVATE -> NETWORK_EXTERNAL).
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from pydantic import BaseModel, ConfigDict, Field

from aegis.types import Capability

logger = logging.getLogger(__name__)


class ActionNode(BaseModel):
    """Immutable node recording a single executed tool or capability in the action graph."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    node_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for the action node.",
    )
    session_id: str = Field(
        ...,
        min_length=1,
        description="Session trace identifier.",
    )
    capability: Capability = Field(
        ...,
        description="Capability executed at this node.",
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of execution.",
    )
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Contextual metadata for the action.",
    )


class ActionDependencyGraph:
    """Directed behavioral execution graph monitoring and restricting multi-step capability transitions."""

    # Prohibited direct transitions (Prev -> Proposed) when session is in an untrusted/tainted state
    FORBIDDEN_DIRECT_TRANSITIONS: Set[Tuple[Capability, Capability]] = {
        # Data exfiltration chains: Reading private info followed directly by external egress
        (Capability.READ_PRIVATE, Capability.NETWORK_EXTERNAL),
        (Capability.READ_PRIVATE, Capability.SEND_EXTERNAL_MESSAGE),
        (Capability.READ_PRIVATE, Capability.WRITE_FILE),
        # Direct mutation chains: Public/untrusted reading followed directly by state mutation/code exec
        (Capability.READ_PUBLIC, Capability.WRITE_DATABASE),
        (Capability.READ_PUBLIC, Capability.EXECUTE_CODE),
        (Capability.READ_PUBLIC, Capability.ADMIN),
        (Capability.READ_PUBLIC, Capability.FINANCIAL_ACTION),
    }

    # Prohibited persistent history chains (if ANY node in history has X, session cannot transition to Y when tainted)
    FORBIDDEN_HISTORICAL_PAIRS: Set[Tuple[Capability, Capability]] = {
        # Data exfiltration historical pairs
        (Capability.READ_PRIVATE, Capability.NETWORK_EXTERNAL),
        (Capability.READ_PRIVATE, Capability.SEND_EXTERNAL_MESSAGE),
        # Dangerous escalation pairs from untrusted public ingestion
        (Capability.READ_PUBLIC, Capability.EXECUTE_CODE),
        (Capability.READ_PUBLIC, Capability.ADMIN),
        (Capability.READ_PUBLIC, Capability.FINANCIAL_ACTION),
        (Capability.READ_PUBLIC, Capability.WRITE_DATABASE),
    }

    MAX_SESSIONS = 5000
    MAX_NODES_PER_SESSION = 50

    def __init__(self) -> None:
        """Initialize ActionDependencyGraph with per-session execution chains."""
        self._graph: Dict[str, List[ActionNode]] = {}

    def record_node(
        self,
        session_id: str,
        capability: Capability,
        details: Optional[Dict[str, Any]] = None,
    ) -> ActionNode:
        """Append an execution node to the session's action graph.

        Args:
            session_id: Active session identifier.
            capability: Operational Capability executed.
            details: Optional metadata parameters.

        Returns:
            Created ActionNode instance.
        """
        node = ActionNode(
            session_id=session_id,
            capability=capability,
            details=details or {},
        )
        if session_id not in self._graph:
            if len(self._graph) >= self.MAX_SESSIONS:
                oldest_sid = next(iter(self._graph))
                del self._graph[oldest_sid]
            self._graph[session_id] = []

        self._graph[session_id].append(node)
        if len(self._graph[session_id]) > self.MAX_NODES_PER_SESSION:
            self._graph[session_id] = self._graph[session_id][-self.MAX_NODES_PER_SESSION:]

        logger.debug(
            "ActionGraph recorded node [%s] for session '%s' (chain length: %d)",
            capability.value,
            session_id,
            len(self._graph[session_id]),
        )
        return node

    def get_history(self, session_id: str) -> List[Capability]:
        """Retrieve chronological sequence of executed capabilities for a session."""
        nodes = self._graph.get(session_id, [])
        return [node.capability for node in nodes]

    def get_nodes(self, session_id: str) -> List[ActionNode]:
        """Retrieve full chronological ActionNode list for a session."""
        return list(self._graph.get(session_id, []))

    def evaluate_transition(
        self,
        session_id: str,
        proposed_capability: Capability,
        is_tainted: bool = True,
    ) -> Tuple[bool, str]:
        """Evaluate if transitioning to proposed_capability violates behavioral graph policies.

        Args:
            session_id: Active session identifier.
            proposed_capability: Capability requested by candidate tool.
            is_tainted: True if the session contains untrusted context.

        Returns:
            Tuple of (is_valid: bool, reason: str).
        """
        history = self.get_history(session_id)
        if not history:
            return True, "Initial capability transition allowed."

        prev_capability = history[-1]

        # 1. Direct Transition Rule Check under Tainted State
        if is_tainted and (prev_capability, proposed_capability) in self.FORBIDDEN_DIRECT_TRANSITIONS:
            return False, (
                f"Forbidden action graph transition: '{prev_capability.value}' -> '{proposed_capability.value}' "
                f"violates multi-step execution boundaries for tainted sessions."
            )

        # 2. Historical Chain Rule Check (e.g. earlier READ_PRIVATE -> now NETWORK_EXTERNAL)
        if is_tainted:
            for past_cap in history:
                if (past_cap, proposed_capability) in self.FORBIDDEN_HISTORICAL_PAIRS:
                    return False, (
                        f"Forbidden action chain detected: Historical execution of '{past_cap.value}' "
                        f"prohibits subsequent transition to external egress '{proposed_capability.value}'."
                    )

        return True, "Action graph transition validated successfully."

    def clear(self, session_id: Optional[str] = None) -> None:
        """Clear action graph history."""
        if session_id:
            self._graph.pop(session_id, None)
        else:
            self._graph.clear()
