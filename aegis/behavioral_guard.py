"""Deterministic Behavioral Anomaly Guard for AegisAgent.

Tracks multi-step action sequences, detects capability escalation jumps, and prevents
dangerous transitions (such as read-to-egress and reconnaissance chains) via deterministic state analysis.
"""

from collections import defaultdict
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from aegis.types import BehavioralState, Capability

logger = logging.getLogger(__name__)


class BehavioralGuard:
    """Runtime deterministic state automaton and behavioral anomaly detector."""

    MAX_ACTIVE_SESSIONS = 5000
    MAX_STEPS_PER_SESSION = 50

    def __init__(
        self,
        max_sliding_window: int = 10,
        loop_threshold: int = 4,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        self.max_sliding_window = max_sliding_window
        self.loop_threshold = loop_threshold
        # Maps session_id to chronological action steps: List of (Capability, tool_name, timestamp)
        self.session_histories: Dict[str, List[Tuple[Capability, str, float]]] = {}

    def _append_step(self, session_id: str, capability: Capability, tool_name: str, ts: float) -> None:
        """Internal bounded append ensuring bounded memory consumption against DoS."""
        if session_id not in self.session_histories:
            if len(self.session_histories) >= self.MAX_ACTIVE_SESSIONS:
                # Evict oldest session
                oldest_sid = next(iter(self.session_histories))
                del self.session_histories[oldest_sid]
            self.session_histories[session_id] = []

        history = self.session_histories[session_id]
        history.append((capability, tool_name, ts))
        if len(history) > self.MAX_STEPS_PER_SESSION:
            self.session_histories[session_id] = history[-self.MAX_STEPS_PER_SESSION:]

    def record_step(self, session_id: str, capability: Capability, tool_name: str) -> None:
        """Explicitly record an executed action step into session history."""
        self._append_step(session_id, capability, tool_name, time.time())

    def get_history(self, session_id: str) -> List[Tuple[Capability, str, float]]:
        """Retrieve action history for a session."""
        return list(self.session_histories.get(session_id, []))

    def clear_session(self, session_id: str) -> None:
        """Clear action history for a session."""
        if session_id in self.session_histories:
            del self.session_histories[session_id]

    def reset_session(self, session_id: str) -> None:
        """Reset / clear action history for a session."""
        self.clear_session(session_id)

    def evaluate_step(
        self,
        session_id: str,
        proposal_or_capability: Any = None,
        tool_name: Optional[str] = None,
        user_intent: str = "",
        is_tainted: bool = False,
        *args: Any,
        **kwargs: Any,
    ) -> Tuple[BehavioralState, float, List[str]]:
        """Evaluate a proposed action step against deterministic behavioral sequence rules.

        Accepts either a ToolCallProposal instance or explicit Capability/tool arguments.
        """
        proposed_capability = Capability.READ_PUBLIC
        proposed_tool = "unknown"

        if hasattr(proposal_or_capability, "inferred_capability"):
            proposed_capability = proposal_or_capability.inferred_capability
            proposed_tool = getattr(proposal_or_capability, "tool_name", "unknown")
        elif isinstance(proposal_or_capability, Capability):
            proposed_capability = proposal_or_capability
            proposed_tool = tool_name or (args[0] if len(args) > 0 else kwargs.get("proposed_tool", "unknown"))
        elif isinstance(proposal_or_capability, str):
            proposed_tool = proposal_or_capability
            proposed_capability = Capability.from_tool_name(proposed_tool)
        elif kwargs.get("proposed_capability") is not None:
            proposed_capability = kwargs["proposed_capability"]
            proposed_tool = kwargs.get("proposed_tool", "unknown")

        actual_intent = user_intent or kwargs.get("user_intent", "")

        return self.evaluate_action_step(
            session_id=session_id,
            proposed_capability=proposed_capability,
            proposed_tool=proposed_tool,
            user_intent=actual_intent,
        )

    def evaluate_action_step(
        self,
        session_id: str,
        proposed_capability: Capability,
        proposed_tool: str,
        user_intent: str = "",
    ) -> Tuple[BehavioralState, float, List[str]]:
        """Evaluate a proposed action step against deterministic behavioral sequence rules.

        Args:
            session_id: Active session identifier.
            proposed_capability: Capability requested by the proposed tool call.
            proposed_tool: Identifier of the tool to be invoked.
            user_intent: Verified root intent string of the user.

        Returns:
            Tuple of (BehavioralState, anomaly_score [0.0 - 1.0], triggered_rules).
        """
        history = self.session_histories.get(session_id, [])
        now = time.time()
        triggered_rules: List[str] = []
        max_score: float = 0.0
        final_state: BehavioralState = BehavioralState.NORMAL

        intent_lower = (user_intent or "").lower()
        tool_lower = (proposed_tool or "").lower()

        # ----------------------------------------------------------------------
        # Rule 4: Multi-Step Reconnaissance Sequence (CRITICAL, score 1.0)
        # Sequence: web_search -> read_file -> http_request / network egress
        # ----------------------------------------------------------------------
        if proposed_capability in (Capability.NETWORK_EXTERNAL, Capability.SEND_EXTERNAL_MESSAGE):
            tools_in_history = [t.lower() for _, t, _ in history]
            has_search = any("search" in t or "web" in t for t in tools_in_history)
            has_file_read = any("read" in t or "file" in t or "cat" in t for t in tools_in_history)

            if has_search and has_file_read:
                rule_name = "BEH-04: Multi-Step Reconnaissance Sequence (search -> read -> egress)"
                triggered_rules.append(rule_name)
                max_score = max(max_score, 1.0)
                final_state = BehavioralState.CRITICAL

        # ----------------------------------------------------------------------
        # Rule 1: Dangerous State Flip (Read-to-Egress) (CRITICAL, score 0.95)
        # Session previously invoked READ_PRIVATE and now attempts NETWORK_EXTERNAL / SEND_EXTERNAL_MESSAGE
        # ----------------------------------------------------------------------
        if proposed_capability in (Capability.NETWORK_EXTERNAL, Capability.SEND_EXTERNAL_MESSAGE):
            has_read_private = any(cap == Capability.READ_PRIVATE for cap, _, _ in history)
            authorizes_egress = any(
                kw in intent_lower for kw in ["send", "email", "post", "export", "upload", "share", "webhook", "http"]
            )

            if has_read_private and not authorizes_egress:
                rule_name = "BEH-01: Dangerous Read-to-Egress State Flip"
                triggered_rules.append(rule_name)
                max_score = max(max_score, 0.95)
                final_state = BehavioralState.CRITICAL

        # ----------------------------------------------------------------------
        # Rule 2: Sudden Capability Escalation Jump (ANOMALOUS, score 0.80)
        # History exclusively READ_PUBLIC (or <= 1 step) attempting ADMIN, EXECUTE_CODE, or FINANCIAL_ACTION
        # ----------------------------------------------------------------------
        if proposed_capability in (Capability.ADMIN, Capability.EXECUTE_CODE, Capability.FINANCIAL_ACTION):
            if not history or all(cap == Capability.READ_PUBLIC for cap, _, _ in history):
                # Check if user explicitly asked for code execution/admin/financial in prompt
                authorizes_admin = any(
                    kw in intent_lower for kw in ["admin", "execute", "run code", "bash", "shell", "transfer", "pay", "charge"]
                )
                if not authorizes_admin:
                    rule_name = f"BEH-02: Sudden Capability Escalation Jump ({proposed_capability.value})"
                    triggered_rules.append(rule_name)
                    max_score = max(max_score, 0.80)
                    if final_state != BehavioralState.CRITICAL:
                        final_state = BehavioralState.ANOMALOUS

        # ----------------------------------------------------------------------
        # Rule 3: Repetitive Tool Flooding / Looping (SUSPICIOUS, score 0.65)
        # Same tool invoked >= loop_threshold times in sliding window
        # ----------------------------------------------------------------------
        sliding_window_sec = float(self.max_sliding_window)
        threshold = max(1, self.loop_threshold)
        recent_invocations = [
            t for _, t, ts in history
            if (now - ts) <= sliding_window_sec and t.lower() == tool_lower
        ]
        if len(recent_invocations) >= threshold:
            call_count = len(recent_invocations) + 1
            rule_name = (
                f"BEH-03: Excessive Tool Invocation Rate / Loop "
                f"({proposed_tool} called {call_count} times in {int(sliding_window_sec)}s)"
            )
            triggered_rules.append(rule_name)
            max_score = max(max_score, 0.65)
            if final_state not in (BehavioralState.CRITICAL, BehavioralState.ANOMALOUS):
                final_state = BehavioralState.SUSPICIOUS

        # Record this proposed step into history safely with bounded capacity
        self._append_step(session_id, proposed_capability, proposed_tool, now)

        return final_state, round(max_score, 2), triggered_rules
