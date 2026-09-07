"""Deterministic Behavioral Anomaly Guard for AegisAgent.

Tracks multi-step action sequences, detects capability escalation jumps, and prevents
dangerous transitions (such as read-to-egress and reconnaissance chains) via deterministic state analysis.
"""

from collections import defaultdict
import logging
import time
from typing import Dict, List, Optional, Set, Tuple

from aegis.types import BehavioralState, Capability

logger = logging.getLogger(__name__)


class BehavioralGuard:
    """Runtime deterministic state automaton and behavioral anomaly detector."""

    def __init__(self) -> None:
        # Maps session_id to chronological action steps: List of (Capability, tool_name, timestamp)
        self.session_histories: Dict[str, List[Tuple[Capability, str, float]]] = defaultdict(list)

    def record_step(self, session_id: str, capability: Capability, tool_name: str) -> None:
        """Explicitly record an executed action step into session history."""
        self.session_histories[session_id].append((capability, tool_name, time.time()))

    def get_history(self, session_id: str) -> List[Tuple[Capability, str, float]]:
        """Retrieve action history for a session."""
        return list(self.session_histories[session_id])

    def clear_session(self, session_id: str) -> None:
        """Clear action history for a session."""
        if session_id in self.session_histories:
            del self.session_histories[session_id]

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
        history = self.session_histories[session_id]
        now = time.time()
        triggered_rules: List[str] = []
        max_score: float = 0.0
        final_state: BehavioralState = BehavioralState.NORMAL

        intent_lower = (user_intent or "").lower()
        tool_lower = proposed_tool.lower()

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
        # Same write/exec tool invoked > 5 times in sliding 10-second window
        # ----------------------------------------------------------------------
        recent_invocations = [
            t for _, t, ts in history
            if (now - ts) <= 10.0 and t.lower() == tool_lower
        ]
        if len(recent_invocations) >= 5:
            rule_name = f"BEH-03: Excessive Tool Invocation Rate / Loop ({proposed_tool} called {len(recent_invocations)+1} times in 10s)"
            triggered_rules.append(rule_name)
            max_score = max(max_score, 0.65)
            if final_state not in (BehavioralState.CRITICAL, BehavioralState.ANOMALOUS):
                final_state = BehavioralState.SUSPICIOUS

        # Record this proposed step into history
        self.session_histories[session_id].append((proposed_capability, proposed_tool, now))

        return final_state, round(max_score, 2), triggered_rules
