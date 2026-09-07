"""Deterministic policy gate, capability enforcement, and multi-factor risk engine for AegisAgent V2.

Orchestrates capability arbitration, outbound network guard, DLP secret protection,
honeypot canary traps, behavioral anomaly detection, field-level data lineage,
action dependency graph validation, and tri-state HITL authorization.
"""

import json
import logging
import re
from typing import Any, List, Optional, Set

import numpy as np
import torch
from sentence_transformers import SentenceTransformer

from aegis.action_graph import ActionDependencyGraph
from aegis.behavioral_guard import BehavioralGuard
from aegis.capabilities import CapabilityRegistry
from aegis.circuit_breaker import AgentCircuitBreaker
from aegis.consensus import DualAgentConsensusGate
from aegis.data_lineage import DataLineageTracker
from aegis.declarative_policy import DeclarativePolicyEngine
from aegis.dlp import DataLossPreventionEngine
from aegis.honeytoken import HoneytokenManager
from aegis.identity import AgentIdentityManager
from aegis.memory_guard import MemoryGuard
from aegis.network_guard import OutboundNetworkGuard
from aegis.risk_engine import RiskEngine
from aegis.sandbox import IsolatedCodeSandbox
from aegis.taint import SessionContext
from aegis.types import (
    BehavioralState,
    Capability,
    FieldTrustLevel,
    PolicyDecision,
    PolicyVerdict,
    ScanResult,
    ToolCallProposal,
    ToolPrivilege,
)

logger = logging.getLogger(__name__)


class PolicyGate:
    """Enterprise deterministic policy gate and tri-state risk arbitrator for autonomous agents."""

    DEFAULT_EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
    SIMILARITY_THRESHOLD = 0.35

    HIGH_IMPACT_WRITE_TOOLS: Set[str] = {
        "send_email",
        "execute_shell",
        "delete_file",
        "write_db",
        "transfer_funds",
        "drop_table",
    }

    READ_ONLY_TOOLS: Set[str] = {
        "web_search",
        "read_file",
        "get_weather",
        "read_db",
    }

    def __init__(
        self,
        model_name: str = DEFAULT_EMBEDDING_MODEL,
        device: Optional[str] = None,
        lazy_load: bool = False,
        custom_high_impact_tools: Optional[List[str]] = None,
        custom_read_only_tools: Optional[List[str]] = None,
        capability_registry: Optional[CapabilityRegistry] = None,
        network_guard: Optional[OutboundNetworkGuard] = None,
        dlp_engine: Optional[DataLossPreventionEngine] = None,
        memory_guard: Optional[MemoryGuard] = None,
        honeytoken_manager: Optional[HoneytokenManager] = None,
        action_graph: Optional[ActionDependencyGraph] = None,
        risk_engine: Optional[RiskEngine] = None,
        consensus_gate: Optional[DualAgentConsensusGate] = None,
        sandbox: Optional[IsolatedCodeSandbox] = None,
        circuit_breaker: Optional[AgentCircuitBreaker] = None,
        declarative_policy: Optional[DeclarativePolicyEngine] = None,
        identity_manager: Optional[AgentIdentityManager] = None,
        data_lineage: Optional[DataLineageTracker] = None,
        behavioral_guard: Optional[BehavioralGuard] = None,
    ) -> None:
        """Initialize PolicyGate with security engines, behavioral graph, consensus arbitrator, and circuit breaker."""
        self.model_name = model_name
        if device is None:
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
        else:
            self.device = device

        self.capability_registry = capability_registry or CapabilityRegistry()
        self.network_guard = network_guard or OutboundNetworkGuard()
        self.dlp = dlp_engine or DataLossPreventionEngine()
        self.memory_guard = memory_guard or MemoryGuard()
        self.honeytoken = honeytoken_manager or HoneytokenManager()
        self.action_graph = action_graph or ActionDependencyGraph()
        self.risk_engine = risk_engine or RiskEngine()
        self.consensus_gate = consensus_gate or DualAgentConsensusGate()
        self.sandbox = sandbox or IsolatedCodeSandbox()
        self.circuit_breaker = circuit_breaker or AgentCircuitBreaker()
        self.declarative_policy = declarative_policy or DeclarativePolicyEngine()
        self.identity_manager = identity_manager or AgentIdentityManager()
        self.data_lineage = data_lineage or DataLineageTracker()
        self.behavioral_guard = behavioral_guard or BehavioralGuard()

        self.high_impact_write_tools = set(self.HIGH_IMPACT_WRITE_TOOLS)
        if custom_high_impact_tools:
            self.high_impact_write_tools.update(custom_high_impact_tools)

        self.read_only_tools = set(self.READ_ONLY_TOOLS)
        if custom_read_only_tools:
            self.read_only_tools.update(custom_read_only_tools)

        # Regex patterns for detecting data exfiltration and image tags
        self._exfil_regex = re.compile(
            r"https?://[^\s\"']+\?[^\s\"']*(token|key|secret|auth|session|pass|leak|exfil|dump|q=)",
            re.IGNORECASE,
        )
        self._image_tag_regex = re.compile(r"!\[.*?\]\(.*?\)", re.IGNORECASE)
        self._url_regex = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

        self._encoder: Optional[SentenceTransformer] = None
        if not lazy_load:
            self._init_encoder()

    def _init_encoder(self) -> None:
        """Load SentenceTransformer embedding model."""
        if self._encoder is not None:
            return
        try:
            self._encoder = SentenceTransformer(self.model_name, device=self.device)
            logger.info("PolicyGate loaded embedding model '%s' on %s", self.model_name, self.device)
        except Exception as e:
            logger.error("Failed to load SentenceTransformer '%s': %s", self.model_name, e)
            raise RuntimeError(f"Could not initialize PolicyGate encoder '{self.model_name}': {e}") from e

    @property
    def encoder(self) -> SentenceTransformer:
        """Lazy-loaded SentenceTransformer encoder."""
        if self._encoder is None:
            self._init_encoder()
        return self._encoder

    def compute_similarity(self, text_a: str, text_b: str) -> float:
        """Compute normalized cosine similarity between two text snippets using dense embeddings."""
        if not text_a or not text_b or not isinstance(text_a, str) or not isinstance(text_b, str):
            return 0.0

        str_a = text_a.strip()
        str_b = text_b.strip()
        if not str_a or not str_b:
            return 0.0

        embeddings = self.encoder.encode(
            [str_a, str_b],
            convert_to_numpy=True,
            normalize_embeddings=False,
            show_progress_bar=False,
        )

        vec_a = embeddings[0]
        vec_b = embeddings[1]

        norm_a = np.linalg.norm(vec_a)
        norm_b = np.linalg.norm(vec_b)

        if norm_a == 0 or norm_b == 0:
            return 0.0

        cos_sim = float(np.dot(vec_a, vec_b) / (norm_a * norm_b))
        return float(np.clip(cos_sim, -1.0, 1.0))

    def _extract_all_urls(self, obj: Any) -> List[str]:
        """Recursively scan arguments dictionary for URLs."""
        urls: List[str] = []
        if isinstance(obj, str):
            for match in self._url_regex.finditer(obj):
                urls.append(match.group(0))
        elif isinstance(obj, dict):
            for v in obj.values():
                urls.extend(self._extract_all_urls(v))
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                urls.extend(self._extract_all_urls(item))
        return urls

    def evaluate_tool_call(
        self,
        session: SessionContext,
        tool_proposal: ToolCallProposal,
        detector_scan: Optional[ScanResult] = None,
    ) -> PolicyDecision:
        """Evaluate a proposed tool invocation across all security dimensions.

        Enforces:
        0. Circuit breaker cascading isolation & step limit check
        0b. Declarative role-based capability permissions
        0c. Behavioral anomaly guard state rules (read-to-egress, reconnaissance, flood loops)
        1. Honeytoken canary tripwire check
        2. Field-level data lineage & argument taint verification
        3. Outbound network guard & SSRF IP validation
        4. Behavioral action dependency graph check
        5. Data Loss Prevention (DLP) secret & PII inspection
        6. Static AST analysis for code execution tools
        7. Strict capability enforcement under tainted session
        8. Dual-agent consensus evaluation for high-impact actions
        9. Multi-factor quantitative risk scoring & tri-state decision

        Returns:
            Deterministic PolicyDecision model.
        """
        try:
            return self._evaluate_tool_call_internal(session, tool_proposal, detector_scan)
        except Exception as e:
            logger.error("Fail-Closed trigger in PolicyGate: %s", e, exc_info=True)
            return PolicyDecision(
                verdict=PolicyVerdict.BLOCK.value,
                reason=f"Fail-Closed trigger: {str(e)}",
                intent_similarity_score=0.0,
                blast_radius_contained=True,
                network_verdict="FAIL_CLOSED",
                risk_score=1.0,
            )

    def _evaluate_tool_call_internal(
        self,
        session: SessionContext,
        tool_proposal: ToolCallProposal,
        detector_scan: Optional[ScanResult] = None,
    ) -> PolicyDecision:
        """Internal execution pipeline for deterministic tool validation."""
        tool_name = tool_proposal.tool_name.lower().strip()
        args = tool_proposal.arguments or {}
        serialized_args = json.dumps(args, sort_keys=True)
        action_description = f"{tool_proposal.tool_name} with arguments {serialized_args}"

        is_tainted = session.is_session_tainted()

        # Step 0: Circuit Breaker Cascade Isolation Check & Step Counter
        self.circuit_breaker.record_step(session.session_id)
        if self.circuit_breaker.is_tripped(session.session_id):
            metrics = self.circuit_breaker.get_metrics(session.session_id)
            trip_reason = metrics.get("trip_reason") or "CIRCUIT_BREAKER_TRIPPED"
            return PolicyDecision(
                verdict=PolicyVerdict.BLOCK.value,
                reason=f"Circuit Breaker Quarantined: {trip_reason}",
                intent_similarity_score=0.0,
                blast_radius_contained=True,
                dlp_violations=[],
                network_verdict="PASS",
                risk_score=1.0,
            )

        # Step 1: Pre-scan arguments for DLP violations & Canary Tokens
        _, dlp_violations = self.dlp.sanitize_tool_args(args)
        is_canary_tripped, canary_id = self.honeytoken.check_exfiltration(serialized_args)

        inferred_cap = self.capability_registry.infer_capability(tool_name, args)
        if tool_proposal.inferred_capability != Capability.READ_PUBLIC:
            capability = tool_proposal.inferred_capability
        else:
            capability = inferred_cap

        similarity = self.compute_similarity(session.user_root_intent, action_description)
        is_detector_miss = bool(detector_scan.is_safe) if detector_scan is not None else True
        detector_confidence = (
            (1.0 - detector_scan.confidence_score)
            if (detector_scan and detector_scan.is_safe)
            else (detector_scan.confidence_score if detector_scan else (0.9 if is_tainted else 0.0))
        )

        # Step 0b: Declarative Role Policy Enforcement
        role = getattr(session, "role", None) or getattr(tool_proposal, "role", None)
        if role:
            role_allowed, role_reason = self.declarative_policy.evaluate_role_permission(
                role, capability
            )
            if not role_allowed:
                self.circuit_breaker.record_policy_violation(session.session_id)
                return PolicyDecision(
                    verdict=PolicyVerdict.BLOCK.value,
                    reason=f"Declarative Policy Violation: {role_reason}",
                    intent_similarity_score=round(similarity, 4),
                    blast_radius_contained=is_detector_miss,
                    dlp_violations=dlp_violations,
                    network_verdict="PASS",
                    risk_score=1.0,
                )

        # Step 0c: Behavioral Anomaly Guard Evaluation
        beh_state, beh_score, beh_rules = self.behavioral_guard.evaluate_action_step(
            session_id=session.session_id,
            proposed_capability=capability,
            proposed_tool=tool_name,
            user_intent=session.user_root_intent,
        )

        # Step 0d: Field-Level Data Lineage Inspection
        session_lineage = getattr(session, "field_lineage", {})
        arg_trust_map = self.data_lineage.inspect_tool_arguments(args, session_lineage)
        field_violations = [
            arg_name
            for arg_name, trust in arg_trust_map.items()
            if trust in (FieldTrustLevel.UNTRUSTED, FieldTrustLevel.DERIVED_UNTRUSTED)
        ]

        # If behavioral anomaly is CRITICAL -> immediate block override
        if beh_state == BehavioralState.CRITICAL:
            self.circuit_breaker.record_policy_violation(session.session_id)
            return PolicyDecision(
                verdict=PolicyVerdict.BLOCK.value,
                reason=f"Blocked by Behavioral Guard (Rule: {'; '.join(beh_rules)}, Anomaly Score: {beh_score:.2f})",
                intent_similarity_score=round(similarity, 4),
                blast_radius_contained=is_detector_miss,
                dlp_violations=dlp_violations,
                network_verdict="PASS",
                risk_score=1.0,
                behavioral_state=beh_state.value,
                behavioral_score=beh_score,
                field_lineage_violations=field_violations,
            )

        # If a sensitive or state-mutating tool receives an UNTRUSTED/DERIVED argument -> block via field lineage
        if field_violations and capability not in (Capability.READ_PUBLIC, Capability.READ_PRIVATE) and is_tainted:
            self.circuit_breaker.record_policy_violation(session.session_id)
            return PolicyDecision(
                verdict=PolicyVerdict.BLOCK.value,
                reason=f"Field-Level Taint Violation: Argument '{field_violations[0]}' contains untrusted data origin.",
                intent_similarity_score=round(similarity, 4),
                blast_radius_contained=is_detector_miss,
                dlp_violations=dlp_violations,
                network_verdict="PASS",
                risk_score=1.0,
                behavioral_state=beh_state.value,
                behavioral_score=beh_score,
                field_lineage_violations=field_violations,
            )

        # Step 2: Canary Honeypot Tripwire Check (Immediate Override -> BLOCK)
        if is_canary_tripped:
            self.circuit_breaker.record_policy_violation(session.session_id)
            return PolicyDecision(
                verdict=PolicyVerdict.BLOCK.value,
                reason=f"Honeypot Canary Tripwire: Attempted exfiltration of active canary token '{canary_id}'.",
                intent_similarity_score=round(similarity, 4),
                blast_radius_contained=is_detector_miss,
                dlp_violations=dlp_violations,
                network_verdict="PASS",
                risk_score=1.0,
                canary_tripped=True,
                behavioral_state=beh_state.value,
                behavioral_score=beh_score,
                field_lineage_violations=field_violations,
            )

        # Step 3: Untainted session check
        if not is_tainted and not field_violations and beh_state == BehavioralState.NORMAL:
            self.action_graph.record_node(session.session_id, capability, args)
            self.circuit_breaker.record_success(session.session_id)
            return PolicyDecision(
                verdict=PolicyVerdict.ALLOW.value,
                reason="Safe tool execution: Session is untainted with verified user provenance.",
                intent_similarity_score=1.0,
                blast_radius_contained=False,
                dlp_violations=dlp_violations,
                network_verdict="PASS",
                risk_score=0.0,
                behavioral_state=beh_state.value,
                behavioral_score=beh_score,
                field_lineage_violations=[],
            )

        # Step 4: Outbound Network Guard & SSRF Protection
        candidate_urls = self._extract_all_urls(args)
        if tool_proposal.target_destination:
            candidate_urls.extend(self._extract_all_urls(tool_proposal.target_destination))
            if tool_proposal.target_destination.startswith(("http://", "https://")):
                candidate_urls.append(tool_proposal.target_destination)

        for k, v in args.items():
            if isinstance(v, str) and any(
                kw in v for kw in ["http://", "https://", "169.254", "192.168", "10.", "127.0.0.1", "localhost"]
            ):
                candidate_urls.extend(self._extract_all_urls(v))

        for url in candidate_urls:
            is_valid, net_reason = self.network_guard.validate_url(url)
            if not is_valid:
                net_verdict = (
                    "BLOCKED_SSRF"
                    if (
                        "SSRF" in net_reason
                        or "private" in net_reason.lower()
                        or "loopback" in net_reason.lower()
                        or "metadata" in net_reason.lower()
                    )
                    else "BLOCKED_DISALLOWED_DOMAIN"
                )
                return PolicyDecision(
                    verdict=PolicyVerdict.BLOCK.value,
                    reason=f"Network guard violation: {net_reason}",
                    intent_similarity_score=round(similarity, 4),
                    blast_radius_contained=is_detector_miss,
                    dlp_violations=dlp_violations,
                    network_verdict=net_verdict,
                    risk_score=1.0,
                    behavioral_state=beh_state.value,
                    behavioral_score=beh_score,
                    field_lineage_violations=field_violations,
                )

        # HTTP method and payload size validation
        http_method = str(args.get("method", "GET"))
        is_valid_req, req_reason = self.network_guard.validate_request(
            method=http_method,
            payload_size_bytes=len(serialized_args.encode("utf-8")),
            is_tainted=is_tainted,
        )
        if not is_valid_req:
            return PolicyDecision(
                verdict=PolicyVerdict.BLOCK.value,
                reason=f"Network method/egress violation: {req_reason}",
                intent_similarity_score=round(similarity, 4),
                blast_radius_contained=is_detector_miss,
                dlp_violations=dlp_violations,
                network_verdict="BLOCKED_METHOD",
                risk_score=1.0,
                behavioral_state=beh_state.value,
                behavioral_score=beh_score,
                field_lineage_violations=field_violations,
            )

        # Step 5: Behavioral Action Dependency Graph Evaluation
        is_valid_trans, trans_reason = self.action_graph.evaluate_transition(
            session.session_id, capability, is_tainted=is_tainted
        )
        if not is_valid_trans:
            return PolicyDecision(
                verdict=PolicyVerdict.BLOCK.value,
                reason=trans_reason,
                intent_similarity_score=round(similarity, 4),
                blast_radius_contained=is_detector_miss,
                dlp_violations=dlp_violations,
                network_verdict="PASS",
                risk_score=1.0,
                action_transition_valid=False,
                behavioral_state=beh_state.value,
                behavioral_score=beh_score,
                field_lineage_violations=field_violations,
            )

        # Step 6: Data Loss Prevention (DLP) Inspection for Sensitive Secrets & PII
        critical_dlp_violations = [
            v for v in dlp_violations if v not in {"Email Address", "Phone Number"}
        ]
        if critical_dlp_violations and is_tainted:
            return PolicyDecision(
                verdict=PolicyVerdict.BLOCK.value,
                reason=f"DLP block: attempted exfiltration of {', '.join(critical_dlp_violations)}.",
                intent_similarity_score=round(similarity, 4),
                blast_radius_contained=is_detector_miss,
                dlp_violations=dlp_violations,
                network_verdict="PASS",
                risk_score=1.0,
                behavioral_state=beh_state.value,
                behavioral_score=beh_score,
                field_lineage_violations=field_violations,
            )

        # Step 7: Static AST Analysis for Code Execution Proposals
        if capability == Capability.EXECUTE_CODE:
            code_payload = str(args.get("code") or args.get("script") or args.get("command") or "")
            if code_payload:
                is_safe_ast, ast_violation = self.sandbox.inspect_ast(code_payload)
                if not is_safe_ast:
                    return PolicyDecision(
                        verdict=PolicyVerdict.BLOCK.value,
                        reason=f"Code Sandbox AST Violation: {ast_violation}",
                        intent_similarity_score=round(similarity, 4),
                        blast_radius_contained=is_detector_miss,
                        dlp_violations=dlp_violations,
                        network_verdict="PASS",
                        risk_score=1.0,
                        behavioral_state=beh_state.value,
                        behavioral_score=beh_score,
                        field_lineage_violations=field_violations,
                    )

        # Step 8: Strict Capability Enforcement for Critical Operations & High Drift
        if not self.capability_registry.is_allowed_for_tainted_session(capability):
            if capability in {
                Capability.EXECUTE_CODE,
                Capability.ADMIN,
                Capability.FINANCIAL_ACTION,
            } or (
                similarity < self.SIMILARITY_THRESHOLD
                and capability in {
                    Capability.WRITE_DATABASE,
                    Capability.WRITE_FILE,
                    Capability.NETWORK_EXTERNAL,
                    Capability.SEND_EXTERNAL_MESSAGE,
                    Capability.READ_PRIVATE,
                }
            ):
                return PolicyDecision(
                    verdict=PolicyVerdict.BLOCK.value,
                    reason=(
                        f"Capability violation: {capability.value} denied for tainted session "
                        f"(intent similarity: {similarity:.4f} < threshold: {self.SIMILARITY_THRESHOLD})."
                    ),
                    intent_similarity_score=round(similarity, 4),
                    blast_radius_contained=is_detector_miss,
                    dlp_violations=dlp_violations,
                    network_verdict="PASS",
                    risk_score=0.90,
                    behavioral_state=beh_state.value,
                    behavioral_score=beh_score,
                    field_lineage_violations=field_violations,
                )

        # Step 9: Data Exfiltration Channels & Semantic Divergence
        has_exfil_channel = bool(self._exfil_regex.search(serialized_args))
        has_image_exfil = bool(self._image_tag_regex.search(serialized_args))
        unauthorized_url_egress = bool(
            self._url_regex.search(serialized_args)
            and not self._url_regex.search(session.user_root_intent)
            and similarity < self.SIMILARITY_THRESHOLD
        )

        if has_exfil_channel or has_image_exfil or unauthorized_url_egress:
            return PolicyDecision(
                verdict=PolicyVerdict.BLOCK.value,
                reason=(
                    f"Data Exfiltration Channel: Tainted session attempting unauthorized external URL egress, "
                    f"markdown image exfiltration, or secret query parameter transmission via '{tool_proposal.tool_name}'."
                ),
                intent_similarity_score=round(similarity, 4),
                blast_radius_contained=is_detector_miss,
                dlp_violations=dlp_violations,
                network_verdict="PASS",
                risk_score=0.95,
                behavioral_state=beh_state.value,
                behavioral_score=beh_score,
                field_lineage_violations=field_violations,
            )

        # Step 10: Dual-Agent Consensus & Shadow Evaluator for High-Impact Actions
        consensus_approved: Optional[bool] = None
        consensus_details: Optional[dict[str, Any]] = None
        if self.consensus_gate.requires_consensus(capability):
            is_cns_ok, cns_reason, cns_details = self.consensus_gate.evaluate_consensus(
                user_intent=session.user_root_intent,
                proposed_tool=tool_proposal,
                session_context=session,
                primary_similarity_score=similarity,
            )
            consensus_approved = is_cns_ok
            consensus_details = cns_details
            if not is_cns_ok:
                return PolicyDecision(
                    verdict=PolicyVerdict.BLOCK.value,
                    reason=cns_reason,
                    intent_similarity_score=round(similarity, 4),
                    blast_radius_contained=is_detector_miss,
                    dlp_violations=dlp_violations,
                    network_verdict="PASS",
                    risk_score=0.95,
                    consensus_approved=False,
                    consensus_details=cns_details,
                    behavioral_state=beh_state.value,
                    behavioral_score=beh_score,
                    field_lineage_violations=field_violations,
                )

        # Step 11: Multi-Factor Risk Scoring and Tri-State Decision via RiskEngine
        risk_score, risk_verdict, breakdown = self.risk_engine.calculate_risk(
            detector_score=detector_confidence,
            is_tainted=is_tainted,
            capability=capability,
            intent_similarity=similarity,
            canary_tripped=False,
            transition_valid=True,
            security_override=False,
            behavioral_score=beh_score,
            behavioral_state=beh_state,
        )

        if risk_verdict == PolicyVerdict.REQUIRE_HUMAN_APPROVAL:
            return PolicyDecision(
                verdict=PolicyVerdict.REQUIRE_HUMAN_APPROVAL.value,
                reason=(
                    f"Elevated Risk Threshold (score: {risk_score:.2f}): Tool '{tool_proposal.tool_name}' "
                    f"requires human approval (intent similarity: {similarity:.2f})."
                ),
                intent_similarity_score=round(similarity, 4),
                blast_radius_contained=is_detector_miss,
                dlp_violations=dlp_violations,
                network_verdict="PASS",
                risk_score=risk_score,
                consensus_approved=consensus_approved,
                consensus_details=consensus_details,
                behavioral_state=beh_state.value,
                behavioral_score=beh_score,
                field_lineage_violations=field_violations,
            )

        if risk_verdict == PolicyVerdict.BLOCK:
            return PolicyDecision(
                verdict=PolicyVerdict.BLOCK.value,
                reason=(
                    f"Composite Risk Threshold Exceeded (score: {risk_score:.2f} >= {self.risk_engine.block_threshold}): "
                    f"Tool execution blocked."
                ),
                intent_similarity_score=round(similarity, 4),
                blast_radius_contained=is_detector_miss,
                dlp_violations=dlp_violations,
                network_verdict="PASS",
                risk_score=risk_score,
                consensus_approved=consensus_approved,
                consensus_details=consensus_details,
                behavioral_state=beh_state.value,
                behavioral_score=beh_score,
                field_lineage_violations=field_violations,
            )

        # Step 12: Safe Operation Permitted -> Record node in action graph
        self.action_graph.record_node(session.session_id, capability, args)
        return PolicyDecision(
            verdict=PolicyVerdict.ALLOW.value,
            reason=f"Safe operation: Tool '{tool_proposal.tool_name}' validated under capability, lineage, and taint controls.",
            intent_similarity_score=round(similarity, 4),
            blast_radius_contained=False,
            dlp_violations=dlp_violations,
            network_verdict="PASS",
            risk_score=risk_score,
            consensus_approved=consensus_approved,
            consensus_details=consensus_details,
            behavioral_state=beh_state.value,
            behavioral_score=beh_score,
            field_lineage_violations=[],
        )

    def execute_sandboxed_tool(self, code: str, timeout_sec: Optional[float] = None) -> dict[str, Any]:
        """Execute Python code in the ephemeral isolated sandbox environment."""
        return self.sandbox.execute_sandboxed(code, timeout_sec=timeout_sec)
