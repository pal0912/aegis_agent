"""Deterministic policy gate, capability enforcement, and egress control engine for AegisAgent V2.

Prevents the "Lethal Trifecta" (untrusted data + execution tools + private access),
enforces fine-grained operational capabilities, prevents SSRF / private network egress,
and intercepts data loss / secret exfiltration attempts.
"""

import json
import logging
import re
from typing import Any, List, Optional, Set

import numpy as np
import torch
from sentence_transformers import SentenceTransformer

from aegis.capabilities import CapabilityRegistry
from aegis.dlp import DataLossPreventionEngine
from aegis.network_guard import OutboundNetworkGuard
from aegis.taint import SessionContext
from aegis.types import (
    Capability,
    PolicyDecision,
    PolicyVerdict,
    ScanResult,
    ToolCallProposal,
    ToolPrivilege,
)

logger = logging.getLogger(__name__)


class PolicyGate:
    """Deterministic security gate evaluating tool call proposals against capabilities and session trust state."""

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
    ) -> None:
        """Initialize PolicyGate with embedding model, capability registry, network guard, and DLP.

        Args:
            model_name: SentenceTransformers model identifier.
            device: Target torch device ('cuda', 'cpu'). Auto-selected if None.
            lazy_load: If True, defer model loading until first similarity computation.
            custom_high_impact_tools: Additional high-impact write tools to register.
            custom_read_only_tools: Additional read-only tools to register.
            capability_registry: Custom CapabilityRegistry instance.
            network_guard: Custom OutboundNetworkGuard instance.
            dlp_engine: Custom DataLossPreventionEngine instance.
        """
        self.model_name = model_name
        if device is None:
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
        else:
            self.device = device

        self.capability_registry = capability_registry or CapabilityRegistry()
        self.network_guard = network_guard or OutboundNetworkGuard()
        self.dlp = dlp_engine or DataLossPreventionEngine()

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

        norm_a = float(np.linalg.norm(vec_a))
        norm_b = float(np.linalg.norm(vec_b))

        if norm_a < 1e-9 or norm_b < 1e-9:
            return 0.0

        cosine_sim = float(np.dot(vec_a, vec_b) / (norm_a * norm_b))
        return float(np.clip(cosine_sim, -1.0, 1.0))

    def _extract_all_urls(self, obj: Any) -> List[str]:
        """Recursively extract all URL strings from tool arguments or structures."""
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
        """Evaluate a proposed tool call through capability arbitration, network guard, DLP, and semantic alignment.

        Fails closed on any unexpected exception.

        Args:
            session: Active agent execution context containing root intent and taint state.
            tool_proposal: Proposed tool name and arguments.
            detector_scan: Optional upstream prompt injection scan result.

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

        # Pre-scan arguments for DLP violations
        _, dlp_violations = self.dlp.sanitize_tool_args(args)

        # Step 1: Untainted session fast-path check
        if not is_tainted:
            return PolicyDecision(
                verdict=PolicyVerdict.ALLOW.value,
                reason="Safe tool execution: Session is untainted with verified user provenance.",
                intent_similarity_score=1.0,
                blast_radius_contained=False,
                dlp_violations=dlp_violations,
                network_verdict="PASS",
            )

        inferred_cap = self.capability_registry.infer_capability(tool_name, args)
        if tool_proposal.inferred_capability != Capability.READ_PUBLIC:
            capability = tool_proposal.inferred_capability
        else:
            capability = inferred_cap

        similarity = self.compute_similarity(session.user_root_intent, action_description)
        is_detector_miss = bool(detector_scan.is_safe) if detector_scan is not None else True

        # Step 2: Data Loss Prevention (DLP) Inspection
        if dlp_violations and is_tainted:
            return PolicyDecision(
                verdict=PolicyVerdict.BLOCK.value,
                reason=f"DLP block: attempted exfiltration of {', '.join(dlp_violations)}.",
                intent_similarity_score=round(similarity, 4),
                blast_radius_contained=is_detector_miss,
                dlp_violations=dlp_violations,
                network_verdict="PASS",
            )

        # Step 3: Outbound Network Guard & SSRF Protection
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
            )

        # Step 4: Capability Enforcement
        if not self.capability_registry.is_allowed_for_tainted_session(capability):
            if similarity < self.SIMILARITY_THRESHOLD or capability in {
                Capability.EXECUTE_CODE,
                Capability.WRITE_DATABASE,
                Capability.ADMIN,
                Capability.FINANCIAL_ACTION,
                Capability.WRITE_FILE,
                Capability.NETWORK_EXTERNAL,
                Capability.SEND_EXTERNAL_MESSAGE,
            }:
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
                )

        # Step 5: Data Exfiltration Channels & Semantic Divergence
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
            )

        # High-impact tool semantic alignment check
        is_high_impact = tool_name in self.high_impact_write_tools
        if is_high_impact and similarity < self.SIMILARITY_THRESHOLD:
            return PolicyDecision(
                verdict=PolicyVerdict.BLOCK.value,
                reason=(
                    f"Lethal Trifecta: Tainted session attempting unauthorized high-impact tool '{tool_proposal.tool_name}' "
                    f"(similarity score: {similarity:.4f} < threshold: {self.SIMILARITY_THRESHOLD})."
                ),
                intent_similarity_score=round(similarity, 4),
                blast_radius_contained=is_detector_miss,
                dlp_violations=dlp_violations,
                network_verdict="PASS",
            )

        # Step 6: Safe Operation Permitted
        return PolicyDecision(
            verdict=PolicyVerdict.ALLOW.value,
            reason=f"Safe operation: Tool '{tool_proposal.tool_name}' validated under capability and taint controls.",
            intent_similarity_score=round(similarity, 4),
            blast_radius_contained=False,
            dlp_violations=dlp_violations,
            network_verdict="PASS",
        )
