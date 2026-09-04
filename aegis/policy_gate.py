"""Deterministic policy gate and semantic intent alignment engine for AegisAgent.

Prevents the "Lethal Trifecta" (untrusted data + execution tools + private access)
by validating tool proposals against verified user root intent using dense semantic similarity.
"""

import json
import logging
import re
from typing import List, Optional, Set

import numpy as np
import torch
from sentence_transformers import SentenceTransformer

from aegis.taint import SessionContext
from aegis.types import PolicyDecision, PolicyVerdict, ScanResult, ToolCallProposal, ToolPrivilege

logger = logging.getLogger(__name__)


class PolicyGate:
    """Deterministic security gate evaluating tool call proposals against session trust state."""

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
    ) -> None:
        """Initialize PolicyGate with embedding model and registered tool categories.

        Args:
            model_name: SentenceTransformers model identifier.
            device: Target torch device ('cuda', 'cpu'). Auto-selected if None.
            lazy_load: If True, defer model loading until first similarity computation.
            custom_high_impact_tools: Additional high-impact write tools to register.
            custom_read_only_tools: Additional read-only tools to register.
        """
        self.model_name = model_name
        if device is None:
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
        else:
            self.device = device

        self.high_impact_write_tools = set(self.HIGH_IMPACT_WRITE_TOOLS)
        if custom_high_impact_tools:
            self.high_impact_write_tools.update(custom_high_impact_tools)

        self.read_only_tools = set(self.READ_ONLY_TOOLS)
        if custom_read_only_tools:
            self.read_only_tools.update(custom_read_only_tools)

        self._exfil_regex = re.compile(
            r"https?://[^\s\"']+\?[^\s\"']*(token|key|secret|auth|session|pass|leak|exfil|dump|q=)",
            re.IGNORECASE,
        )
        self._url_regex = re.compile(r"https?://", re.IGNORECASE)

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
        """Compute cosine similarity between two text snippets using dense embeddings.

        Args:
            text_a: First text string (e.g. user root intent).
            text_b: Second text string (e.g. tool execution description).

        Returns:
            Cosine similarity score in range [-1.0, 1.0].
        """
        if not text_a or not text_b:
            return 0.0

        embeddings = self.encoder.encode(
            [text_a, text_b],
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        # Since embeddings are normalized, cosine similarity is the dot product
        similarity = float(np.dot(embeddings[0], embeddings[1]))
        return max(-1.0, min(1.0, similarity))

    def evaluate_tool_call(
        self,
        session: SessionContext,
        tool_proposal: ToolCallProposal,
        detector_scan: Optional[ScanResult] = None,
    ) -> PolicyDecision:
        """Evaluate a proposed tool call against session taint state and intent alignment.

        Args:
            session: Active agent execution context containing root intent and taint state.
            tool_proposal: Proposed tool name and arguments.
            detector_scan: Optional upstream prompt injection scan result.

        Returns:
            Deterministic PolicyDecision model.
        """
        tool_name = tool_proposal.tool_name.lower().strip()
        is_high_impact = tool_name in self.high_impact_write_tools

        # Rule 1: Untainted session check
        if not session.is_session_tainted():
            return PolicyDecision(
                verdict=PolicyVerdict.ALLOW.value,
                reason="Safe tool execution: Session is untainted with verified user provenance.",
                intent_similarity_score=1.0,
                blast_radius_contained=False,
            )

        serialized_args = json.dumps(tool_proposal.arguments, sort_keys=True)
        action_description = f"{tool_proposal.tool_name} with arguments {serialized_args}"
        similarity = self.compute_similarity(session.user_root_intent, action_description)

        # Rule 2: Tainted Lethal Trifecta check (high impact write tools)
        if session.is_session_tainted() and is_high_impact:
            if similarity < self.SIMILARITY_THRESHOLD:
                blast_contained = bool(detector_scan.is_safe) if detector_scan is not None else False
                return PolicyDecision(
                    verdict=PolicyVerdict.BLOCK.value,
                    reason=(
                        f"Lethal Trifecta: Tainted session attempting unauthorized high-impact tool '{tool_proposal.tool_name}' "
                        f"(similarity score: {similarity:.4f} < threshold: {self.SIMILARITY_THRESHOLD})."
                    ),
                    intent_similarity_score=round(similarity, 4),
                    blast_radius_contained=blast_contained,
                )

            return PolicyDecision(
                verdict=PolicyVerdict.ALLOW.value,
                reason=(
                    f"Authorized high-impact tool: Action '{tool_proposal.tool_name}' aligned with "
                    f"user root intent (similarity: {similarity:.4f} >= {self.SIMILARITY_THRESHOLD})."
                ),
                intent_similarity_score=round(similarity, 4),
                blast_radius_contained=False,
            )

        # Rule 3: Check for data exfiltration channels in read-only / passive tools under tainted session
        has_exfil_channel = bool(self._exfil_regex.search(serialized_args))
        unauthorized_url_egress = bool(
            self._url_regex.search(serialized_args)
            and not self._url_regex.search(session.user_root_intent)
            and similarity < self.SIMILARITY_THRESHOLD
        )

        if has_exfil_channel or unauthorized_url_egress:
            blast_contained = bool(detector_scan.is_safe) if detector_scan is not None else False
            return PolicyDecision(
                verdict=PolicyVerdict.BLOCK.value,
                reason=(
                    f"Data Exfiltration Channel: Tainted session attempting unauthorized external URL egress "
                    f"or secret query parameter exfiltration via '{tool_proposal.tool_name}'."
                ),
                intent_similarity_score=round(similarity, 4),
                blast_radius_contained=blast_contained,
            )

        # Rule 4: Safe passive read-only tool invocation
        return PolicyDecision(
            verdict=PolicyVerdict.ALLOW.value,
            reason=f"Safe passive operation: Read-only tool '{tool_proposal.tool_name}' permitted under tainted context.",
            intent_similarity_score=round(similarity, 4),
            blast_radius_contained=False,
        )
