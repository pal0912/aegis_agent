"""Unified risk scoring engine and human-in-the-loop (HITL) gating for AegisAgent V2.

Computes composite multi-factor risk scores combining neural injection metrics,
provenance taint status, capability severity, and semantic alignment to drive tri-state authorization.
"""

import logging
from typing import Any, Dict, Optional, Tuple

from aegis.types import Capability, PolicyVerdict

logger = logging.getLogger(__name__)


class RiskEngine:
    """Multi-factor quantitative risk scoring engine determining tri-state policy decisions."""

    # Component weights summing to 1.0
    W_DETECTOR = 0.35
    W_TAINT = 0.20
    W_CAPABILITY = 0.25
    W_SEMANTIC = 0.20

    # Decision thresholds
    ALLOW_THRESHOLD = 0.40
    BLOCK_THRESHOLD = 0.75

    # Capability Severity Weights
    CAPABILITY_SEVERITY: Dict[Capability, float] = {
        Capability.READ_PUBLIC: 0.10,
        Capability.READ_PRIVATE: 0.50,
        Capability.WRITE_FILE: 0.70,
        Capability.WRITE_DATABASE: 0.70,
        Capability.NETWORK_EXTERNAL: 0.85,
        Capability.SEND_EXTERNAL_MESSAGE: 0.85,
        Capability.EXECUTE_CODE: 1.00,
        Capability.ADMIN: 1.00,
        Capability.FINANCIAL_ACTION: 1.00,
    }

    def __init__(
        self,
        allow_threshold: float = ALLOW_THRESHOLD,
        block_threshold: float = BLOCK_THRESHOLD,
    ) -> None:
        """Initialize RiskEngine with configurable decision boundaries."""
        self.allow_threshold = allow_threshold
        self.block_threshold = block_threshold

    def calculate_risk(
        self,
        detector_score: float,
        is_tainted: bool,
        capability: Capability,
        intent_similarity: float,
        canary_tripped: bool = False,
        transition_valid: bool = True,
        security_override: bool = False,
    ) -> Tuple[float, PolicyVerdict, Dict[str, float]]:
        """Compute composite risk score and determine tri-state authorization verdict.

        Formula:
            R = W1 * Detector + W2 * Taint + W3 * Capability_Severity + W4 * (1.0 - Intent_Similarity)

        Args:
            detector_score: Injection confidence score [0.0, 1.0].
            is_tainted: True if session contains untrusted external input.
            capability: Requested operational Capability.
            intent_similarity: Cosine similarity between user root intent and action [-1.0, 1.0].
            canary_tripped: True if a honeypot canary trap was accessed or exfiltrated.
            transition_valid: True if action dependency graph transition is valid.
            security_override: True if hard security violation (SSRF, DLP) was triggered.

        Returns:
            Tuple of (composite_risk_score: float, verdict: PolicyVerdict, component_breakdown: dict).
        """
        # 1. Hard Security Overrides (Immediate Force to 1.0 Risk -> BLOCK)
        if canary_tripped or not transition_valid or security_override:
            breakdown = {
                "detector_component": self.W_DETECTOR * max(0.0, min(1.0, detector_score)),
                "taint_component": self.W_TAINT * (1.0 if is_tainted else 0.0),
                "capability_component": self.W_CAPABILITY * self.CAPABILITY_SEVERITY.get(capability, 0.5),
                "semantic_component": self.W_SEMANTIC * (1.0 - max(0.0, min(1.0, intent_similarity))),
                "override_penalty": 1.0,
            }
            return 1.0, PolicyVerdict.BLOCK, breakdown

        # 2. Compute Individual Weighted Components
        norm_detector = max(0.0, min(1.0, detector_score))
        c_detector = self.W_DETECTOR * norm_detector

        taint_val = 1.0 if is_tainted else 0.0
        c_taint = self.W_TAINT * taint_val

        cap_severity = self.CAPABILITY_SEVERITY.get(capability, 0.50)
        c_capability = self.W_CAPABILITY * cap_severity

        norm_similarity = max(0.0, min(1.0, intent_similarity))
        semantic_distance = 1.0 - norm_similarity
        c_semantic = self.W_SEMANTIC * semantic_distance

        raw_score = c_detector + c_taint + c_capability + c_semantic
        risk_score = round(float(max(0.0, min(1.0, raw_score))), 4)

        breakdown = {
            "detector_component": round(c_detector, 4),
            "taint_component": round(c_taint, 4),
            "capability_component": round(c_capability, 4),
            "semantic_component": round(c_semantic, 4),
        }

        # 3. Tri-State Decision Mapping
        if risk_score < self.allow_threshold:
            verdict = PolicyVerdict.ALLOW
        elif risk_score < self.block_threshold:
            verdict = PolicyVerdict.REQUIRE_HUMAN_APPROVAL
        else:
            verdict = PolicyVerdict.BLOCK

        logger.debug("RiskEngine evaluated risk=%.4f -> verdict=%s", risk_score, verdict.value)
        return risk_score, verdict, breakdown
