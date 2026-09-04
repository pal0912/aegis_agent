"""Core type definitions and Pydantic v2 data models for AegisAgent.

Enterprise-grade defense-in-depth security middleware and deterministic policy gate.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Optional
import hashlib
from pydantic import BaseModel, ConfigDict, Field, field_validator


class TrustLevel(str, Enum):
    """Represents the provenance and trustworthiness level of an ingested input payload."""

    TRUSTED = "TRUSTED"  # Direct, verified user prompt instructions.
    UNTRUSTED = "UNTRUSTED"  # Retrieved third-party context (web, PDF, emails, APIs).
    QUARANTINED = "QUARANTINED"  # Content flagged as an active exploit payload.


class ToolPrivilege(str, Enum):
    """Categorizes tools based on risk level and state mutation capacity."""

    READ_ONLY = "READ_ONLY"  # Passive tools (e.g., search, fetch_doc, read_db).
    HIGH_IMPACT_WRITE = "HIGH_IMPACT_WRITE"  # Destructive or state-mutating tools (e.g., execute_shell, send_email, write_db, transfer_funds).


class PolicyVerdict(str, Enum):
    """Deterministic policy gate verdicts."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ESCALATE_TO_HUMAN = "ESCALATE_TO_HUMAN"


class ScanResult(BaseModel):
    """Output metrics and findings from multi-layer prompt injection & exploit scanners."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    is_safe: bool = Field(
        ...,
        description="True if the scanned content passed all safety checks without exploit signals.",
    )
    confidence_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score between 0.0 and 1.0 indicating safety probability.",
    )
    reasons: List[str] = Field(
        default_factory=list,
        description="Detailed list of detected anomalies, heuristic violations, or safety reasons.",
    )
    latency_ms: float = Field(
        ...,
        ge=0.0,
        description="Execution latency of the scanning phase in milliseconds.",
    )
    tokens_analyzed: int = Field(
        ...,
        ge=0,
        description="Total token or unit count analyzed during the scan.",
    )
    detected_heuristics: List[str] = Field(
        default_factory=list,
        description="Specific heuristic rules or signature names triggered during inspection.",
    )


class ToolCallProposal(BaseModel):
    """Proposed tool call invocation emitted by an autonomous agent."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_name: str = Field(
        ...,
        min_length=1,
        description="Identifier of the proposed tool to be invoked.",
    )
    arguments: dict[str, Any] = Field(
        default_factory=dict,
        description="Dictionary of parameters and arguments supplied for tool invocation.",
    )
    source_trace_id: str = Field(
        ...,
        min_length=1,
        description="Trace identifier of the source context that triggered this tool call.",
    )


class PolicyDecision(BaseModel):
    """Deterministic policy gate decision evaluating agent tool execution requests."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    verdict: str = Field(
        ...,
        description="Policy gate decision verdict: 'ALLOW', 'BLOCK', or 'ESCALATE_TO_HUMAN'.",
    )
    reason: str = Field(
        ...,
        description="Deterministic justification for the policy decision.",
    )
    intent_similarity_score: float = Field(
        ...,
        description="Cosine similarity or alignment score between authorized user intent and proposed action.",
    )
    blast_radius_contained: bool = Field(
        ...,
        description="True if detector missed the injection, but PolicyGate blocked unauthorized tool execution.",
    )

    @field_validator("verdict")
    @classmethod
    def validate_verdict(cls, v: str) -> str:
        valid = {verdict.value for verdict in PolicyVerdict}
        if v not in valid:
            raise ValueError(f"verdict must be one of {sorted(valid)}, got '{v}'")
        return v


class AuditEvent(BaseModel):
    """Immutable audit record logging ingestion, scanning, and policy enforcement decisions."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of the audit event.",
    )
    trace_id: str = Field(
        ...,
        min_length=1,
        description="Unique distributed tracing identifier for correlating execution flow.",
    )
    trust_level: TrustLevel = Field(
        ...,
        description="Assigned trust classification of the evaluated payload.",
    )
    raw_content_sha256: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="SHA-256 cryptographic hash of raw content (raw payload is never stored unhashed).",
    )
    scan_result: Optional[ScanResult] = Field(
        default=None,
        description="Scan result details if scanning was performed.",
    )
    policy_decision: Optional[PolicyDecision] = Field(
        default=None,
        description="Policy gate decision if tool execution evaluation was conducted.",
    )

    @staticmethod
    def hash_payload(payload: str) -> str:
        """Utility helper to generate canonical SHA-256 hash for raw content."""
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
