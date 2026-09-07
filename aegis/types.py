"""Core type definitions and Pydantic v2 data models for AegisAgent V2.

Enterprise-grade defense-in-depth security middleware, capability-based security model,
outbound network guard, DLP engine, honeytoken traps, memory protection, and deterministic policy gate.
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field, field_validator


class TrustLevel(str, Enum):
    """Represents the provenance and trustworthiness level of an ingested input payload."""

    TRUSTED = "TRUSTED"  # Direct, verified user prompt instructions.
    UNTRUSTED = "UNTRUSTED"  # Retrieved third-party context (web, PDF, emails, APIs).
    QUARANTINED = "QUARANTINED"  # Content flagged as an active exploit payload.


class FieldTrustLevel(str, Enum):
    """Fine-grained field-level provenance trust classifications."""

    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    DERIVED_UNTRUSTED = "DERIVED_UNTRUSTED"


class FieldProvenance(BaseModel):
    """Detailed metadata and cryptographic signature for a specific data field or key-path."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(
        ...,
        description="Dot-delimited JSON-pointer keypath (e.g. 'response.data[0].notes').",
    )
    trust: FieldTrustLevel = Field(
        ...,
        description="Assigned field trust classification.",
    )
    source: str = Field(
        ...,
        description="Source identifier (e.g. 'user_prompt', 'web_search:url', 'database:users').",
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of field ingestion or transformation.",
    )
    value_hash: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="SHA-256 hash of the field value for mutation and substring tracking.",
    )


class BehavioralState(str, Enum):
    """Runtime behavioral anomaly states emitted by the behavioral guard engine."""

    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    ANOMALOUS = "ANOMALOUS"
    CRITICAL = "CRITICAL"



class ToolPrivilege(str, Enum):
    """Categorizes tools based on risk level and state mutation capacity."""

    READ_ONLY = "READ_ONLY"  # Passive tools (e.g., search, fetch_doc, read_db).
    HIGH_IMPACT_WRITE = "HIGH_IMPACT_WRITE"  # Destructive or state-mutating tools (e.g., execute_shell, send_email, write_db, transfer_funds).


class Capability(str, Enum):
    """Fine-grained capability-based security classifications for agent tools and actions."""

    READ_PUBLIC = "READ_PUBLIC"  # Public web browsing, open docs, weather.
    READ_PRIVATE = "READ_PRIVATE"  # Internal customer data, local files, internal DB reads, environment vars.
    WRITE_FILE = "WRITE_FILE"  # Creating or modifying local files.
    WRITE_DATABASE = "WRITE_DATABASE"  # Inserts, updates, deletes on any persistence store.
    SEND_EXTERNAL_MESSAGE = "SEND_EXTERNAL_MESSAGE"  # Outbound email, Slack, webhooks, SMS.
    EXECUTE_CODE = "EXECUTE_CODE"  # Shell execution (bash, sh, cmd, powershell), Python eval/exec, Docker commands.
    NETWORK_EXTERNAL = "NETWORK_EXTERNAL"  # Outbound HTTP/HTTPS requests, sockets.
    FINANCIAL_ACTION = "FINANCIAL_ACTION"  # Bank/wire transfers, credit card charges.
    ADMIN = "ADMIN"  # Modifying access controls, dropping tables, credential rotation.


class PolicyVerdict(str, Enum):
    """Tri-state deterministic policy gate verdicts."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"
    ESCALATE_TO_HUMAN = "REQUIRE_HUMAN_APPROVAL"


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
        default_factory=lambda: str(uuid.uuid4()),
        description="Trace identifier of the source context that triggered this tool call.",
    )
    inferred_capability: Capability = Field(
        default=Capability.READ_PUBLIC,
        description="Inferred or declared operational capability requested by this tool invocation.",
    )
    target_destination: Optional[str] = Field(
        default=None,
        description="Optional target destination: URL, file path, email address, IP host, or SQL resource.",
    )
    role: Optional[str] = Field(
        default=None,
        description="Optional role or identity of the agent issuing this proposal.",
    )


class PolicyDecision(BaseModel):
    """Deterministic policy gate decision evaluating agent tool execution requests."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    verdict: str = Field(
        ...,
        description="Policy gate decision verdict: 'ALLOW', 'BLOCK', or 'REQUIRE_HUMAN_APPROVAL'.",
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
    dlp_violations: List[str] = Field(
        default_factory=list,
        description="List of detected secret or PII leak violations intercepted by DLP.",
    )
    network_verdict: str = Field(
        default="PASS",
        description="Network guard evaluation verdict ('PASS', 'BLOCKED_SSRF', 'BLOCKED_DISALLOWED_DOMAIN', 'BLOCKED_METHOD').",
    )
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Unified composite risk score computed across neural, taint, capability, and semantic factors.",
    )
    canary_tripped: bool = Field(
        default=False,
        description="True if an active honeypot canary token was accessed or attempted to be exfiltrated.",
    )
    action_transition_valid: bool = Field(
        default=True,
        description="True if the proposed action transition satisfies the behavioral dependency graph.",
    )
    memory_rollback_triggered: bool = Field(
        default=False,
        description="True if tainted memory state was rolled back to a previous clean snapshot.",
    )
    consensus_approved: Optional[bool] = Field(
        default=None,
        description="True if dual-agent consensus evaluation was performed and approved.",
    )
    consensus_details: Optional[dict[str, Any]] = Field(
        default=None,
        description="Forensic evaluation breakdown from the shadow consensus evaluator.",
    )
    sandboxed_execution: Optional[dict[str, Any]] = Field(
        default=None,
        description="Details of ephemeral sandbox execution if code execution was invoked.",
    )
    behavioral_state: Optional[str] = Field(
        default=None,
        description="Assigned behavioral anomaly state ('NORMAL', 'SUSPICIOUS', 'ANOMALOUS', 'CRITICAL').",
    )
    behavioral_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Quantitative anomaly score computed by the behavioral guard.",
    )
    field_lineage_violations: List[str] = Field(
        default_factory=list,
        description="Specific argument paths flagged for carrying untrusted data origins.",
    )

    @field_validator("verdict")
    @classmethod
    def validate_verdict(cls, v: str) -> str:
        valid = {verdict.value for verdict in PolicyVerdict}
        if v not in valid:
            raise ValueError(f"verdict must be one of {sorted(valid)}, got '{v}'")
        return v


class MitreAtlasTechnique(str, Enum):
    """MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) matrix mappings."""

    LLM_PROMPT_INJECTION = "AML.T0051 (LLM Prompt Injection)"
    LLM_JAILBREAK = "AML.T0054 (LLM Jailbreak)"
    ML_RECONNAISSANCE = "AML.T0040 (ML Model/Service Reconnaissance)"
    CONTEXT_POISONING = "AML.T0018 (Backdoor ML Model/Context Poisoning)"
    EXFILTRATION_SIDE_CHANNELS = "AML.T0048 (Exfiltration via ML Model Side-Channels)"
    UNAUTHORIZED_COMMAND_EXECUTION = "AML.T0060 (Unauthorized Command Execution)"
    EVASION = "AML.T0015 (Evade ML Model)"
    CREDENTIAL_ACCESS = "AML.T0047 (Credential Access via ML Model)"


class MultiTierOutcome(str, Enum):
    """Multi-tier security evaluation outcome classifications for adaptive testing."""

    DETECTED = "DETECTED"  # Caught early by heuristic or neural classifier.
    CONTAINED = "CONTAINED"  # Classifier missed, but blocked by Capability, Network, Graph, DLP, or Canary.
    PARTIALLY_CONTAINED = "PARTIALLY_CONTAINED"  # Passive read allowed, but high-impact write/egress prevented.
    EXECUTED = "EXECUTED"  # Unauthorized action executed with attacker parameters (containment breach).
    EXFILTRATED = "EXFILTRATED"  # Canary token or secret leaked to external sink (critical breach).


class TraceHop(BaseModel):
    """Individual execution milestone within an end-to-end security trace."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    hop_id: str = Field(
        ...,
        description="Unique identifier for the trace hop.",
    )
    name: str = Field(
        ...,
        description="Name of the trace milestone (e.g. INPUT_INGESTION, INJECTION_SCAN, POLICY_EVALUATION).",
    )
    status: str = Field(
        ...,
        description="Outcome status of this hop ('PASS', 'BLOCKED', 'FLAGGED', 'ESCALATED', 'ROLLBACK').",
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of hop execution.",
    )
    latency_ms: float = Field(
        default=0.0,
        ge=0.0,
        description="Execution latency of this hop in milliseconds.",
    )
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured forensic metadata associated with this trace hop.",
    )


class AuditEvent(BaseModel):
    """Immutable audit record logging ingestion, scanning, tracing, and policy enforcement decisions."""

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
    mitre_atlas_tags: List[str] = Field(
        default_factory=list,
        description="Assigned MITRE ATLAS threat taxonomy tags.",
    )
    trace_hops: List[TraceHop] = Field(
        default_factory=list,
        description="Chronological security execution trace hops for SOC investigation.",
    )
    otlp_export: Optional[dict[str, Any]] = Field(
        default=None,
        description="OpenTelemetry SIEM-compatible structured log payload.",
    )
    ledger_sequence_id: Optional[int] = Field(
        default=None,
        description="Cryptographically chained sequence ID in the audit ledger.",
    )
    ledger_prev_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 hash of the preceding ledger block.",
    )
    ledger_entry_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 hash of this ledger entry block.",
    )
    ledger_signature: Optional[str] = Field(
        default=None,
        description="HMAC-SHA256 signature guaranteeing ledger authenticity.",
    )

    @staticmethod
    def hash_payload(payload: str) -> str:
        """Utility helper to generate canonical SHA-256 hash for raw content."""
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


