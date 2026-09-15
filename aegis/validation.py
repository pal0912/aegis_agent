"""Scoped and Safe Validation Mode framework for AegisAgent V2.

Ensures adversarial testing, policy fuzzing, sandbox execution, network tests,
and end-to-end security verification can never perform real destructive,
financial, credential, filesystem, database, or external-network actions.
"""

from datetime import datetime, timedelta, timezone
from enum import Enum
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegis.types import Capability


class ValidationMode(str, Enum):
    """Explicit runtime modes for security validation and testing."""

    DRY_RUN = "DRY_RUN"  # Complete simulation: tools never execute, side effects intercepted as CONTAINED.
    SIMULATION = "SIMULATION"  # Execution only against mock/synthetic/transaction-isolated test fixtures.
    ISOLATED_TEST = "ISOLATED_TEST"  # Execution restricted to ephemeral directory, test network, and canaries.
    LIVE_VALIDATION = "LIVE_VALIDATION"  # Production execution gated behind explicit operator token and verified env.


class SideEffectCategory(str, Enum):
    """Categorization of side-effect vectors intercepted during security validation."""

    FILESYSTEM_MODIFICATION = "filesystem_modification"
    DATABASE_MODIFICATION = "database_modification"
    NETWORK_EGRESS = "network_egress"
    SECRET_ACCESS = "secret_access"
    EXTERNAL_MESSAGING = "external_messaging"
    CAPABILITY_ESCALATION = "capability_escalation"
    FINANCIAL_TRANSACTION = "financial_transaction"
    UNRESTRICTED_CODE_EXECUTION = "unrestricted_code_execution"


class SideEffectRecord(BaseModel):
    """Forensic record of an attempted and contained side-effect action."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    category: SideEffectCategory
    tool_name: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    destination: Optional[str] = None
    status: str = "CONTAINED"  # Contained rather than merely detected
    reason: str
    details: Dict[str, Any] = Field(default_factory=dict)


def default_expires_at() -> datetime:
    """Default short TTL expiration: 120 seconds from creation."""
    return datetime.now(timezone.utc) + timedelta(seconds=120)


class ValidationScope(BaseModel):
    """Typed, immutable security envelope defining explicit boundaries for validation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    validation_id: str = Field(default_factory=lambda: f"val_{uuid.uuid4().hex[:12]}")
    mode: ValidationMode = Field(default=ValidationMode.DRY_RUN)
    permitted_capabilities: Set[Capability] = Field(
        default_factory=lambda: {Capability.READ_PUBLIC}
    )
    permitted_filesystem_paths: List[str] = Field(default_factory=list)
    permitted_network_destinations: List[str] = Field(
        default_factory=lambda: ["127.0.0.1", "localhost", "test-container"]
    )
    permitted_tools: Optional[Set[str]] = Field(
        default=None,
        description="Optional explicit whitelist of allowed tool names. If None, derived from permitted capabilities.",
    )
    max_runtime_sec: float = Field(default=30.0, gt=0.0, le=3600.0)
    max_steps: int = Field(default=10, gt=0, le=1000)
    max_payload_size_bytes: int = Field(default=65536, gt=0, le=10485760)
    allow_external_side_effects: bool = Field(
        default=False,
        description="Strictly forbidden in DRY_RUN, SIMULATION, and ISOLATED_TEST modes.",
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Field(default_factory=default_expires_at)
    parent_scope_id: Optional[str] = Field(default=None)
    operator_authorization_token: Optional[str] = Field(
        default=None,
        description="Cryptographic authorization token required for LIVE_VALIDATION mode.",
    )
    live_environment_verified: bool = Field(
        default=False,
        description="Explicit boolean confirmation required for LIVE_VALIDATION mode.",
    )

    @field_validator("permitted_filesystem_paths")
    @classmethod
    def validate_paths(cls, paths: List[str]) -> List[str]:
        cleaned = []
        for p in paths:
            norm = os.path.normpath(p)
            cleaned.append(norm)
        return cleaned

    @model_validator(mode="after")
    def validate_safety_constraints(self) -> "ValidationScope":
        # 1. Safe modes cannot permit external side effects
        if self.mode in {ValidationMode.DRY_RUN, ValidationMode.SIMULATION, ValidationMode.ISOLATED_TEST}:
            if self.allow_external_side_effects:
                raise ValueError(
                    f"allow_external_side_effects cannot be True in safe validation mode '{self.mode.value}'."
                )

        # 2. LIVE_VALIDATION requires explicit authorization token and verified environment
        if self.mode == ValidationMode.LIVE_VALIDATION:
            if not self.operator_authorization_token or not self.operator_authorization_token.strip():
                raise ValueError(
                    "LIVE_VALIDATION mode requires an explicit, non-empty operator_authorization_token."
                )
            if not self.live_environment_verified:
                raise ValueError(
                    "LIVE_VALIDATION mode requires live_environment_verified=True."
                )

        # 3. Expiration must be in the future relative to creation
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be strictly later than created_at.")

        return self

    def is_expired(self) -> bool:
        """Check if the validation scope TTL has expired."""
        return datetime.now(timezone.utc) > self.expires_at

    def intersect_capabilities(
        self,
        agent_capabilities: Set[Capability],
        policy_capabilities: Optional[Set[Capability]] = None,
    ) -> Set[Capability]:
        """Compute strict capability intersection: Effective = Requested ∩ Scope ∩ Agent ∩ Policy."""
        effective = self.permitted_capabilities.intersection(agent_capabilities)
        if policy_capabilities is not None:
            effective = effective.intersection(policy_capabilities)
        return effective

    def validate_child_scope(self, child: "ValidationScope") -> bool:
        """Verify monotonic scope attenuation: ChildScope ⊆ ParentScope.
        
        Raises ValueError with specific violation if child attempts to escalate authority.
        """
        # 1. Mode escalation check
        mode_hierarchy = {
            ValidationMode.DRY_RUN: 0,
            ValidationMode.SIMULATION: 1,
            ValidationMode.ISOLATED_TEST: 2,
            ValidationMode.LIVE_VALIDATION: 3,
        }
        if mode_hierarchy[child.mode] > mode_hierarchy[self.mode]:
            raise ValueError(
                f"Scope escalation: Child mode '{child.mode.value}' is less restrictive than parent '{self.mode.value}'."
            )

        # 2. Capability monotonicity
        if not child.permitted_capabilities.issubset(self.permitted_capabilities):
            escalated = child.permitted_capabilities - self.permitted_capabilities
            raise ValueError(
                f"Scope escalation: Child requested capabilities not in parent: {[c.value for c in escalated]}"
            )

        # 3. External side effects
        if child.allow_external_side_effects and not self.allow_external_side_effects:
            raise ValueError("Scope escalation: Child cannot enable allow_external_side_effects when parent forbids it.")

        # 4. Resource limits cannot be widened
        if child.max_runtime_sec > self.max_runtime_sec:
            raise ValueError(
                f"Scope escalation: Child runtime ({child.max_runtime_sec}s) exceeds parent ({self.max_runtime_sec}s)."
            )
        if child.max_steps > self.max_steps:
            raise ValueError(
                f"Scope escalation: Child steps ({child.max_steps}) exceeds parent ({self.max_steps})."
            )
        if child.max_payload_size_bytes > self.max_payload_size_bytes:
            raise ValueError(
                f"Scope escalation: Child payload size ({child.max_payload_size_bytes}) exceeds parent ({self.max_payload_size_bytes})."
            )

        # 5. Network destination monotonicity
        child_net = set(child.permitted_network_destinations)
        parent_net = set(self.permitted_network_destinations)
        if not child_net.issubset(parent_net):
            widened_net = child_net - parent_net
            raise ValueError(
                f"Scope escalation: Child network destinations widened beyond parent: {sorted(widened_net)}"
            )

        # 6. Tool whitelist monotonicity
        if self.permitted_tools is not None:
            if child.permitted_tools is None:
                raise ValueError(
                    "Scope escalation: Child cannot have unrestricted tools when parent has permitted_tools whitelist."
                )
            if not child.permitted_tools.issubset(self.permitted_tools):
                widened_tools = child.permitted_tools - self.permitted_tools
                raise ValueError(
                    f"Scope escalation: Child tools widened beyond parent: {sorted(widened_tools)}"
                )

        # 7. Expiration monotonicity
        if child.expires_at > self.expires_at:
            raise ValueError("Scope escalation: Child expires_at cannot exceed parent expires_at.")

        return True

    def is_network_destination_allowed(self, target: str) -> bool:
        """Check if destination URL or host is within permitted network destinations."""
        if not target:
            return False
        parsed = urlparse(target if "://" in target else f"http://{target}")
        host = (parsed.hostname or "").lower()
        port = parsed.port

        for allowed in self.permitted_network_destinations:
            allowed_clean = allowed.lower().strip()
            if host == allowed_clean:
                return True
            if port and f"{host}:{port}" == allowed_clean:
                return True
            # Wildcard test domain support e.g. *.test.internal
            if allowed_clean.startswith("*.") and host.endswith(allowed_clean[1:]):
                return True

        return False

    def is_filesystem_path_allowed(self, target_path: str) -> bool:
        """Verify target path is strictly contained within permitted filesystem roots."""
        if not target_path:
            return False

        try:
            target_norm = os.path.normpath(os.path.abspath(target_path))
        except Exception:
            return False

        # Block root or drive roots in safe modes if no paths specified
        if not self.permitted_filesystem_paths:
            return False

        for allowed_root in self.permitted_filesystem_paths:
            allowed_norm = os.path.normpath(os.path.abspath(allowed_root))
            try:
                common = os.path.commonpath([allowed_norm, target_norm])
                if common == allowed_norm:
                    return True
            except (ValueError, Exception):
                continue

        return False

    def inspect_and_contain_side_effect(
        self,
        tool_name: str,
        capability: Capability,
        arguments: Dict[str, Any],
        destination: Optional[str] = None,
    ) -> Optional[SideEffectRecord]:
        """Detect if invocation attempts prohibited real-world side effects in safe validation mode."""
        t_name = tool_name.lower()

        # 1. External Messaging
        if capability == Capability.SEND_EXTERNAL_MESSAGE or any(
            k in t_name for k in ["email", "slack", "sms", "webhook", "post_message"]
        ):
            if not self.allow_external_side_effects:
                return SideEffectRecord(
                    category=SideEffectCategory.EXTERNAL_MESSAGING,
                    tool_name=tool_name,
                    destination=destination or arguments.get("recipient") or arguments.get("channel"),
                    reason=f"Prohibited external message execution under safe mode '{self.mode.value}'.",
                    details=arguments,
                )

        # 2. Financial Transactions
        if capability == Capability.FINANCIAL_ACTION or any(
            k in t_name for k in ["pay", "charge", "transfer", "wire", "refund"]
        ):
            if not self.allow_external_side_effects:
                return SideEffectRecord(
                    category=SideEffectCategory.FINANCIAL_TRANSACTION,
                    tool_name=tool_name,
                    destination=destination or arguments.get("account") or arguments.get("recipient"),
                    reason=f"Prohibited financial transaction under safe mode '{self.mode.value}'.",
                    details=arguments,
                )

        # 3. Database Mutations (DROP, TRUNCATE, UPDATE, DELETE, INSERT)
        if capability in {Capability.WRITE_DATABASE, Capability.ADMIN} or any(
            k in t_name for k in ["write_db", "insert", "update", "delete_record", "drop", "truncate"]
        ):
            query = str(arguments.get("query") or arguments.get("sql") or "").upper()
            is_mutation = any(kw in query for kw in ["INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "ALTER"])
            if is_mutation or capability == Capability.WRITE_DATABASE or capability == Capability.ADMIN:
                if self.mode in {ValidationMode.DRY_RUN, ValidationMode.SIMULATION, ValidationMode.ISOLATED_TEST}:
                    return SideEffectRecord(
                        category=SideEffectCategory.DATABASE_MODIFICATION,
                        tool_name=tool_name,
                        destination=destination or arguments.get("database") or arguments.get("table"),
                        reason=f"Prohibited database mutation against persistent store in '{self.mode.value}'.",
                        details={"query": query[:200] if query else ""},
                    )

        # 4. Filesystem Modifications
        if capability == Capability.WRITE_FILE or any(
            k in t_name for k in ["write", "delete", "unlink", "append", "modify_file", "create_file"]
        ):
            filepath = str(arguments.get("filepath") or arguments.get("path") or arguments.get("filename") or "")
            if filepath:
                if not self.is_filesystem_path_allowed(filepath):
                    return SideEffectRecord(
                        category=SideEffectCategory.FILESYSTEM_MODIFICATION,
                        tool_name=tool_name,
                        destination=filepath,
                        reason=f"Filesystem write outside allowed ephemeral root '{self.permitted_filesystem_paths}'.",
                        details={"target_path": filepath},
                    )
            elif self.mode == ValidationMode.DRY_RUN:
                return SideEffectRecord(
                    category=SideEffectCategory.FILESYSTEM_MODIFICATION,
                    tool_name=tool_name,
                    reason="Filesystem mutation intercepted in DRY_RUN mode.",
                    details=arguments,
                )

        # 5. Network Egress
        if capability == Capability.NETWORK_EXTERNAL or any(
            k in t_name for k in ["http", "curl", "fetch", "download", "request"]
        ):
            target = destination or arguments.get("url") or arguments.get("host") or arguments.get("endpoint")
            if target and not self.is_network_destination_allowed(str(target)):
                return SideEffectRecord(
                    category=SideEffectCategory.NETWORK_EGRESS,
                    tool_name=tool_name,
                    destination=str(target),
                    reason=f"Network egress to destination '{target}' not in allowlist {self.permitted_network_destinations}.",
                    details={"target": str(target)},
                )

        # 6. Unrestricted Code Execution
        if capability == Capability.EXECUTE_CODE or any(
            k in t_name for k in ["exec", "bash", "shell", "eval", "cmd", "powershell"]
        ):
            if self.mode in {ValidationMode.DRY_RUN, ValidationMode.SIMULATION}:
                return SideEffectRecord(
                    category=SideEffectCategory.UNRESTRICTED_CODE_EXECUTION,
                    tool_name=tool_name,
                    reason=f"Unrestricted host code execution prohibited under '{self.mode.value}'.",
                    details=arguments,
                )

        # 7. Secret Access
        if capability == Capability.READ_PRIVATE or any(
            k in t_name for k in ["get_secret", "env", "credentials", "api_key", "password"]
        ):
            target_key = str(arguments.get("key") or arguments.get("secret_name") or "")
            # In validation mode, accessing production credentials is prohibited
            if any(term in target_key.lower() for term in ["prod", "live", "aws_secret", "openai_key", "db_pass"]):
                return SideEffectRecord(
                    category=SideEffectCategory.SECRET_ACCESS,
                    tool_name=tool_name,
                    destination=target_key,
                    reason=f"Access to production credential '{target_key}' prohibited in validation mode.",
                    details={"target_key": target_key},
                )

        return None


class ValidationTrace(BaseModel):
    """Forensic audit trace of an entire security validation session."""

    model_config = ConfigDict(extra="forbid")

    trace_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    validation_id: str
    mode: ValidationMode
    policy_version: str = "2.0"
    agent_identity: Optional[str] = None
    capabilities: Set[Capability] = Field(default_factory=set)
    tests_executed: List[str] = Field(default_factory=list)
    security_decisions: List[Dict[str, Any]] = Field(default_factory=list)
    side_effects_attempted: List[SideEffectRecord] = Field(default_factory=list)
    side_effects_prevented: List[SideEffectRecord] = Field(default_factory=list)

    def record_attempted_side_effect(
        self,
        record: SideEffectRecord,
    ) -> None:
        """Record an attempted side-effect and log its containment status."""
        self.side_effects_attempted.append(record)
        if record.status == "CONTAINED":
            self.side_effects_prevented.append(record)
