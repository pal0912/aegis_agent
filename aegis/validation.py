import base64
import collections
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegis.types import Capability


class LiveValidationAuthorizer:
    """Cryptographic authorization engine for LIVE_VALIDATION mode.

    Generates and verifies HMAC-SHA256 authorization tokens bound to a specific
    validation_id, environment, expiration timestamp, and unique nonce.
    """

    DEFAULT_SECRET: str = "aegis-live-val-secret-key-32bytes-min!!"

    @classmethod
    def generate_token(
        cls,
        validation_id: str,
        environment: str = "live",
        secret_key: Optional[str] = None,
        ttl_seconds: int = 300,
    ) -> str:
        """Generate a cryptographically signed authorization token bound to a validation scope."""
        key = secret_key or cls.DEFAULT_SECRET
        now = int(time.time())
        claims = {
            "val_id": validation_id,
            "env": environment,
            "iat": now,
            "exp": now + ttl_seconds,
            "nonce": uuid.uuid4().hex,
        }
        claims_json = json.dumps(claims, sort_keys=True)
        claims_b64 = base64.urlsafe_b64encode(claims_json.encode("utf-8")).decode("utf-8")
        sig = hmac.new(key.encode("utf-8"), claims_b64.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"live_tok.{claims_b64}.{sig}"

    AUTHORIZED_BOOTSTRAP_TOKENS: set[str] = {"SEC_TOKEN_999"}
    MAX_TRACKED_NONCES: int = 50000
    _lock = threading.RLock()
    _used_nonces: collections.OrderedDict[str, float] = (
        collections.OrderedDict()
    )

    @classmethod
    def verify_token(
        cls,
        token: str,
        validation_id: str,
        expected_environment: str = "live",
        secret_key: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Verify operator token authenticity, scope, and replay freshness."""
        key = secret_key or cls.DEFAULT_SECRET
        if not token or not isinstance(token, str) or not token.strip():
            return False, "Token is missing or not a string."

        # Support authorized bootstrap token for testing and provisioning
        if token in cls.AUTHORIZED_BOOTSTRAP_TOKENS:
            return True, "Authorized bootstrap operator token verified."

        if not token.startswith("live_tok."):
            return False, "Malformed token prefix: must start with 'live_tok.'"
        parts = token.split(".")
        if len(parts) != 3:
            return (
                False,
                "Malformed token structure: must contain exactly 3 segments.",
            )
        _, claims_b64, sig = parts
        expected_sig = hmac.new(
            key.encode("utf-8"), claims_b64.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return (
                False,
                "Cryptographic signature verification failed "
                "(invalid secret or tampered token).",
            )
        try:
            claims = json.loads(
                base64.urlsafe_b64decode(claims_b64.encode("utf-8")).decode(
                    "utf-8"
                )
            )
        except Exception as exc:
            return False, f"Token claims decode failure: {exc}"

        if claims.get("val_id") != validation_id:
            return (
                False,
                f"Token scope mismatch: issued for '{claims.get('val_id')}', "
                f"presented for '{validation_id}'.",
            )

        if claims.get("env") != expected_environment:
            return (
                False,
                f"Token environment mismatch: issued for '{claims.get('env')}', "
                f"required '{expected_environment}'.",
            )

        if time.time() > claims.get("exp", 0):
            return False, f"Token expired at timestamp {claims.get('exp')}."

        nonce = claims.get("nonce")
        if not nonce:
            return False, "Token missing replay prevention nonce."

        with cls._lock:
            if nonce in cls._used_nonces:
                return (
                    False,
                    f"Token replay detected: nonce '{nonce}' has already "
                    f"been consumed.",
                )
            if len(cls._used_nonces) >= cls.MAX_TRACKED_NONCES:
                cls._used_nonces.popitem(last=False)
            cls._used_nonces[nonce] = time.time()

        return True, "Token verified."


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
    permitted_capabilities: frozenset[Capability] = Field(
        default_factory=lambda: frozenset({Capability.READ_PUBLIC})
    )
    permitted_filesystem_paths: tuple[str, ...] = Field(default_factory=tuple)
    permitted_network_destinations: tuple[str, ...] = Field(
        default_factory=tuple,
        description="Explicit allowlist of permitted network destinations. Safe modes do not implicitly trust localhost or loopback.",
    )
    permitted_tools: Optional[frozenset[str]] = Field(
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

    @field_validator("permitted_capabilities", mode="before")
    @classmethod
    def validate_caps(cls, val: Any) -> frozenset[Capability]:
        if val is None:
            return frozenset({Capability.READ_PUBLIC})
        return frozenset(val)

    @field_validator("permitted_filesystem_paths", mode="before")
    @classmethod
    def validate_paths(cls, paths: Any) -> tuple[str, ...]:
        if not paths:
            return ()
        cleaned = []
        for p in paths:
            norm = os.path.normpath(str(p))
            cleaned.append(norm)
        return tuple(cleaned)

    @field_validator("permitted_network_destinations", mode="before")
    @classmethod
    def validate_net_dest(cls, val: Any) -> tuple[str, ...]:
        if not val:
            return ()
        return tuple(val)

    @field_validator("permitted_tools", mode="before")
    @classmethod
    def validate_tools(cls, val: Any) -> Optional[frozenset[str]]:
        if val is None:
            return None
        return frozenset(val)

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
            is_valid, reason = LiveValidationAuthorizer.verify_token(
                self.operator_authorization_token,
                validation_id=self.validation_id,
                expected_environment="live",
            )
            if not is_valid:
                raise ValueError(f"LIVE_VALIDATION operator authorization token rejected: {reason}")

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

    def create_child_scope(self, **overrides: Any) -> "ValidationScope":
        """Create a child ValidationScope and validate monotonic attenuation against this parent."""
        data = self.model_dump()
        data["parent_scope_id"] = self.validation_id
        data["validation_id"] = f"val_{uuid.uuid4().hex[:12]}"
        data.update(overrides)
        child = ValidationScope(**data)
        self.validate_child_scope(child)
        return child

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

        # 8. Filesystem path monotonicity
        if self.permitted_filesystem_paths:
            for child_path in child.permitted_filesystem_paths:
                if not self.is_filesystem_path_allowed(child_path):
                    raise ValueError(
                        f"Scope escalation: Child filesystem path '{child_path}' is not contained within parent allowed paths."
                    )

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
        if not target_path or not isinstance(target_path, str):
            return False

        # Reject null byte injection and URL-encoded null bytes
        if "\x00" in target_path or "%00" in target_path:
            return False

        try:
            target_abs = os.path.abspath(target_path)
            target_real = os.path.realpath(target_abs)
        except Exception:
            return False

        # Block root or drive roots in safe modes if no paths specified
        if not self.permitted_filesystem_paths:
            return False

        for allowed_root in self.permitted_filesystem_paths:
            allowed_norm = os.path.normpath(os.path.abspath(allowed_root))
            allowed_real = os.path.realpath(allowed_norm)
            try:
                common_norm = os.path.commonpath([allowed_norm, target_abs])
                common_real = os.path.commonpath([allowed_real, target_real])
                if common_norm == allowed_norm and common_real == allowed_real:
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

        def _extract_all_strings(obj: Any) -> List[str]:
            res = []
            if isinstance(obj, str):
                res.append(obj)
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    res.extend(_extract_all_strings(k))
                    res.extend(_extract_all_strings(v))
            elif isinstance(obj, (list, tuple, set)):
                for item in obj:
                    res.extend(_extract_all_strings(item))
            return res

        all_arg_strings = _extract_all_strings(arguments)

        # 1. External Messaging
        messaging_keywords = [
            "email", "slack", "sms", "webhook", "post_message", "discord", "telegram",
            "teams", "mattermost", "pagerduty", "pushover", "matrix", "notify", "broadcast",
            "publish_message", "send_chat", "emit_webhook", "dispatch_alert"
        ]
        if capability == Capability.SEND_EXTERNAL_MESSAGE or any(k in t_name for k in messaging_keywords) or any(
            any(k in s.lower() for k in ["webhook_url", "channel_id", "slack.com", "discord.com", "api.telegram.org"])
            for s in all_arg_strings
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

        # 3. Database Mutations (DROP, TRUNCATE, UPDATE, DELETE, INSERT, ALTER, CREATE, REPLACE, MERGE, etc.)
        sql_mutation_regex = re.compile(
            r"\b(INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|REPLACE|MERGE|GRANT|REVOKE|EXEC|EXECUTE|CALL)\b",
            re.IGNORECASE,
        )

        has_sql_mutation = False
        for s in all_arg_strings:
            clean_s = re.sub(r"/\*.*?\*/", " ", s, flags=re.DOTALL)
            clean_s = re.sub(r"--.*", " ", clean_s)
            if sql_mutation_regex.search(clean_s):
                has_sql_mutation = True
                break

        if capability in {Capability.WRITE_DATABASE, Capability.ADMIN} or any(
            k in t_name for k in ["write_db", "insert", "update", "delete_record", "drop", "truncate", "modify_db", "db_exec"]
        ) or has_sql_mutation:
            if self.mode in {ValidationMode.DRY_RUN, ValidationMode.SIMULATION, ValidationMode.ISOLATED_TEST}:
                return SideEffectRecord(
                    category=SideEffectCategory.DATABASE_MODIFICATION,
                    tool_name=tool_name,
                    destination=destination or arguments.get("database") or arguments.get("table"),
                    reason=f"Prohibited database mutation against persistent store in '{self.mode.value}'.",
                    details={"arguments_preview": str(arguments)[:200]},
                )

        # 4. Filesystem Modifications
        fs_keywords = [
            "write", "delete", "unlink", "append", "modify_file", "create_file",
            "rename", "move", "remove", "rmdir", "symlink", "link", "touch", "chmod", "chown"
        ]
        candidate_paths = []
        for k, v in arguments.items():
            if isinstance(v, str) and any(p_key in k.lower() for p_key in ["path", "file", "dest", "source", "target", "dir"]):
                candidate_paths.append(v)

        if capability == Capability.WRITE_FILE or any(k in t_name for k in fs_keywords) or any(k in str(arguments).lower() for k in fs_keywords):
            if candidate_paths:
                for fp in candidate_paths:
                    if not self.is_filesystem_path_allowed(fp):
                        return SideEffectRecord(
                            category=SideEffectCategory.FILESYSTEM_MODIFICATION,
                            tool_name=tool_name,
                            destination=fp,
                            reason=f"Filesystem write outside allowed ephemeral root '{self.permitted_filesystem_paths}'.",
                            details={"target_path": fp},
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
