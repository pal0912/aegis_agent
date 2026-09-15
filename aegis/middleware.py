"""Defense-in-depth security middleware and LangChain tool wrappers for AegisAgent V2.

Provides automated input ingestion decoration (@aegis_guard), memory snapshotting/rollback,
and deterministic policy interception for autonomous agent tool invocations (AegisToolWrapper).
"""

import asyncio
import contextvars
import functools
import inspect
import json
import logging
import re
import uuid
from typing import Any, Callable, Dict, List, Optional, Set, Type

from langchain_core.tools import BaseTool
from pydantic import ConfigDict, Field

_current_aegis_execution_token: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "_current_aegis_execution_token", default=None
)


class DirectToolInvocationBlockedError(PermissionError):
    """Raised when an underlying tool is invoked directly without routing through AegisToolWrapper."""

    pass

from aegis.audit import AuditLogger
from aegis.detector import InjectionDetector
from aegis.memory_guard import MemoryEntry, MemoryGuard
from aegis.policy_gate import PolicyGate
from aegis.sanitizer import ContextSanitizer
from aegis.taint import SessionContext
from aegis.types import (
    AuditEvent,
    Capability,
    PolicyVerdict,
    RestrictedExecutionPolicy,
    ScanResult,
    ToolCallProposal,
    TrustLevel,
)

logger = logging.getLogger(__name__)

QUARANTINE_SHIELD_MESSAGE = (
    "[AEGIS SHIELD ACTIVATED]: The content from this source was quarantined due to "
    "detected prompt injection directives. Memory state has been rolled back."
)


def aegis_guard(
    detector: InjectionDetector,
    sanitizer: ContextSanitizer,
    policy_gate: Optional[PolicyGate] = None,
    audit_logger: Optional[AuditLogger] = None,
    session: Optional[SessionContext] = None,
    memory_guard: Optional[MemoryGuard] = None,
) -> Callable:
    """Decorator guarding external data ingestion functions (APIs, web scrapers, emails, PDFs).

    Automates taint tracking, memory snapshots, injection scanning, tamper-evident audit logging,
    and non-executable XML encapsulation.

    Args:
        detector: Active InjectionDetector instance.
        sanitizer: ContextSanitizer instance.
        policy_gate: Optional PolicyGate instance for policy checks.
        audit_logger: Optional AuditLogger for telemetry.
        session: Active SessionContext for tracking execution lineage.
        memory_guard: Optional MemoryGuard for snapshot creation and rollbacks.
    """

    def decorator(func: Callable) -> Callable:
        source_label = func.__name__

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> str:
            active_session = session or kwargs.get("session")
            session_id = active_session.session_id if active_session else "GLOBAL_SESSION"

            # 1. Create clean memory snapshot before untrusted retrieval
            active_mem_guard = memory_guard or (policy_gate.memory_guard if policy_gate else None)
            snapshot_id = None
            if active_mem_guard is not None:
                snapshot_id = active_mem_guard.create_snapshot(session_id)

            raw_content = func(*args, **kwargs)
            str_content = str(raw_content) if raw_content is not None else ""

            # 2. Update session taint state
            if active_session is not None:
                active_session.ingest_untrusted_data(
                    source_name=source_label, raw_text=str_content
                )

            # 3. Scan for prompt injections and jailbreaks
            scan_result: ScanResult = detector.scan(str_content)

            # 4. Handle unsafe/quarantined payload
            if not scan_result.is_safe:
                if active_session is not None:
                    active_session.quarantine_session(
                        reason="; ".join(scan_result.reasons)
                    )

                # Rollback memory to pre-retrieval clean state
                if active_mem_guard is not None and snapshot_id is not None:
                    active_mem_guard.rollback(session_id, snapshot_id)

                if audit_logger is not None:
                    audit_event = AuditEvent(
                        trace_id=session_id,
                        trust_level=TrustLevel.QUARANTINED,
                        raw_content_sha256=AuditEvent.hash_payload(str_content),
                        scan_result=scan_result,
                        policy_decision=None,
                    )
                    audit_logger.log_event(audit_event)

                logger.warning(
                    "AegisGuard quarantined payload from '%s': %s",
                    source_label,
                    scan_result.reasons,
                )
                return QUARANTINE_SHIELD_MESSAGE

            # 5. Safe payload: Validate and add to MemoryGuard
            if active_mem_guard is not None:
                mem_entry = MemoryEntry.create(
                    content=str_content,
                    trust_level=TrustLevel.UNTRUSTED,
                    source=source_label,
                )
                active_mem_guard.add_entry(session_id, mem_entry)

            if audit_logger is not None:
                audit_event = AuditEvent(
                    trace_id=session_id,
                    trust_level=TrustLevel.UNTRUSTED,
                    raw_content_sha256=AuditEvent.hash_payload(str_content),
                    scan_result=scan_result,
                    policy_decision=None,
                )
                audit_logger.log_event(audit_event)

            # 6. Encapsulate inside non-executable boundaries
            return sanitizer.sanitize_and_encapsulate(
                str_content, source_label=source_label
            )

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> str:
            active_session = session or kwargs.get("session")
            session_id = active_session.session_id if active_session else "GLOBAL_SESSION"

            active_mem_guard = memory_guard or (policy_gate.memory_guard if policy_gate else None)
            snapshot_id = None
            if active_mem_guard is not None:
                snapshot_id = active_mem_guard.create_snapshot(session_id)

            raw_content = await func(*args, **kwargs)
            str_content = str(raw_content) if raw_content is not None else ""

            if active_session is not None:
                active_session.ingest_untrusted_data(
                    source_name=source_label, raw_text=str_content
                )

            scan_result: ScanResult = detector.scan(str_content)

            if not scan_result.is_safe:
                if active_session is not None:
                    active_session.quarantine_session(
                        reason="; ".join(scan_result.reasons)
                    )

                if active_mem_guard is not None and snapshot_id is not None:
                    active_mem_guard.rollback(session_id, snapshot_id)

                if audit_logger is not None:
                    audit_event = AuditEvent(
                        trace_id=session_id,
                        trust_level=TrustLevel.QUARANTINED,
                        raw_content_sha256=AuditEvent.hash_payload(str_content),
                        scan_result=scan_result,
                        policy_decision=None,
                    )
                    audit_logger.log_event(audit_event)

                return QUARANTINE_SHIELD_MESSAGE

            if active_mem_guard is not None:
                mem_entry = MemoryEntry.create(
                    content=str_content,
                    trust_level=TrustLevel.UNTRUSTED,
                    source=source_label,
                )
                active_mem_guard.add_entry(session_id, mem_entry)

            if audit_logger is not None:
                audit_event = AuditEvent(
                    trace_id=session_id,
                    trust_level=TrustLevel.UNTRUSTED,
                    raw_content_sha256=AuditEvent.hash_payload(str_content),
                    scan_result=scan_result,
                    policy_decision=None,
                )
                audit_logger.log_event(audit_event)

            return sanitizer.sanitize_and_encapsulate(
                str_content, source_label=source_label
            )

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


class AegisToolWrapper(BaseTool):
    """Secure LangChain BaseTool wrapper with deterministic PolicyGate interception and tri-state handling."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")

    underlying_tool: BaseTool = Field(
        ..., description="The original underlying LangChain tool."
    )
    policy_gate: PolicyGate = Field(
        ..., description="PolicyGate instance enforcing intent alignment and blast radius control."
    )
    session: SessionContext = Field(
        ..., description="Active session context containing taint state and root intent."
    )
    audit_logger: Optional[AuditLogger] = Field(
        default=None, description="Optional audit logger to record evaluation results."
    )
    last_detector_scan: Optional[ScanResult] = Field(
        default=None, description="Optional upstream prompt injection scan result."
    )

    def __init__(
        self,
        underlying_tool: BaseTool,
        policy_gate: PolicyGate,
        session: SessionContext,
        audit_logger: Optional[AuditLogger] = None,
        last_detector_scan: Optional[ScanResult] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize AegisToolWrapper wrapping an existing LangChain tool."""
        super().__init__(
            name=underlying_tool.name,
            description=underlying_tool.description,
            args_schema=getattr(underlying_tool, "args_schema", None),
            return_direct=getattr(underlying_tool, "return_direct", False),
            underlying_tool=underlying_tool,
            policy_gate=policy_gate,
            session=session,
            audit_logger=audit_logger,
            last_detector_scan=last_detector_scan,
            **kwargs,
        )
        wrapper_token = uuid.uuid4().hex
        object.__setattr__(self, "_aegis_wrapper_token", wrapper_token)
        self._attach_execution_guard(underlying_tool, wrapper_token)

    @classmethod
    def _attach_execution_guard(cls, tool: Any, token: str) -> None:
        """Bind an execution guard token to the underlying tool, locking direct invocation."""
        valid_tokens: Optional[Set[str]] = getattr(tool, "_aegis_valid_tokens", None)
        if valid_tokens is None:
            valid_tokens = set()
            try:
                object.__setattr__(tool, "_aegis_valid_tokens", valid_tokens)
            except Exception:
                pass
        valid_tokens.add(token)

        if getattr(tool, "_aegis_execution_guard_attached", False):
            return

        tool_name = getattr(tool, "name", str(tool))

        # Guard synchronous _run
        if hasattr(tool, "_run"):
            orig_run = tool._run

            def guarded_run(*args: Any, **kwargs: Any) -> Any:
                active_token = _current_aegis_execution_token.get()
                tokens = getattr(tool, "_aegis_valid_tokens", set())
                if active_token is None or active_token not in tokens:
                    logger.error(
                        "Direct invocation of underlying tool '%s' blocked. All invocations must route through AegisToolWrapper.",
                        tool_name,
                    )
                    raise DirectToolInvocationBlockedError(
                        f"Direct invocation of underlying tool '{tool_name}' is blocked. "
                        f"Tools must be invoked exclusively through AegisToolWrapper to ensure policy enforcement."
                    )
                return orig_run(*args, **kwargs)

            try:
                object.__setattr__(tool, "_run", guarded_run)
            except Exception as e:
                logger.warning("Could not guard _run on tool '%s': %s", tool_name, e)

        # Guard asynchronous _arun
        if hasattr(tool, "_arun"):
            orig_arun = tool._arun

            async def guarded_arun(*args: Any, **kwargs: Any) -> Any:
                active_token = _current_aegis_execution_token.get()
                tokens = getattr(tool, "_aegis_valid_tokens", set())
                if active_token is None or active_token not in tokens:
                    logger.error(
                        "Direct async invocation of underlying tool '%s' blocked. All invocations must route through AegisToolWrapper.",
                        tool_name,
                    )
                    raise DirectToolInvocationBlockedError(
                        f"Direct async invocation of underlying tool '{tool_name}' is blocked. "
                        f"Tools must be invoked exclusively through AegisToolWrapper to ensure policy enforcement."
                    )
                return await orig_arun(*args, **kwargs)

            try:
                object.__setattr__(tool, "_arun", guarded_arun)
            except Exception as e:
                logger.warning("Could not guard _arun on tool '%s': %s", tool_name, e)

        try:
            object.__setattr__(tool, "_aegis_execution_guard_attached", True)
        except Exception:
            pass

    @classmethod
    def guard_tools(
        cls,
        tools: List[BaseTool],
        policy_gate: PolicyGate,
        session: SessionContext,
        audit_logger: Optional[AuditLogger] = None,
        last_detector_scan: Optional[ScanResult] = None,
    ) -> List["AegisToolWrapper"]:
        """Wrap a collection of tools with AegisToolWrapper and return only guarded handles."""
        return [
            cls(
                underlying_tool=tool,
                policy_gate=policy_gate,
                session=session,
                audit_logger=audit_logger,
                last_detector_scan=last_detector_scan,
            )
            for tool in tools
        ]

    def _build_arguments_dict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Convert invocation positional arguments and keyword arguments into a clean dictionary."""
        if kwargs:
            return kwargs
        if args and len(args) == 1:
            if isinstance(args[0], dict):
                return args[0]
            return {"input": args[0]}
        return {"args": list(args)} if args else {}

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """Synchronously evaluate policy gate before executing underlying tool."""
        args_dict = self._build_arguments_dict(*args, **kwargs)

        proposal = ToolCallProposal(
            tool_name=self.name,
            arguments=args_dict,
            source_trace_id=self.session.session_id,
        )

        try:
            decision = self.policy_gate.evaluate_tool_call(
                session=self.session,
                tool_proposal=proposal,
                detector_scan=self.last_detector_scan,
            )
        except Exception as exc:
            logger.error("AegisToolWrapper policy evaluation failed with exception: %s -> FAIL_CLOSED", exc)
            return f"[AEGIS POLICY GATE BLOCKED]: Policy evaluation error -> FAIL_CLOSED: {exc}"

        if decision is None or not hasattr(decision, "verdict"):
            logger.error("AegisToolWrapper received invalid/null decision -> FAIL_CLOSED")
            return "[AEGIS POLICY GATE BLOCKED]: Malformed or null policy decision -> FAIL_CLOSED."

        # Audit log the policy decision
        if self.audit_logger is not None:
            raw_payload = json.dumps(
                {"tool": self.name, "arguments": args_dict}, sort_keys=True
            )
            event = AuditEvent(
                trace_id=self.session.session_id,
                trust_level=self.session.trust_level,
                raw_content_sha256=AuditEvent.hash_payload(raw_payload),
                scan_result=self.last_detector_scan,
                policy_decision=decision,
                policy_version=getattr(decision, "policy_version", "2.0"),
                policy_snapshot_hash=getattr(decision, "policy_snapshot_hash", None),
            )
            self.audit_logger.log_event(event)

        # Check ValidationScope interception before real execution
        val_scope = getattr(self.session, "validation_scope", None)
        if val_scope is not None:
            if val_scope.is_expired():
                logger.error("AegisToolWrapper: ValidationScope expired -> FAIL_CLOSED")
                return "[AEGIS VALIDATION EXPIRED]: Scope expired, execution blocked."
            if getattr(val_scope.mode, "value", str(val_scope.mode)) == "DRY_RUN":
                logger.info("AegisToolWrapper: Intercepted tool '%s' under DRY_RUN mode.", self.name)
                return f"[AEGIS VALIDATION DRY_RUN CONTAINED]: Simulated execution of '{self.name}' without side effects."

        # 1. ALLOW -> Normal Authorized Execution
        if decision.verdict == PolicyVerdict.ALLOW.value:
            tok_reset = _current_aegis_execution_token.set(getattr(self, "_aegis_wrapper_token", None))
            try:
                if args:
                    return self.underlying_tool.run(*args, **kwargs)
                return self.underlying_tool.run(args_dict)
            finally:
                _current_aegis_execution_token.reset(tok_reset)

        # 2. ALLOW_RESTRICTED -> Execute strictly within verified restriction envelope
        if decision.verdict == PolicyVerdict.ALLOW_RESTRICTED.value:
            if not decision.restriction_policy or not isinstance(decision.restriction_policy, RestrictedExecutionPolicy):
                logger.error("AegisToolWrapper: Missing or invalid restriction_policy for ALLOW_RESTRICTED -> Fail-Closed BLOCK")
                return "[AEGIS POLICY GATE BLOCKED]: ALLOW_RESTRICTED missing valid restriction envelope."
            return self._execute_restricted(decision.restriction_policy, args_dict, *args, **kwargs)

        # 3. REQUIRE_HUMAN_APPROVAL -> Halt for Operator Approval
        if decision.verdict in {PolicyVerdict.REQUIRE_HUMAN_APPROVAL.value, "REQUIRE_HUMAN_APPROVAL"}:
            logger.info(
                "AegisToolWrapper halted tool '%s' for human approval (risk score: %.2f)",
                self.name,
                decision.risk_score,
            )
            return (
                f"[AEGIS HUMAN APPROVAL REQUIRED]: Action '{self.name}' requires operator authorization. "
                f"Reason: {decision.reason} (Risk Score: {decision.risk_score:.2f})"
            )

        # 4. All other verdicts (BLOCK, FAIL_CLOSED, QUARANTINE, unknown) -> Strictly Blocked
        logger.warning(
            "AegisToolWrapper denied tool '%s' execution (verdict: %s): %s",
            self.name,
            decision.verdict,
            decision.reason,
        )
        return (
            f"[AEGIS POLICY GATE BLOCKED]: Unauthorized action '{self.name}' prevented. "
            f"Reason: {decision.reason}"
        )

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        """Asynchronously evaluate policy gate before executing underlying tool."""
        args_dict = self._build_arguments_dict(*args, **kwargs)

        proposal = ToolCallProposal(
            tool_name=self.name,
            arguments=args_dict,
            source_trace_id=self.session.session_id,
        )

        try:
            decision = self.policy_gate.evaluate_tool_call(
                session=self.session,
                tool_proposal=proposal,
                detector_scan=self.last_detector_scan,
            )
        except Exception as exc:
            logger.error("AegisToolWrapper async policy evaluation failed with exception: %s -> FAIL_CLOSED", exc)
            return f"[AEGIS POLICY GATE BLOCKED]: Policy evaluation error -> FAIL_CLOSED: {exc}"

        if decision is None or not hasattr(decision, "verdict"):
            logger.error("AegisToolWrapper async received invalid/null decision -> FAIL_CLOSED")
            return "[AEGIS POLICY GATE BLOCKED]: Malformed or null policy decision -> FAIL_CLOSED."

        if self.audit_logger is not None:
            raw_payload = json.dumps(
                {"tool": self.name, "arguments": args_dict}, sort_keys=True
            )
            event = AuditEvent(
                trace_id=self.session.session_id,
                trust_level=self.session.trust_level,
                raw_content_sha256=AuditEvent.hash_payload(raw_payload),
                scan_result=self.last_detector_scan,
                policy_decision=decision,
                policy_version=getattr(decision, "policy_version", "2.0"),
                policy_snapshot_hash=getattr(decision, "policy_snapshot_hash", None),
            )
            self.audit_logger.log_event(event)

        # Check ValidationScope interception before real execution
        val_scope = getattr(self.session, "validation_scope", None)
        if val_scope is not None:
            if val_scope.is_expired():
                logger.error("AegisToolWrapper async: ValidationScope expired -> FAIL_CLOSED")
                return "[AEGIS VALIDATION EXPIRED]: Scope expired, execution blocked."
            if getattr(val_scope.mode, "value", str(val_scope.mode)) == "DRY_RUN":
                logger.info("AegisToolWrapper async: Intercepted tool '%s' under DRY_RUN mode.", self.name)
                return f"[AEGIS VALIDATION DRY_RUN CONTAINED]: Simulated execution of '{self.name}' without side effects."

        # 1. ALLOW -> Normal Authorized Async Execution
        if decision.verdict == PolicyVerdict.ALLOW.value:
            tok_reset = _current_aegis_execution_token.set(getattr(self, "_aegis_wrapper_token", None))
            try:
                if args:
                    return await self.underlying_tool.arun(*args, **kwargs)
                return await self.underlying_tool.arun(args_dict)
            finally:
                _current_aegis_execution_token.reset(tok_reset)

        # 2. ALLOW_RESTRICTED -> Execute strictly within verified restriction envelope
        if decision.verdict == PolicyVerdict.ALLOW_RESTRICTED.value:
            if not decision.restriction_policy or not isinstance(decision.restriction_policy, RestrictedExecutionPolicy):
                logger.error("AegisToolWrapper async: Missing or invalid restriction_policy for ALLOW_RESTRICTED -> Fail-Closed BLOCK")
                return "[AEGIS POLICY GATE BLOCKED]: ALLOW_RESTRICTED missing valid restriction envelope."
            return await self._aexecute_restricted(decision.restriction_policy, args_dict, *args, **kwargs)

        # 3. REQUIRE_HUMAN_APPROVAL -> Halt for Operator Approval
        if decision.verdict in {PolicyVerdict.REQUIRE_HUMAN_APPROVAL.value, "REQUIRE_HUMAN_APPROVAL"}:
            return (
                f"[AEGIS HUMAN APPROVAL REQUIRED]: Action '{self.name}' requires operator authorization. "
                f"Reason: {decision.reason} (Risk Score: {decision.risk_score:.2f})"
            )

        # 4. All other verdicts (BLOCK, FAIL_CLOSED, QUARANTINE, unknown) -> Strictly Blocked
        logger.warning(
            "AegisToolWrapper async denied tool '%s' execution (verdict: %s): %s",
            self.name,
            decision.verdict,
            decision.reason,
        )
        return (
            f"[AEGIS POLICY GATE BLOCKED]: Unauthorized action '{self.name}' prevented. "
            f"Reason: {decision.reason}"
        )

    def _execute_restricted(
        self,
        restriction_policy: RestrictedExecutionPolicy,
        args_dict: Dict[str, Any],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Execute underlying tool strictly within the enforced capability and resource envelope."""
        val_scope = getattr(self.session, "validation_scope", None)
        if val_scope is not None:
            if val_scope.is_expired():
                return "[AEGIS VALIDATION EXPIRED]: Scope expired, execution blocked."
            if getattr(val_scope.mode, "value", str(val_scope.mode)) == "DRY_RUN":
                return f"[AEGIS VALIDATION DRY_RUN CONTAINED]: Simulated restricted execution of '{self.name}' without side effects."

        violation = self._validate_restrictions(restriction_policy, args_dict)
        if violation is not None:
            logger.warning("AegisToolWrapper restriction violation on tool '%s': %s", self.name, violation)
            return f"[AEGIS RESTRICTION VIOLATION]: {violation}"

        tok_reset = _current_aegis_execution_token.set(getattr(self, "_aegis_wrapper_token", None))
        try:
            if args:
                raw_output = self.underlying_tool.run(*args, **kwargs)
            else:
                raw_output = self.underlying_tool.run(args_dict)
        finally:
            _current_aegis_execution_token.reset(tok_reset)

        if restriction_policy.sanitize_output:
            sanitizer = ContextSanitizer()
            return sanitizer.sanitize_and_encapsulate(
                str(raw_output) if raw_output is not None else "",
                source_label=f"restricted_{self.name}",
            )
        return raw_output

    async def _aexecute_restricted(
        self,
        restriction_policy: RestrictedExecutionPolicy,
        args_dict: Dict[str, Any],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Asynchronously execute underlying tool strictly within the enforced capability and resource envelope."""
        val_scope = getattr(self.session, "validation_scope", None)
        if val_scope is not None:
            if val_scope.is_expired():
                return "[AEGIS VALIDATION EXPIRED]: Scope expired, execution blocked."
            if getattr(val_scope.mode, "value", str(val_scope.mode)) == "DRY_RUN":
                return f"[AEGIS VALIDATION DRY_RUN CONTAINED]: Simulated restricted execution of '{self.name}' without side effects."

        violation = self._validate_restrictions(restriction_policy, args_dict)
        if violation is not None:
            logger.warning("AegisToolWrapper async restriction violation on tool '%s': %s", self.name, violation)
            return f"[AEGIS RESTRICTION VIOLATION]: {violation}"

        tok_reset = _current_aegis_execution_token.set(getattr(self, "_aegis_wrapper_token", None))
        try:
            if args:
                raw_output = await self.underlying_tool.arun(*args, **kwargs)
            else:
                raw_output = await self.underlying_tool.arun(args_dict)
        finally:
            _current_aegis_execution_token.reset(tok_reset)

        if restriction_policy.sanitize_output:
            sanitizer = ContextSanitizer()
            return sanitizer.sanitize_and_encapsulate(
                str(raw_output) if raw_output is not None else "",
                source_label=f"restricted_{self.name}",
            )
        return raw_output

    def _validate_restrictions(
        self,
        restriction_policy: RestrictedExecutionPolicy,
        args_dict: Dict[str, Any],
    ) -> Optional[str]:
        """Validate execution parameters against the RestrictedExecutionPolicy envelope."""
        if not restriction_policy or not isinstance(restriction_policy, RestrictedExecutionPolicy):
            return "Invalid or missing restriction policy envelope."

        # Inferred capability check
        inferred_cap = self.policy_gate.capability_registry.infer_capability(self.name, args_dict)
        if inferred_cap not in restriction_policy.allowed_capabilities:
            return (
                f"Capability '{inferred_cap.value}' exceeds restricted capability envelope "
                f"{[c.value for c in restriction_policy.allowed_capabilities]}."
            )

        # Payload size limit
        serialized = json.dumps(args_dict, sort_keys=True)
        if len(serialized.encode("utf-8")) > restriction_policy.max_payload_size_bytes:
            return (
                f"Payload size {len(serialized)} bytes exceeds maximum permitted limit of "
                f"{restriction_policy.max_payload_size_bytes} bytes."
            )

        str_args = str(args_dict).lower()

        def _extract_all_strings(val: Any) -> List[str]:
            items: List[str] = []
            if isinstance(val, str):
                items.append(val)
            elif isinstance(val, dict):
                for k, v in val.items():
                    items.extend(_extract_all_strings(k))
                    items.extend(_extract_all_strings(v))
            elif isinstance(val, (list, tuple, set)):
                for item in val:
                    items.extend(_extract_all_strings(item))
            return items

        all_arg_strings = _extract_all_strings(args_dict)

        # Filesystem restrictions
        if restriction_policy.read_only_filesystem:
            fs_keywords = [
                "write", "delete", "unlink", "truncate", "overwrite", "append",
                "rename", "remove", "rmdir", "symlink", "link", "touch", "chmod", "chown"
            ]
            if inferred_cap in {Capability.WRITE_FILE, Capability.ADMIN} or any(
                k in str_args for k in fs_keywords
            ) or any(k in self.name.lower() for k in fs_keywords):
                return "Filesystem mutations strictly prohibited under read-only restriction."

        # Database restrictions
        if not restriction_policy.allow_database_writes:
            sql_mutation_regex = re.compile(
                r"\b(INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|REPLACE|MERGE|GRANT|REVOKE|EXEC|EXECUTE|CALL)\b",
                re.IGNORECASE,
            )
            has_db_mutation = False
            for s in all_arg_strings:
                clean_s = re.sub(r"/\*.*?\*/", " ", s, flags=re.DOTALL)
                clean_s = re.sub(r"--.*", " ", clean_s)
                if sql_mutation_regex.search(clean_s):
                    has_db_mutation = True
                    break

            if inferred_cap in {Capability.WRITE_DATABASE, Capability.ADMIN} or has_db_mutation or any(
                k in self.name.lower() for k in ["write_db", "insert", "update", "delete", "drop", "truncate", "modify_db", "db_exec"]
            ):
                return "Database writes strictly prohibited under restriction policy."

        # External messaging restrictions
        if not restriction_policy.allow_external_messaging:
            messaging_keywords = [
                "email", "slack", "sms", "webhook", "post_message", "discord", "telegram",
                "teams", "mattermost", "pagerduty", "pushover", "matrix", "notify", "broadcast",
                "publish_message", "send_chat", "emit_webhook", "dispatch_alert", "mail"
            ]
            has_msg_dest = any(
                any(k in s.lower() for k in ["webhook_url", "channel_id", "slack.com", "discord.com", "api.telegram.org"])
                for s in all_arg_strings
            )
            if inferred_cap == Capability.SEND_EXTERNAL_MESSAGE or any(
                k in self.name.lower() for k in messaging_keywords
            ) or has_msg_dest:
                return "External messaging strictly prohibited under restriction policy."

        # Secret access restrictions
        if not restriction_policy.allow_secret_access:
            if any(
                k in str_args for k in ["get_secret", "passwd", "credential", "api_key", "token", "private_key", ".env", "secret"]
            ) or any(k in self.name.lower() for k in ["secret", "credential", "vault", "token"]):
                return "Secret access strictly prohibited under restriction policy."

        # Network egress restrictions
        if not restriction_policy.allow_network_egress:
            if inferred_cap == Capability.NETWORK_EXTERNAL or any(
                kw in str_args for kw in ["http://", "https://", "ftp://", "ws://"]
            ):
                return "Network egress strictly prohibited under restriction policy."
        elif restriction_policy.allowed_network_domains:
            import urllib.parse
            urls = self.policy_gate._extract_all_urls(args_dict)
            for u in urls:
                try:
                    parsed = urllib.parse.urlparse(u)
                    hostname = parsed.hostname or ""
                    if not any(
                        hostname == dom or hostname.endswith("." + dom.lstrip("*."))
                        for dom in restriction_policy.allowed_network_domains
                    ):
                        return f"Egress to domain '{hostname}' not permitted under restriction policy."
                except Exception:
                    return f"Invalid or unparseable target URL: '{u}'."

        return None
