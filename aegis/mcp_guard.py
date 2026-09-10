"""Model Context Protocol (MCP) Security Guard for AegisAgent V2.

Intercepts external MCP server manifests, prevents MCP prompt injection inside tool schemas,
enforces least-privilege capability boundaries, and filters data exfiltration parameters.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from aegis.audit import AuditLogger
from aegis.capabilities import CapabilityRegistry
from aegis.detector import InjectionDetector
from aegis.dlp import DataLossPreventionEngine
from aegis.network_guard import OutboundNetworkGuard
from aegis.policy_gate import PolicyGate
from aegis.sanitizer import ContextSanitizer
from aegis.taint import SessionContext
from aegis.types import AuditEvent, Capability, MitreAtlasTechnique, PolicyDecision, PolicyVerdict, ScanResult, ToolCallProposal, TrustLevel

logger = logging.getLogger(__name__)


class MCPSecurityGuard:
    """Security proxy and validation gateway for Model Context Protocol (MCP) tool servers."""

    def __init__(
        self,
        detector: Optional[InjectionDetector] = None,
        capability_registry: Optional[CapabilityRegistry] = None,
        dlp_engine: Optional[DataLossPreventionEngine] = None,
        network_guard: Optional[OutboundNetworkGuard] = None,
        policy_gate: Optional[PolicyGate] = None,
        sanitizer: Optional[ContextSanitizer] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        """Initialize MCP guard with injection detector, capability registry, DLP, and network guard."""
        self.detector = detector or InjectionDetector(lazy_load=False)
        self.capability_registry = capability_registry or CapabilityRegistry()
        self.dlp = dlp_engine or DataLossPreventionEngine()
        self.network_guard = network_guard or OutboundNetworkGuard()
        self.policy_gate = policy_gate or PolicyGate(lazy_load=False)
        self.sanitizer = sanitizer or ContextSanitizer()
        self.audit_logger = audit_logger or AuditLogger.get_instance()
        self._url_regex = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

    def _extract_urls(self, obj: Any) -> List[str]:
        """Recursively find all URLs in input parameters."""
        urls: List[str] = []
        if isinstance(obj, str):
            for match in self._url_regex.finditer(obj):
                urls.append(match.group(0))
        elif isinstance(obj, dict):
            for v in obj.values():
                urls.extend(self._extract_urls(v))
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                urls.extend(self._extract_urls(item))
        return urls

    def sanitize_mcp_manifest(
        self, server_manifest: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], List[str]]:
        """Inspect and sanitize external MCP server manifest tools and descriptions.

        Scans tool descriptions for concealed prompt injection directives, assigns deterministic
        operational capabilities to each tool, and neutralizes XML boundary breakouts.

        Args:
            server_manifest: Manifest dictionary containing a "tools" array emitted by an MCP server.

        Returns:
            Tuple of (sanitized_manifest_dict, list_of_flagged_violations).
        """
        violations: List[str] = []
        sanitized_manifest = dict(server_manifest)
        tools = sanitized_manifest.get("tools", [])
        sanitized_tools: List[Dict[str, Any]] = []

        for tool in tools:
            tool_copy = dict(tool)
            tool_name = tool_copy.get("name", "unnamed_tool")
            description = tool_copy.get("description", "")

            # 1. Scan tool description with neural & heuristic classifier
            if description:
                scan_res = self.detector.scan(description, threshold=0.75)
                if not scan_res.is_safe:
                    violation_msg = (
                        f"MCP_PROMPT_INJECTION_DETECTED: Tool '{tool_name}' contains concealed "
                        f"instruction override in description (confidence: {scan_res.confidence_score:.2f})."
                    )
                    violations.append(violation_msg)
                    logger.warning(violation_msg)
                    # Redact and neutralize prompt injection directives
                    description = re.sub(
                        r"(?i)\b(?:system\s+override|disregard\s+prior|ignore\s+all|override\s+system|new\s+system\s+directive).*$",
                        "[INJECTION_NEUTRALIZED]",
                        description,
                    ).strip()

                # Neutralize boundary breakouts and executable HTML/Markdown in description
                cleaned_desc = self.sanitizer.strip_dangerous_tags(description)
                escaped_desc = self.sanitizer.escape_boundary_breakouts(cleaned_desc)
                tool_copy["description"] = escaped_desc

            # 2. Assign deterministic operational capability mapping
            inferred_cap = self.capability_registry.infer_capability(tool_name, {})
            tool_copy["assigned_capability"] = inferred_cap.value

            sanitized_tools.append(tool_copy)

        sanitized_manifest["tools"] = sanitized_tools
        return sanitized_manifest, violations

    def intercept_mcp_call(
        self,
        server_name: str,
        tool_name: str,
        arguments: Dict[str, Any],
        session_context: SessionContext,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """Intercept and validate an outbound execution request to an external MCP server tool.

        Applies DLP sanitization, capability privilege checks under tainted session states,
        and outbound SSRF network verification.

        Args:
            server_name: Identifier of target MCP server (e.g. 'mcp-filesystem', 'mcp-github').
            tool_name: Specific tool being invoked.
            arguments: Parameter dictionary provided for tool invocation.
            session_context: Active execution context with intent and taint status.

        Returns:
            Tuple of (is_authorized: bool, status_reason: str, sanitized_arguments: dict).
        """
        # 1. DLP sanitization on parameters
        sanitized_args, dlp_violations = self.dlp.sanitize_tool_args(arguments)
        is_tainted = session_context.is_session_tainted()

        # 2. Capability inference & least-privilege boundary gating
        inferred_cap = self.capability_registry.infer_capability(tool_name, sanitized_args)

        if inferred_cap == Capability.UNKNOWN:
            reason = (
                f"MCP Unregistered Tool Blocked: Tool '{tool_name}' on server '{server_name}' "
                f"is unclassified and unregistered in CapabilityRegistry."
            )
            logger.error(reason)
            self._record_mcp_audit(
                server_name=server_name,
                tool_name=tool_name,
                args=sanitized_args,
                session=session_context,
                verdict=PolicyVerdict.BLOCK,
                reason=reason,
                mitre_tags=[MitreAtlasTechnique.UNAUTHORIZED_COMMAND_EXECUTION.value],
            )
            return False, reason, sanitized_args

        if is_tainted:
            # Enforce capability constraints on tainted sessions
            if not self.capability_registry.is_allowed_for_tainted_session(inferred_cap):
                reason = (
                    f"MCP Privilege Escalation Blocked: Tool '{tool_name}' on server '{server_name}' "
                    f"requires capability '{inferred_cap.value}', which is restricted for tainted sessions."
                )
                logger.error(reason)
                self._record_mcp_audit(
                    server_name=server_name,
                    tool_name=tool_name,
                    args=sanitized_args,
                    session=session_context,
                    verdict=PolicyVerdict.BLOCK,
                    reason=reason,
                    mitre_tags=[MitreAtlasTechnique.UNAUTHORIZED_COMMAND_EXECUTION.value],
                )
                return False, reason, sanitized_args

        # 3. Outbound Network & SSRF Inspection
        urls = self._extract_urls(sanitized_args)
        for url in urls:
            is_valid_url, net_reason = self.network_guard.validate_url(url)
            if not is_valid_url:
                reason = f"MCP Network Guard Violation: Blocked illegal egress target '{url}' - {net_reason}"
                logger.error(reason)
                self._record_mcp_audit(
                    server_name=server_name,
                    tool_name=tool_name,
                    args=sanitized_args,
                    session=session_context,
                    verdict=PolicyVerdict.BLOCK,
                    reason=reason,
                    mitre_tags=[MitreAtlasTechnique.ML_RECONNAISSANCE.value],
                )
                return False, reason, sanitized_args

        # 4. Success / Authorized Execution
        reason = f"MCP tool '{tool_name}' on server '{server_name}' authorized under capability '{inferred_cap.value}'."
        self._record_mcp_audit(
            server_name=server_name,
            tool_name=tool_name,
            args=sanitized_args,
            session=session_context,
            verdict=PolicyVerdict.ALLOW,
            reason=reason,
            mitre_tags=[],
        )
        return True, reason, sanitized_args

    def _record_mcp_audit(
        self,
        server_name: str,
        tool_name: str,
        args: Dict[str, Any],
        session: SessionContext,
        verdict: PolicyVerdict,
        reason: str,
        mitre_tags: List[str],
    ) -> None:
        """Emit structured audit record to cryptographic ledger."""
        try:
            decision = PolicyDecision(
                verdict=verdict.value,
                reason=reason,
                intent_similarity_score=1.0 if verdict == PolicyVerdict.ALLOW else 0.0,
                blast_radius_contained=True if verdict == PolicyVerdict.BLOCK else False,
            )
            trust_lvl = session.trust_level if isinstance(session.trust_level, TrustLevel) else TrustLevel(session.trust_level)
            event = AuditEvent(
                trace_id=session.session_id,
                trust_level=trust_lvl,
                raw_content_sha256=AuditEvent.hash_payload(json.dumps(args, sort_keys=True)),
                policy_decision=decision,
                mitre_atlas_tags=mitre_tags,
            )
            self.audit_logger.log_event(event)
        except Exception as exc:
            logger.error(f"Failed to record MCP audit event: {exc}")
