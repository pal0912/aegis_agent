"""Distributed security tracer, MITRE ATLAS threat classifier, and OpenTelemetry SIEM exporter.

Provides correlated execution tracing across input ingestion, memory state, neural scanning,
and policy gate decisions while generating standards-compliant OTLP JSON logs for SIEM integration.
"""

from datetime import datetime, timezone
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
import uuid

from aegis.dlp import DataLossPreventionEngine
from aegis.types import (
    AuditEvent,
    Capability,
    MitreAtlasTechnique,
    PolicyDecision,
    PolicyVerdict,
    ScanResult,
    TraceHop,
    TrustLevel,
)

logger = logging.getLogger(__name__)


class SecurityTracer:
    """Enterprise distributed security tracer generating correlated spans and MITRE ATLAS tags."""

    def __init__(self, dlp_engine: Optional[DataLossPreventionEngine] = None) -> None:
        """Initialize SecurityTracer with DLP redaction and trace cache."""
        self.dlp = dlp_engine or DataLossPreventionEngine(enable_pii=True)
        self._traces: Dict[str, List[TraceHop]] = {}

    def start_trace(self, session_id: Optional[str] = None) -> str:
        """Initialize a new correlated security trace ID.

        Args:
            session_id: Optional existing session ID to use as trace ID.

        Returns:
            Unique trace_id string.
        """
        trace_id = session_id or str(uuid.uuid4())
        if trace_id not in self._traces:
            self._traces[trace_id] = []
        return trace_id

    def record_hop(
        self,
        trace_id: str,
        name: str,
        status: str,
        latency_ms: float = 0.0,
        details: Optional[Dict[str, Any]] = None,
    ) -> TraceHop:
        """Record an ordered execution milestone within the active trace.

        Milestone sequence:
        INPUT_INGESTION -> INJECTION_SCAN -> MEMORY_STATE -> POLICY_EVALUATION -> NETWORK_GUARD -> EXECUTION_OUTCOME

        Args:
            trace_id: Active trace identifier.
            name: Milestone name (e.g., 'INPUT_INGESTION', 'POLICY_EVALUATION').
            status: Outcome status ('PASS', 'BLOCKED', 'FLAGGED', 'ESCALATED', 'ROLLBACK').
            latency_ms: Execution duration for this hop in milliseconds.
            details: Contextual forensic data.

        Returns:
            Created and sanitized TraceHop instance.
        """
        raw_details = details or {}
        # Apply DLP sanitization to all trace hop details
        sanitized_details, _ = self.dlp.sanitize_tool_args(raw_details)

        hop = TraceHop(
            hop_id=f"hop_{uuid.uuid4().hex[:8]}",
            name=name.upper().strip(),
            status=status.upper().strip(),
            latency_ms=round(max(0.0, latency_ms), 2),
            details=sanitized_details,
        )

        if trace_id not in self._traces:
            self._traces[trace_id] = []

        self._traces[trace_id].append(hop)
        logger.debug("Trace '%s' recorded hop [%s] -> %s", trace_id, hop.name, hop.status)
        return hop

    def get_trace_hops(self, trace_id: str) -> List[TraceHop]:
        """Retrieve full chronological hop list for a trace."""
        return list(self._traces.get(trace_id, []))

    def map_mitre_atlas_techniques(
        self,
        scan_result: Optional[ScanResult] = None,
        policy_decision: Optional[PolicyDecision] = None,
        capability: Optional[Capability] = None,
    ) -> List[str]:
        """Map security scan findings and policy decisions to standard MITRE ATLAS threat techniques.

        Args:
            scan_result: Optional ScanResult from InjectionDetector.
            policy_decision: Optional PolicyDecision from PolicyGate.
            capability: Optional target Capability.

        Returns:
            List of matching MITRE ATLAS taxonomy string labels.
        """
        techniques: List[str] = []

        # 1. Evaluate Scan Result Findings
        if scan_result and not scan_result.is_safe:
            reasons_str = " ".join(scan_result.reasons).lower()
            heuristics_str = " ".join(scan_result.detected_heuristics).lower()
            combined = reasons_str + " " + heuristics_str

            if any(k in combined for k in ["jailbreak", "roleplay", "persona", "dan"]):
                techniques.append(MitreAtlasTechnique.LLM_JAILBREAK.value)
            elif any(k in combined for k in ["base64", "zero-width", "homoglyph", "obfuscation", "rot13"]):
                techniques.append(MitreAtlasTechnique.EVASION.value)
                techniques.append(MitreAtlasTechnique.LLM_PROMPT_INJECTION.value)
            else:
                techniques.append(MitreAtlasTechnique.LLM_PROMPT_INJECTION.value)

        # 2. Evaluate Policy Decision Findings
        if policy_decision:
            reason_str = policy_decision.reason.lower()

            if policy_decision.canary_tripped or "honeypot" in reason_str or "canary" in reason_str:
                techniques.append(MitreAtlasTechnique.CREDENTIAL_ACCESS.value)
                techniques.append(MitreAtlasTechnique.EXFILTRATION_SIDE_CHANNELS.value)

            if "ssrf" in reason_str or policy_decision.network_verdict.startswith("BLOCKED_SSRF"):
                techniques.append(MitreAtlasTechnique.ML_RECONNAISSANCE.value)

            if policy_decision.memory_rollback_triggered or "memory" in reason_str or "poison" in reason_str:
                techniques.append(MitreAtlasTechnique.CONTEXT_POISONING.value)

            if "exfiltration" in reason_str or policy_decision.dlp_violations or policy_decision.field_lineage_violations:
                techniques.append(MitreAtlasTechnique.EXFILTRATION_SIDE_CHANNELS.value)

            if (
                capability in {Capability.EXECUTE_CODE, Capability.ADMIN}
                or "shell" in reason_str
                or "command" in reason_str
                or policy_decision.behavioral_state == "CRITICAL"
                or "behavioral guard" in reason_str
            ):
                techniques.append(MitreAtlasTechnique.UNAUTHORIZED_COMMAND_EXECUTION.value)

        # Default fallback if blocked without specific match
        if not techniques and policy_decision and policy_decision.verdict == PolicyVerdict.BLOCK.value:
            techniques.append(MitreAtlasTechnique.LLM_PROMPT_INJECTION.value)

        # Return unique, sorted list
        return sorted(set(techniques))

    def export_otlp_log(self, event: AuditEvent) -> Dict[str, Any]:
        """Format an internal AuditEvent into a standardized OpenTelemetry / SIEM JSON log record.

        Compatible with Splunk, Elastic Common Schema (ECS), Datadog, and AWS CloudWatch.

        Args:
            event: Source AuditEvent model.

        Returns:
            Dictionary formatted according to the OpenTelemetry Log Data Model specification.
        """
        # Determine log severity based on trust level and policy verdict
        verdict = event.policy_decision.verdict if event.policy_decision else "UNKNOWN"
        is_threat = (
            event.trust_level == TrustLevel.QUARANTINED
            or verdict == PolicyVerdict.BLOCK.value
            or (event.policy_decision and event.policy_decision.canary_tripped)
        )

        severity_number = 17 if is_threat else (13 if verdict == PolicyVerdict.REQUIRE_HUMAN_APPROVAL.value else 9)
        severity_text = "ERROR" if is_threat else (
            "WARN" if verdict == PolicyVerdict.REQUIRE_HUMAN_APPROVAL.value else "INFO"
        )

        body_message = (
            f"Aegis Security Event: Verdict={verdict} | Trust={event.trust_level.value} | "
            f"Trace={event.trace_id[:8]}"
        )
        if event.policy_decision:
            body_message += f" | Reason={event.policy_decision.reason}"

        # Populate OpenTelemetry Log Record Schema
        otlp_record = {
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "aegis-security-guard"}},
                            {"key": "service.version", "value": {"stringValue": "2.3.0"}},
                            {"key": "deployment.environment", "value": {"stringValue": "production"}},
                        ]
                    },
                    "scopeLogs": [
                        {
                            "scope": {"name": "aegis.audit.tracer", "version": "2.3.0"},
                            "logRecords": [
                                {
                                    "timeUnixNano": str(int(datetime.now(timezone.utc).timestamp() * 1e9)),
                                    "observedTimeUnixNano": str(int(datetime.now(timezone.utc).timestamp() * 1e9)),
                                    "severityNumber": severity_number,
                                    "severityText": severity_text,
                                    "body": {"stringValue": body_message},
                                    "attributes": [
                                        {"key": "aegis.trace_id", "value": {"stringValue": event.trace_id}},
                                        {"key": "aegis.trust_level", "value": {"stringValue": event.trust_level.value}},
                                        {"key": "aegis.payload_sha256", "value": {"stringValue": event.raw_content_sha256}},
                                        {"key": "aegis.policy_verdict", "value": {"stringValue": verdict}},
                                        {
                                            "key": "aegis.risk_score",
                                            "value": {
                                                "doubleValue": (
                                                    event.policy_decision.risk_score
                                                    if event.policy_decision
                                                    else 0.0
                                                )
                                            },
                                        },
                                        {
                                            "key": "aegis.blast_radius_contained",
                                            "value": {
                                                "boolValue": (
                                                    event.policy_decision.blast_radius_contained
                                                    if event.policy_decision
                                                    else False
                                                )
                                            },
                                        },
                                        {
                                            "key": "aegis.mitre_atlas_techniques",
                                            "value": {
                                                "arrayValue": {
                                                    "values": [{"stringValue": t} for t in event.mitre_atlas_tags]
                                                }
                                            },
                                        },
                                        {
                                            "key": "aegis.trace_hops_count",
                                            "value": {"intValue": len(event.trace_hops)},
                                        },
                                    ],
                                    "traceId": event.trace_id.replace("-", "")[:32],
                                    "spanId": uuid.uuid4().hex[:16],
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        return otlp_record

    def clear(self, trace_id: Optional[str] = None) -> None:
        """Clear cached trace history."""
        if trace_id:
            self._traces.pop(trace_id, None)
        else:
            self._traces.clear()
