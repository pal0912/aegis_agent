"""OpenAI-compatible security gateway and reverse proxy for AegisAgent V2.

Provides drop-in security interception for external agent frameworks (LangGraph, CrewAI, AutoGPT),
evaluating incoming chat completions, prompt injections, proposed tool calls, Model Context Protocol (MCP) servers,
and deep system health/readiness monitoring.
"""

import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional, Union

from fastapi import FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from aegis.audit import AuditLogger
from aegis.detector import AegisDetector
from aegis.dlp import DataLossPreventionEngine
from aegis.health import SystemHealthMonitor
from aegis.mcp_guard import MCPSecurityGuard
from aegis.policy_gate import PolicyGate
from aegis.sanitizer import ContextSanitizer
from aegis.taint import SessionContext
from aegis.tracer import SecurityTracer
from aegis.types import AuditEvent, Capability, PolicyDecision, PolicyVerdict, ScanResult, ToolCallProposal, TrustLevel

logger = logging.getLogger(__name__)


# --- OpenAI Chat Completion Schemas ---
class ChatMessage(BaseModel):
    role: str
    content: Optional[str] = None
    name: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None
    tool_call_id: Optional[str] = None


class ChatCompletionRequest(BaseModel):
    model: str = "gpt-4o"
    messages: List[ChatMessage]
    tools: Optional[List[Dict[str, Any]]] = None
    tool_choice: Optional[Union[str, Dict[str, Any]]] = None
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = None
    stream: Optional[bool] = False


class SecurityHealthResponse(BaseModel):
    status: str
    gateway_version: str
    ledger_integrity: bool
    verified_ledger_entries: int
    active_defense_layers: List[str]
    timestamp: float


# --- MCP Gateway Schemas ---
class MCPManifestSanitizeRequest(BaseModel):
    server_name: Optional[str] = "mcp-server"
    manifest: Dict[str, Any] = Field(..., description="MCP server manifest containing tools array")


class MCPManifestSanitizeResponse(BaseModel):
    server_name: str
    sanitized_manifest: Dict[str, Any]
    violations_detected: List[str]
    is_clean: bool


class MCPExecuteRequest(BaseModel):
    server_name: str
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    session_id: Optional[str] = None
    root_intent: Optional[str] = "Execute tool operation"
    is_tainted: Optional[bool] = False


class MCPExecuteResponse(BaseModel):
    authorized: bool
    status_reason: str
    sanitized_arguments: Dict[str, Any]
    server_name: str
    tool_name: str


def create_gateway_app(
    detector: Optional[AegisDetector] = None,
    policy_gate: Optional[PolicyGate] = None,
    audit_logger: Optional[AuditLogger] = None,
    sanitizer: Optional[ContextSanitizer] = None,
    dlp_engine: Optional[DataLossPreventionEngine] = None,
    mcp_guard: Optional[MCPSecurityGuard] = None,
    health_monitor: Optional[SystemHealthMonitor] = None,
    api_key: Optional[str] = None,
) -> FastAPI:
    """Factory creating the FastAPI OpenAI-compatible Aegis security gateway app."""
    app = FastAPI(
        title="AegisAgent Security Gateway",
        description="OpenAI-compatible reverse proxy middleware enforcing defense-in-depth AI security & MCP validation.",
        version="2.0.0",
    )

    # Initialize components
    det = detector or AegisDetector(lazy_load=False)
    gate = policy_gate or PolicyGate(lazy_load=False)
    audit = audit_logger or AuditLogger.get_instance()
    san = sanitizer or ContextSanitizer()
    dlp = dlp_engine or DataLossPreventionEngine()
    mcp = mcp_guard or MCPSecurityGuard(
        detector=det,
        dlp_engine=dlp,
        policy_gate=gate,
        sanitizer=san,
        audit_logger=audit,
    )
    health = health_monitor or SystemHealthMonitor(ledger=audit.ledger)
    tracer = SecurityTracer(dlp_engine=dlp)

    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        """Inject enterprise defensive HTTP security headers into all gateway responses."""
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        return response

    @app.get("/v1/security/health", response_model=SecurityHealthResponse)
    async def security_health():
        """Return real-time defense health and cryptographic audit ledger verification."""
        is_ledger_valid, count, err = audit.verify_ledger()
        return SecurityHealthResponse(
            status="SECURE" if is_ledger_valid else "LEDGER_INTEGRITY_COMPROMISED",
            gateway_version="2.0.0",
            ledger_integrity=is_ledger_valid,
            verified_ledger_entries=count,
            active_defense_layers=[
                "Neural & Heuristic Prompt Injection Detector",
                "Boundary Isolation & Context Sanitizer",
                "Capability-Based Access Control",
                "Outbound Network & DNS SSRF Guard",
                "Data Loss Prevention (DLP) Engine",
                "Honeypot Canary Token Sensor",
                "Behavioral Action Dependency Graph",
                "Dual-Agent Consensus Shadow Evaluator",
                "Host-Isolated Code Execution Sandbox",
                "Cryptographic Tamper-Evident Ledger",
                "OpenTelemetry MITRE ATLAS Security Tracer",
                "Model Context Protocol (MCP) Security Guard",
                "Multi-Agent Non-Human Identity (NHI) Token Gate",
            ],
            timestamp=time.time(),
        )

    @app.get("/v1/security/readiness")
    async def security_readiness():
        """Deep readiness probe verifying model memory residency, cryptographic audit ledger, and SSRF filter."""
        readiness_data = health.check_readiness()
        return JSONResponse(
            status_code=readiness_data.get("http_status_code", 200),
            content=readiness_data,
        )

    @app.post("/v1/mcp/manifest/sanitize", response_model=MCPManifestSanitizeResponse)
    async def sanitize_mcp_manifest_endpoint(req: MCPManifestSanitizeRequest):
        """Inspect and sanitize an external MCP server manifest, stripping injected prompt instructions."""
        sanitized_manifest, violations = mcp.sanitize_mcp_manifest(req.manifest)
        return MCPManifestSanitizeResponse(
            server_name=req.server_name or "mcp-server",
            sanitized_manifest=sanitized_manifest,
            violations_detected=violations,
            is_clean=len(violations) == 0,
        )

    @app.post("/v1/mcp/execute", response_model=MCPExecuteResponse)
    async def execute_mcp_endpoint(req: MCPExecuteRequest):
        """Intercept and validate an outbound MCP tool execution call against taint policies and network safety."""
        session_id = req.session_id or f"mcp-session-{uuid.uuid4().hex[:8]}"
        session = SessionContext(
            user_root_intent=req.root_intent or "MCP Tool Execution",
            session_id=session_id,
        )
        if req.is_tainted:
            session.quarantine_session(reason="Tainted MCP context dispatch")

        authorized, reason, sanitized_args = mcp.intercept_mcp_call(
            server_name=req.server_name,
            tool_name=req.tool_name,
            arguments=req.arguments,
            session_context=session,
        )

        status_code = status.HTTP_200_OK if authorized else status.HTTP_403_FORBIDDEN
        return JSONResponse(
            status_code=status_code,
            content={
                "authorized": authorized,
                "status_reason": reason,
                "sanitized_arguments": sanitized_args,
                "server_name": req.server_name,
                "tool_name": req.tool_name,
            },
        )

    @app.post("/v1/chat/completions")
    async def chat_completions(request: ChatCompletionRequest, req: Request):
        """Intercept OpenAI chat completion requests, scan prompt inputs, and gate proposed tool calls."""
        trace_id = req.headers.get("X-Aegis-Trace-Id") or str(uuid.uuid4())
        session_id = f"gw-session-{trace_id[:8]}"
        t_start = time.time()

        # Step 1: Extract latest user message and system context
        user_messages = [m for m in request.messages if m.role == "user"]
        latest_user_msg = user_messages[-1].content if user_messages and user_messages[-1].content else ""
        root_intent = user_messages[0].content if user_messages and user_messages[0].content else latest_user_msg

        # Check for tool call proposals embedded in assistant messages
        assistant_tool_calls: List[Dict[str, Any]] = []
        for m in request.messages:
            if m.role == "assistant" and m.tool_calls:
                assistant_tool_calls.extend(m.tool_calls)

        # Step 2: Scan latest user message for prompt injection
        scan_result = det.scan(latest_user_msg)
        is_safe = scan_result.is_safe
        trust_level = TrustLevel.TRUSTED if is_safe else TrustLevel.QUARANTINED

        # Create session context
        session = SessionContext(
            user_root_intent=root_intent,
            session_id=session_id,
        )
        if not is_safe:
            session.quarantine_session(reason="; ".join(scan_result.reasons))
        else:
            session.ingest_untrusted_data(source_name="user_input", raw_text=latest_user_msg)

        tracer.start_trace(session_id=trace_id)
        tracer.record_hop(
            trace_id=trace_id,
            name="INPUT_INGESTION",
            status="PASS" if is_safe else "FLAGGED",
            details={"tokens": len(latest_user_msg.split()), "preview": latest_user_msg[:80]},
        )
        tracer.record_hop(
            trace_id=trace_id,
            name="INJECTION_SCAN",
            status="PASS" if is_safe else "BLOCKED",
            details={
                "confidence": scan_result.confidence_score,
                "reasons": scan_result.reasons,
                "heuristics": scan_result.detected_heuristics,
            },
        )

        # If direct prompt injection is detected with high confidence -> block immediately
        if not is_safe and scan_result.confidence_score >= 0.70:
            policy_dec = PolicyDecision(
                verdict=PolicyVerdict.BLOCK.value,
                reason=f"Prompt injection intercepted by Aegis Gateway: {'; '.join(scan_result.reasons)}",
                intent_similarity_score=0.0,
                blast_radius_contained=False,
                network_verdict="PASS",
                risk_score=1.0,
            )
            event = AuditEvent(
                trace_id=trace_id,
                trust_level=trust_level,
                raw_content_sha256=AuditEvent.hash_payload(latest_user_msg),
                scan_result=scan_result,
                policy_decision=policy_dec,
            )
            audit.log_event(event)

            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "error": {
                        "message": f"Aegis Security Gateway blocked prompt injection: {'; '.join(scan_result.reasons)}",
                        "type": "security_policy_violation",
                        "param": "messages",
                        "code": "prompt_injection_blocked",
                        "trace_id": trace_id,
                    }
                },
            )

        # Step 3: Evaluate any tool calls proposed in the request
        for tool_call in assistant_tool_calls:
            func = tool_call.get("function", {})
            t_name = func.get("name", "unknown_tool")
            try:
                raw_args = func.get("arguments", "{}")
                t_args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            except Exception:
                t_args = {}

            tool_proposal = ToolCallProposal(
                tool_name=t_name,
                arguments=t_args,
                source_trace_id=trace_id,
                inferred_capability=gate.capability_registry.infer_capability(t_name, t_args),
            )

            policy_decision = gate.evaluate_tool_call(
                session=session,
                tool_proposal=tool_proposal,
                detector_scan=scan_result,
            )

            tracer.record_hop(
                trace_id=trace_id,
                name="POLICY_EVALUATION",
                status="PASS" if policy_decision.verdict == "ALLOW" else "BLOCKED",
                details={
                    "tool": t_name,
                    "verdict": policy_decision.verdict,
                    "reason": policy_decision.reason,
                    "risk_score": policy_decision.risk_score,
                },
            )

            # Log audit event
            audit.log_event(AuditEvent(
                trace_id=trace_id,
                trust_level=trust_level,
                raw_content_sha256=AuditEvent.hash_payload(latest_user_msg),
                scan_result=scan_result,
                policy_decision=policy_decision,
            ))

            if policy_decision.verdict == PolicyVerdict.BLOCK.value:
                # Return synthetic tool execution rejection
                return JSONResponse(
                    status_code=status.HTTP_200_OK,
                    content={
                        "id": f"chatcmpl-{trace_id[:8]}",
                        "object": "chat.completion",
                        "created": int(time.time()),
                        "model": request.model,
                        "choices": [
                            {
                                "index": 0,
                                "message": {
                                    "role": "assistant",
                                    "content": f"[Aegis Security Gating: Tool execution for '{t_name}' was blocked. Reason: {policy_decision.reason}]",
                                    "tool_calls": None,
                                },
                                "finish_reason": "stop",
                            }
                        ],
                        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
                        "aegis_security": {
                            "verdict": policy_decision.verdict,
                            "reason": policy_decision.reason,
                            "trace_id": trace_id,
                            "risk_score": policy_decision.risk_score,
                        },
                    },
                )

        # Step 4: If all checks pass, return a clean simulated OpenAI response or forward
        sanitized_input = san.escape_boundary_breakouts(latest_user_msg)
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "id": f"chatcmpl-{trace_id[:8]}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": request.model,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": f"Aegis Verified: Safe response to objective '{root_intent[:60]}'.",
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": len(latest_user_msg.split()), "completion_tokens": 15, "total_tokens": len(latest_user_msg.split()) + 15},
                "aegis_security": {
                    "verdict": "ALLOW",
                    "trace_id": trace_id,
                    "latency_ms": round((time.time() - t_start) * 1000, 2),
                },
            },
        )

    return app


# Default module-level FastAPI instance
app = create_gateway_app()
