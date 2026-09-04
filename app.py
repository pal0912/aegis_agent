"""Streamlit Enterprise Security Console for AegisAgent.

Interactive dashboard for real-time prompt injection detection, taint tracking,
intent alignment analysis, deterministic policy gating, and live audit telemetry.
"""

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import streamlit as st
import torch

from aegis.audit import AuditLogger
from aegis.detector import InjectionDetector
from aegis.policy_gate import PolicyGate
from aegis.sanitizer import ContextSanitizer
from aegis.taint import SessionContext
from aegis.types import AuditEvent, ScanResult, ToolCallProposal, TrustLevel
from evals.attack_dataset import ATTACK_DATASET
from evals.benign_dataset import BENIGN_DATASET

# Page Configuration
st.set_page_config(
    page_title="AegisAgent | Enterprise AI Security Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Enterprise CSS Theme
st.markdown(
    """
    <style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(90deg, #00f2fe 0%, #4facfe 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .sub-title {
        color: #94a3b8;
        font-size: 1.05rem;
        margin-bottom: 1.5rem;
    }
    .status-card {
        background: #1e293b;
        border-radius: 10px;
        padding: 1.2rem;
        border: 1px solid #334155;
        margin-bottom: 1rem;
    }
    .badge-pass {
        background-color: #065f46;
        color: #34d399;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .badge-block {
        background-color: #7f1d1d;
        color: #f87171;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .badge-blast {
        background-color: #581c87;
        color: #c084fc;
        padding: 6px 12px;
        border-radius: 8px;
        font-weight: 800;
        font-size: 0.95rem;
        border: 1px solid #a855f7;
    }
    .badge-tainted {
        background-color: #78350f;
        color: #fbbf24;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .raw-xml {
        background: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 12px;
        font-family: 'Courier New', Courier, monospace;
        font-size: 0.88rem;
        color: #38bdf8;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource(show_spinner="Loading Aegis Neural Security Engines...")
def get_security_engines():
    """Cache and load InjectionDetector, PolicyGate, Sanitizer, and AuditLogger."""
    detector = InjectionDetector(lazy_load=False)
    policy_gate = PolicyGate(lazy_load=False)
    sanitizer = ContextSanitizer()
    audit_logger = AuditLogger.get_instance(log_filepath="aegis_audit.jsonl")
    return detector, policy_gate, sanitizer, audit_logger


# Sidebar Controls
st.sidebar.title("🛡️ Aegis Engine Config")
st.sidebar.markdown("---")

device_status = "CUDA (GPU)" if torch.cuda.is_available() else "CPU (Standard)"
st.sidebar.info(f"**Compute Acceleration:** {device_status}")

detection_threshold = st.sidebar.slider(
    "DeBERTa Sensitivity Threshold",
    min_value=0.10,
    max_value=0.99,
    value=0.80,
    step=0.01,
    help="Higher threshold requires stronger confidence to flag injections.",
)

similarity_threshold = st.sidebar.slider(
    "Intent Divergence Threshold",
    min_value=0.10,
    max_value=0.90,
    value=0.35,
    step=0.01,
    help="Minimum semantic similarity required to permit high-impact actions.",
)

enable_heuristics = st.sidebar.checkbox(
    "Enable Heuristic Pre-Filtering",
    value=True,
    help="Fast regex signature engine for immediate exploit matching.",
)

st.sidebar.markdown("---")
st.sidebar.subheader("Registered High-Impact Tools")
st.sidebar.code(
    "send_email\nexecute_shell\ndelete_file\nwrite_db\ntransfer_funds\ndrop_table",
    language="text",
)

# Header
st.markdown('<div class="main-title">AegisAgent Security Console</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-title">Enterprise-Grade Defense-in-Depth Security Middleware & Deterministic Policy Gate</div>',
    unsafe_allow_html=True,
)

# Load engines
detector, policy_gate, sanitizer, audit_logger = get_security_engines()
policy_gate.SIMILARITY_THRESHOLD = similarity_threshold

# Main Form Area
col_left, col_right = st.columns([1, 1], gap="large")

with col_left:
    st.subheader("1. User Intent & Ingested Payload")

    user_intent = st.text_input(
        "Verified User Root Intent",
        value="Summarize customer feedback from our webpage and extract positive remarks.",
        help="The direct, authorized prompt given by the human user.",
    )

    preset_choice = st.selectbox(
        "Load Attack Vector Preset (or choose Custom)",
        options=["-- Custom Input --"] + [f"{a['id']}: {a['name']} ({a['family']})" for a in ATTACK_DATASET],
        index=1,
    )

    selected_attack = None
    default_payload = ""
    default_tool_name = "read_file"
    default_tool_args = '{"path": "feedback.txt"}'

    if preset_choice != "-- Custom Input --":
        atk_id = preset_choice.split(":")[0].strip()
        selected_attack = next((a for a in ATTACK_DATASET if a["id"] == atk_id), None)
        if selected_attack:
            default_payload = selected_attack["payload"]
            default_tool_name = selected_attack["simulated_tool_proposal"]["tool_name"]
            default_tool_args = json.dumps(selected_attack["simulated_tool_proposal"]["arguments"], indent=2)

    ingested_text = st.text_area(
        "Untrusted External Data Ingestion (e.g., Web Page, Email, PDF, API)",
        value=default_payload,
        height=180,
        help="Raw text retrieved from third-party or untrusted external context.",
    )

with col_right:
    st.subheader("2. Simulated Agent Action Proposal")

    tool_name_input = st.selectbox(
        "Proposed Tool Name",
        options=[
            "execute_shell",
            "send_email",
            "delete_file",
            "write_db",
            "transfer_funds",
            "drop_table",
            "web_search",
            "read_file",
            "read_db",
            "get_weather",
        ],
        index=0 if default_tool_name == "execute_shell" else (
            1 if default_tool_name == "send_email" else (
                2 if default_tool_name == "delete_file" else (
                    3 if default_tool_name == "write_db" else (
                        4 if default_tool_name == "transfer_funds" else (
                            5 if default_tool_name == "drop_table" else 7
                        )
                    )
                )
            )
        ),
    )

    tool_args_str = st.text_area(
        "Tool Arguments (JSON)",
        value=default_tool_args,
        height=110,
        help="Parameters passed by the autonomous agent to the requested tool.",
    )

    try:
        parsed_tool_args = json.loads(tool_args_str)
    except Exception:
        parsed_tool_args = {"raw_input": tool_args_str}

    st.markdown("<br>", unsafe_allow_html=True)
    run_pipeline = st.button("🚀 Run Aegis Defense Pipeline", type="primary", use_container_width=True)

# Pipeline Execution
if run_pipeline:
    st.markdown("---")
    st.subheader("3. Defense-in-Depth Execution Trace")

    t_start = time.perf_counter()

    # Step 1: Session Context & Taint Tracking
    session = SessionContext(user_root_intent=user_intent)
    session.ingest_untrusted_data(source_name="external_retrieval", raw_text=ingested_text)

    # Step 2: Multi-Layer Prompt Injection Scanner
    if not enable_heuristics:
        # Temporarily clear heuristics if disabled
        orig_rules = detector.heuristic_rules
        detector.heuristic_rules = []
        scan_result = detector.scan(ingested_text, threshold=detection_threshold)
        detector.heuristic_rules = orig_rules
    else:
        scan_result = detector.scan(ingested_text, threshold=detection_threshold)

    # Step 3: XML Sanitization & Passive Directive
    if scan_result.is_safe:
        sanitized_context = sanitizer.sanitize_and_encapsulate(ingested_text, source_label="web_crawler")
    else:
        session.quarantine_session(reason="; ".join(scan_result.reasons))
        sanitized_context = "[AEGIS QUARANTINE]: Payload isolated due to detected injection pattern."

    # Step 4: Policy Gate Tool Proposal Evaluation
    proposal = ToolCallProposal(
        tool_name=tool_name_input,
        arguments=parsed_tool_args,
        source_trace_id=session.session_id,
    )

    policy_decision = policy_gate.evaluate_tool_call(
        session=session,
        tool_proposal=proposal,
        detector_scan=scan_result,
    )

    # Step 5: Audit Logging
    audit_event = AuditEvent(
        trace_id=session.session_id,
        trust_level=session.trust_level,
        raw_content_sha256=AuditEvent.hash_payload(ingested_text),
        scan_result=scan_result,
        policy_decision=policy_decision,
    )
    audit_logger.log_event(audit_event)

    total_latency_ms = (time.perf_counter() - t_start) * 1000.0

    # Render Visual Breadcrumbs (4 Columns)
    b1, b2, b3, b4 = st.columns(4)

    with b1:
        st.markdown("**Step 1: Ingestion Scan**")
        if scan_result.is_safe:
            st.markdown('<span class="badge-pass">PASS / SAFE</span>', unsafe_allow_html=True)
            st.caption(f"Score: {scan_result.confidence_score:.2f} | Latency: {scan_result.latency_ms:.1f}ms")
        else:
            st.markdown('<span class="badge-block">QUARANTINE / THREAT</span>', unsafe_allow_html=True)
            st.caption(f"Confidence: {scan_result.confidence_score:.2f} | Latency: {scan_result.latency_ms:.1f}ms")

    with b2:
        st.markdown("**Step 2: Taint Lineage**")
        if session.is_session_tainted():
            st.markdown(f'<span class="badge-tainted">TAINTED ({session.trust_level.value})</span>', unsafe_allow_html=True)
            st.caption("External context ingested")
        else:
            st.markdown('<span class="badge-pass">CLEAN / TRUSTED</span>', unsafe_allow_html=True)
            st.caption("User direct intent only")

    with b3:
        st.markdown("**Step 3: Intent Similarity**")
        sim_val = max(0.0, min(1.0, policy_decision.intent_similarity_score))
        st.progress(sim_val)
        st.caption(f"Score: **{policy_decision.intent_similarity_score:.4f}** (Threshold: {similarity_threshold:.2f})")

    with b4:
        st.markdown("**Step 4: Policy Verdict**")
        if policy_decision.verdict == "ALLOW":
            st.markdown('<span class="badge-pass">VERDICT: ALLOW</span>', unsafe_allow_html=True)
            st.caption("Tool execution authorized")
        else:
            st.markdown('<span class="badge-block">VERDICT: BLOCK</span>', unsafe_allow_html=True)
            st.caption("Unauthorized execution blocked")

    # Blast Radius Containment Banner
    if policy_decision.blast_radius_contained:
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(
            """
            <div class="badge-blast">
            🛡️ BLAST RADIUS CONTAINED: Upstream Neural Scanner did not flag the input (Safe),
            but the Deterministic Policy Gate successfully intercepted and blocked the unauthorized high-impact tool invocation!
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Detailed Findings Expander
    st.markdown("<br>", unsafe_allow_html=True)
    with st.expander("🔍 Deep Technical Diagnostics & Sanitized Context", expanded=True):
        d1, d2 = st.columns(2)
        with d1:
            st.markdown("**Policy Decision Justification:**")
            st.info(policy_decision.reason)
            st.markdown(f"**Total Defense Latency:** `{total_latency_ms:.2f} ms`")
            st.markdown(f"**Session Trace ID:** `{session.session_id}`")
            if scan_result.detected_heuristics:
                st.markdown(f"**Triggered Heuristics:** `{', '.join(scan_result.detected_heuristics)}`")

        with d2:
            st.markdown("**Sanitized & Encapsulated Context (XML Boundary):**")
            st.code(sanitized_context, language="xml")

# Live Audit Telemetry Log
st.markdown("---")
st.subheader("📊 Live Security Audit Stream (`aegis_audit.jsonl`)")

recent_events = audit_logger.get_recent_events(limit=20)
if recent_events:
    table_data = []
    for ev in reversed(recent_events):
        verdict = ev.policy_decision.verdict if ev.policy_decision else "N/A"
        similarity = f"{ev.policy_decision.intent_similarity_score:.3f}" if ev.policy_decision else "N/A"
        table_data.append({
            "Timestamp (UTC)": ev.timestamp,
            "Trace ID": ev.trace_id[:8] + "...",
            "Trust Level": ev.trust_level.value,
            "Payload Hash (SHA256)": ev.raw_content_sha256[:12] + "...",
            "Scan Safety": "SAFE" if (ev.scan_result and ev.scan_result.is_safe) else "FLAGGED",
            "Policy Verdict": verdict,
            "Similarity": similarity,
        })
    st.dataframe(table_data, use_container_width=True)
else:
    st.caption("No audit events recorded yet. Run a pipeline execution above to generate live telemetry.")
