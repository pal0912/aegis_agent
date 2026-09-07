# AegisAgent V2 🛡️

**Enterprise-Grade Defense-in-Depth Security Middleware, Deterministic Policy Gate & Behavioral Runtime Integrity Shield for Autonomous AI Agents**

---

## Overview

AegisAgent V2 protects autonomous LLM agents, LangChain workflows, and multi-agent systems against **prompt injection**, **jailbreaks**, **persistent memory/RAG poisoning**, **SSRF/data exfiltration**, **multi-step covert action chaining**, and the **Lethal Trifecta** (untrusted context + tool execution privilege + sensitive data access).

---

## Defense-in-Depth Architecture (V2)

### 1. Multi-Layer Prompt Injection Scanner (`aegis/detector.py`)
- Transformer-based sequence classifier (`protectai/deberta-v3-base-prompt-injection-v2`).
- Token sliding-window chunking for long documents (>450 tokens).
- Unicode NFKC normalization, base64 de-obfuscation, and zero-width character stripping.
- Heuristic regex signatures scanning raw payloads and hidden HTML/Markdown comments.

### 2. Fine-Grained Capability-Based Security Model (`aegis/capabilities.py`)
- Explicit privilege classification across 9 operational capabilities:
  `READ_PUBLIC`, `READ_PRIVATE`, `WRITE_FILE`, `WRITE_DATABASE`, `NETWORK_EXTERNAL`, `SEND_EXTERNAL_MESSAGE`, `EXECUTE_CODE`, `ADMIN`, and `FINANCIAL_ACTION`.
- Dynamic and argument-aware capability inference.
- Strict containment boundaries enforcing least-privilege for tainted execution states.

### 3. Outbound Network Guard & DNS SSRF Engine (`aegis/network_guard.py`)
- Deterministic IP/DNS validation blocking egress to loopback (`127.0.0.0/8`), private RFC-1918 networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), cloud metadata (`169.254.169.254`, `fe80::/10`), link-local, multicast, and broadcast addresses.
- Strict scheme enforcement (`http`, `https`), domain blacklisting, and tainted HTTP method controls.

### 4. Data Loss Prevention (DLP) & Secret Redaction (`aegis/dlp.py`)
- Real-time detection and cryptographic SHA-256 redaction of OpenAI (`sk-...`), Anthropic (`sk-ant-...`), AWS Access Keys (`AKIA...`), GitHub PATs (`ghp_...`), JWTs, and private keys.
- PII detection including Luhn-validated payment card numbers, US SSNs, and query parameter tokens.

### 5. Memory Integrity Shield & State Rollbacks (`aegis/memory_guard.py`)
- Cryptographic provenance tracking via immutable `MemoryEntry` records.
- Imperative directive scanning on memory writes (blocking attempts like `"Always ignore past rules"`, `"Remember that admin password is"`).
- Atomic snapshots (`create_snapshot`) and deterministic rollbacks (`rollback`) upon threat isolation.

### 6. Honeypot Canary Trap Sensor (`aegis/honeytoken.py`)
- Dynamic generation and passive injection of synthetic tripwire credentials (fake AWS keys, JWTs, database URIs).
- Zero-false-positive detection of outbound exfiltration attempts across tool arguments and payloads.

### 7. Behavioral Action Dependency Graph (`aegis/action_graph.py`)
- Directed execution graph tracking multi-step tool call sequences.
- Prevents multi-step covert chaining (e.g., `READ_PRIVATE` $\rightarrow$ `NETWORK_EXTERNAL` or `UNTRUSTED_INGEST` $\rightarrow$ `EXECUTE_CODE`).

### 8. Multi-Factor Risk Engine & Tri-State HITL Gating (`aegis/risk_engine.py`, `aegis/policy_gate.py`)
- Quantitative composite risk scoring formula:
  $$R = 0.35 \times \text{Detector} + 0.20 \times \text{Taint} + 0.25 \times \text{Capability Severity} + 0.20 \times (1.0 - \text{Intent Similarity})$$
- Tri-State authorization decisions:
  - $R < 0.40 \implies$ `ALLOW`
  - $0.40 \le R < 0.75 \implies$ `REQUIRE_HUMAN_APPROVAL` (Interactive Operator HITL Card)
  - $R \ge 0.75 \implies$ `BLOCK` (Fail-Safe Execution Containment)

### 9. Tamper-Evident Structured Audit Stream (`aegis/audit.py`)
- High-performance, thread-safe JSONL audit logging (`aegis_audit.jsonl`) with automated DLP redaction and cryptographic SHA-256 payload hashes.

---

## Benchmark & Verification Results

AegisAgent V2 was evaluated against the **Adversarial Benchmark Suite (20 attack vectors)**:

| Security Metric | Value | Benchmark Target | Status |
| :--- | :---: | :---: | :---: |
| **Precision** | **93.8%** | $\ge 90.0\%$ | ✅ PASSED |
| **Aegis Defense-in-Depth ASR** | **0.0%** | **0.0% (Zero Breach)** | ✅ PASSED |
| **Blast Radius Containment Rate** | **100.0%** | **100.0% (Fail-Safe)** | ✅ PASSED |
| **Memory Poisoning Shield Block Rate** | **100.0%** | **100.0% (Zero Poisoning)** | ✅ PASSED |
| **Honeypot Canary Trap Catch Rate** | **100.0%** | **100.0% (Zero Leakage)** | ✅ PASSED |
| **Chain-Attack Sequence Interception** | **100.0%** | **100.0% (Zero Chaining)** | ✅ PASSED |
| **HITL Risk Escalation Accuracy** | **100.0%** | **100.0% (Tri-State Accuracy)**| ✅ PASSED |
| **P50 Median Latency** | **80.83 ms** | $< 150.0\text{ ms}$ | ✅ PASSED |

---

## Installation

```bash
git clone https://github.com/pal0912/aegis_agent.git
cd aegis_agent
pip install -r requirements.txt
```

---

## Running the Security Console

Launch the Streamlit dashboard:

```bash
# Windows
.\venv\Scripts\Activate.ps1
streamlit run app.py

# Linux / macOS
source venv/bin/activate
streamlit run app.py
```

---

## Running Automated Tests & Benchmarks

```bash
# Run 34/34 Unit Tests
pytest tests/

# Run Full 20-Vector Adversarial Benchmark Suite
python -m evals.benchmark
```

---

## License

Apache 2.0

