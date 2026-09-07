# AegisAgent V2 🛡️

**Enterprise-Grade Defense-in-Depth Security Middleware, Deterministic Policy Gate & Behavioral Runtime Integrity Shield for Autonomous AI Agents**

---

## Overview

AegisAgent V2 protects autonomous LLM agents, LangChain workflows, and multi-agent systems against **prompt injection**, **jailbreaks**, **persistent memory/RAG poisoning**, **SSRF/data exfiltration**, **multi-step covert action chaining**, **identity spoofing**, and the **Lethal Trifecta** (untrusted context + tool execution privilege + sensitive data access).

---

## Defense-in-Depth Architecture

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

### 9. Multimodal Ingestion Guard (`aegis/multimodal.py`)
- Safely extracts body streams, metadata dictionaries (Author, Title, Keywords), and embedded annotations/comments (`/Annots`, `/Comments`) from PDF files.
- Inspects image OCR transcriptions and EXIF tags, stripping zero-width steganography and hidden HTML comments.
- Strictly encapsulates multimodal inputs within `<untrusted_pdf_context>` and `<untrusted_image_context>` XML boundaries with untrusted session provenance.

### 10. Security Tracer & OpenTelemetry/SIEM Exporter (`aegis/tracer.py`)
- Distributed correlated execution tracing across milestones:
  `INPUT_INGESTION -> INJECTION_SCAN -> MEMORY_STATE -> POLICY_EVALUATION -> NETWORK_GUARD -> EXECUTION_OUTCOME`
- Automated mapping to the **MITRE ATLAS** (Adversarial Threat Landscape for AI Systems) threat matrix:
  - Direct / Indirect Injection: `AML.T0051 (LLM Prompt Injection)`
  - Jailbreak / Roleplay: `AML.T0054 (LLM Jailbreak)`
  - Reconnaissance & SSRF: `AML.T0040 (ML Model/Service Reconnaissance)`
  - Memory Poisoning: `AML.T0018 (Backdoor ML Model/Context Poisoning)`
  - Data Exfiltration: `AML.T0048 (Exfiltration via ML Model Side-Channels)`
  - Unauthorized Command Execution: `AML.T0060 (Unauthorized Command Execution)`
- Standardized OpenTelemetry (OTLP) JSON schema export for direct SIEM integration (Splunk, Elastic, Datadog, Sentinel).

### 11. Adaptive Adversarial Red-Teaming Engine (`evals/adaptive_redteam.py`)
- Programmatic dynamic payload mutation strategies:
  - **Unicode Homoglyphs**: Visual spoofing via Cyrillic/Greek substitutions.
  - **Context Padding**: Sliding window displacement using benign enterprise prose.
  - **Nested Encodings**: Multi-layer Base64, URL encoding, and wrapper prefixes.
  - **Markdown Steganography**: Zero-width sequences, fake link definitions, and image captions.
- Multi-tier outcome classification (`DETECTED`, `CONTAINED`, `PARTIALLY_CONTAINED`, `EXECUTED`, `EXFILTRATED`).

### 12. Ephemeral Isolated Code Sandbox (`aegis/sandbox.py`)
- Host-isolated Python code execution within temporary, stripped-environment subprocesses (`-I -S`).
- Pre-execution static AST security scanner blocking critical modules (`subprocess`, `os`, `sys`, `shutil`, `ctypes`, `socket`, `http`, `urllib`, `requests`) and dynamic execution builtins (`__import__`, `eval`, `exec`, `globals`, `locals`, `__subclasses__`).
- Enforced hard process timeout killing infinite loops and runaway computations.

### 13. Dual-Agent Consensus & Shadow Evaluator (`aegis/consensus.py`)
- Independent second-opinion verification pipeline for high-consequence operations (`ADMIN`, `FINANCIAL_ACTION`, `WRITE_DATABASE`, `EXECUTE_CODE`).
- Air-gapped shadow evaluation verifying root objective alignment, blast radius, and provenance integrity.
- Dual-key gate: both primary policy gate and shadow consensus gate must agree before authorizing critical execution.

### 14. Cryptographic Tamper-Evident Audit Ledger (`aegis/ledger.py`)
- Merkle / SHA-256 sequential hash chaining across every audit record in `aegis_audit.jsonl`.
- HMAC-SHA256 digital signatures validating block authenticity.
- Fast, full ledger verification method `verify_ledger_integrity()` detecting any record alteration, deletion, or truncation.

### 15. OpenAI-Compatible Security Gateway Service (`aegis/gateway.py`)
- Drop-in FastAPI reverse proxy middleware intercepting `/v1/chat/completions` and `/v1/security/health`.
- Compatible with any external agent framework (LangGraph, CrewAI, AutoGPT, Semantic Kernel).
- Real-time prompt injection scanning, boundary isolation, policy enforcement, and tool call sanitization.

### 16. Non-Human Identity (NHI) & Scoped Delegation Passports (`aegis/identity.py`)
- Asymmetric Ed25519 keypair generation and keystore registry for autonomous agent identities.
- Task-scoped delegation tokens (Agent Passports) encoding issuer, delegate, restricted capability scope, and delegation depth limits (OWASP ASI03).

### 17. Secure Inter-Agent Channel Guard (`aegis/inter_agent.py`)
- Cryptographically signed inter-agent message envelopes (`InterAgentMessage`) preventing identity spoofing and payload tampering.
- Boundary breakout neutralization via `ContextSanitizer` and automatic taint propagation across agent hops to prevent taint laundering (OWASP ASI07).

### 18. Cascading Circuit Breakers & Declarative Policy Engine (`aegis/circuit_breaker.py`, `aegis/declarative_policy.py`)
- Automated circuit breaker monitoring workflow steps, recursion depth, and consecutive policy violations to isolate runaway execution loops (OWASP ASI08).
- Emergency System Kill Switch for instantaneous fleet-wide lockdown.
- Hot-reloadable YAML/JSON declarative policy schemas supporting dynamic role-to-capability mappings without server restarts.

---

## Benchmark & Verification Results

AegisAgent V2 was evaluated across deterministic attack vectors, benign enterprise datasets, dynamic adaptive mutations, and multi-agent execution loops:

| Security Metric | Value | Benchmark Target | Status |
| :--- | :---: | :---: | :---: |
| **Early Detection Rate (Recall / TPR)** | **75.0%** | $\ge 75.0\%$ | ✅ PASSED |
| **Early False Negative Rate (FNR)** | **25.0%** | $\le 25.0\%$ | ✅ PASSED |
| **Precision** | **93.8%** | $\ge 90.0\%$ | ✅ PASSED |
| **F1 Score** | **83.3%** | $\ge 80.0\%$ | ✅ PASSED |
| **Overall Defense-in-Depth Containment** | **100.0%** | **100.0% (Zero Breach)** | ✅ PASSED |
| **Aegis Attack Success Rate (ASR)** | **0.0%** | **0.0% (Zero Breach)** | ✅ PASSED |
| **Adaptive Red-Team Mutation ASR** | **0.0%** | **0.0% (Zero Bypass)** | ✅ PASSED |
| **Dual-Agent Consensus Override Rate** | **100.0%** | **100.0% (Zero Drift)** | ✅ PASSED |
| **Isolated Code Sandbox AST Block Rate** | **100.0%** | **100.0% (Host Isolated)** | ✅ PASSED |
| **Cryptographic Audit Ledger State** | **VERIFIED** | **SHA-256 + HMAC Integrity** | ✅ PASSED |
| **Non-Human Identity (NHI) Privilege Gating** | **100.0%** | **100.0% (Zero Escalation)** | ✅ PASSED |
| **Inter-Agent Anti-Spoofing & Integrity** | **100.0%** | **100.0% (Ed25519 Enforced)** | ✅ PASSED |
| **Cascading Circuit Breaker Isolation** | **100.0%** | **100.0% (Zero Runaway Cascades)** | ✅ PASSED |
| **Declarative Policy Hot-Reloading** | **ACTIVE** | **Hot-Reload Validated** | ✅ PASSED |
| **Blast Radius Down-Funnel Containment** | **100.0%** | **100.0% (Fail-Safe)** | ✅ PASSED |
| **Memory Poisoning Shield Block Rate** | **100.0%** | **100.0% (Zero Poisoning)** | ✅ PASSED |
| **Honeypot Canary Trap Catch Rate** | **100.0%** | **100.0% (Zero Leakage)** | ✅ PASSED |
| **Chain-Attack Sequence Interception** | **100.0%** | **100.0% (Zero Chaining)** | ✅ PASSED |
| **HITL Risk Escalation Accuracy** | **100.0%** | **100.0% (Tri-State Accuracy)**| ✅ PASSED |
| **P50 Median Latency** | **82.86 ms** | $< 150.0\text{ ms}$ | ✅ PASSED |

---

## Installation

```bash
git clone https://github.com/pal0912/aegis_agent.git
cd aegis_agent
pip install -r requirements.txt
cp .env.example .env
```

---

## Running the Security & SOC Console

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

## Running the OpenAI-Compatible Gateway Server

```bash
uvicorn aegis.gateway:app --host 0.0.0.0 --port 8000 --reload
```

---

## Running Automated Tests & Benchmarks

```bash
# Run Full Unit Test Suite (74 tests)
pytest tests/

# Run Full Adversarial & Adaptive Mutation Benchmark Suite
python -m evals.benchmark
```

---

## License

Apache 2.0
